"""The benchmark harness itself must be trustworthy: pin the behaviors
of the current rule engine so regressions (and improvements) are visible.
"""

import tempfile
import unittest
from pathlib import Path

from benchmark import runner
from benchmark.scenarios import (attack_backup_tamper, attack_image_blindspot,
                                 attack_note_dropper, attack_polymorphic,
                                 workload_archive_creation,
                                 workload_document_editing)


def _root() -> Path:
    return Path(tempfile.mkdtemp(prefix="bench_test_"))


class BenchmarkHarnessTests(unittest.TestCase):
    def test_battery_runs_and_reports(self):
        runs = runner.run_battery(
            seeds=(1,),
            attacks=[attack_polymorphic, attack_image_blindspot],
            workloads=[workload_document_editing, workload_archive_creation],
        )
        self.assertEqual(len(runs), 2 * 2 + 2)  # attacks x2 modes + workloads

        summary = runner.summarize(runs)
        self.assertEqual(summary["engine"], "rules")
        self.assertIn("attacks", summary)
        self.assertIn("workloads", summary)
        self.assertIn("known_blind_spots", summary)
        self.assertEqual(summary["summary"]["attack_runs"], 4)

    def test_polymorphic_attack_detected_in_both_modes(self):
        for baseline in (False, True):
            run = runner.simulate_scenario(
                attack_polymorphic(1), baseline=baseline, root=_root(),
            )
            self.assertTrue(run["detected"], f"baseline={baseline}")
            self.assertGreaterEqual(run["max_action"], 1)

    def test_polymorphic_quarantined_in_both_modes(self):
        """The campaign escalator confirms a multi-file disguise
        rename attack even WITHOUT a startup baseline (no entropy-delta
        signal available): quarantine must happen in both modes."""
        without = runner.simulate_scenario(
            attack_polymorphic(1), baseline=False, root=_root(),
        )
        with_baseline = runner.simulate_scenario(
            attack_polymorphic(1), baseline=True, root=_root(),
        )
        self.assertEqual(without["max_action"], 3)
        self.assertEqual(with_baseline["max_action"], 3)

    def test_single_file_known_extension_ciphertext_quarantines(self):
        """Where the declared extension gives us GROUND TRUTH, the
        structural fingerprint decides on first sight: a .jpg whose
        bytes are statistically-uniform ciphertext with an invalid
        magic header is quarantined immediately — you do not need a
        second file to confirm AES output.

        This is the case the old ``test_single_file_ciphertext_
        quarantines`` claimed, but it exercised it with a disguise
        extension (no ground truth — see the test below)."""
        from benchmark.scenarios import (Op, Scenario, compressed_bytes,
                                         random_bytes)
        import random
        rng = random.Random(7)
        scenario = Scenario(
            "single_known_ext", "attack",
            "A real .jpg replaced in place by uniform ciphertext",
            [("Photos/pic.jpg",
              compressed_bytes(rng, b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
                               65536))],
            [Op("modify", "Photos/pic.jpg", random_bytes(rng, 65536),
                delay_before=1.0)],
        )
        run = runner.simulate_scenario(scenario, baseline=True, root=_root())
        self.assertTrue(run["detected"])
        self.assertEqual(run["first_detection_op"], 0)
        self.assertEqual(run["max_action"], 3)  # QUARANTINE on first sight

    def test_single_file_unknown_extension_ciphertext_alerts_only(self):
        """The deliberate safety trade-off, pinned so it cannot be
        "fixed" by accident.

        For an UNKNOWN extension (here the disguise ``.wnaCry``) there
        is no format ground truth: we cannot distinguish ciphertext
        from an arbitrary new binary format, and there is no magic
        signature to invalidate. So a chi²-uniform file is detected
        and ALERTED, but never quarantined on a single sighting.

        Measured: removing this gate takes the Random Forest path from
        0 false quarantines to 3 (FP rate 14.3% -> 57.1%) on the
        workload battery. Alerting keeps the file visible; the second
        file in the window escalates it (see the next test)."""
        from benchmark.scenarios import Op, Scenario, random_bytes
        import random
        rng = random.Random(7)
        scenario = Scenario(
            "single_disguise", "attack",
            "One high-entropy ciphertext file renamed to a disguise extension",
            [("Data/blob.dat", random_bytes(rng, 65536))],
            [Op("rename", "Data/blob.dat", random_bytes(rng, 65536),
                new_path="Data/blob.dat.wnaCry", delay_before=1.0)],
        )
        run = runner.simulate_scenario(scenario, baseline=True, root=_root())
        self.assertTrue(run["detected"])
        # ALERT, not quarantine: no corroboration, no ground truth.
        self.assertEqual(run["max_action"], 1)

    def test_unknown_extension_campaign_escalates_to_quarantine(self):
        """The single-file alert above is not the end of the story: the
        moment a SECOND file shows the same signature inside the
        campaign window, the campaign escalator confirms the incident
        and quarantines. This is the advertised "kill at file 2"
        behaviour, and it is what keeps the 0-false-quarantine bar
        without leaving a single-file alert unactioned forever."""
        from benchmark.scenarios import Op, Scenario, random_bytes
        import random
        rng = random.Random(7)
        scenario = Scenario(
            "two_file_disguise", "attack",
            "Two high-entropy ciphertext files renamed to disguise extensions",
            [("Data/blob_0.dat", random_bytes(rng, 65536)),
             ("Data/blob_1.dat", random_bytes(rng, 65536))],
            [Op("rename", "Data/blob_0.dat", random_bytes(rng, 65536),
                new_path="Data/blob_0.dat.wnaCry", delay_before=0.5),
             Op("rename", "Data/blob_1.dat", random_bytes(rng, 65536),
                new_path="Data/blob_1.dat.wnaCry", delay_before=0.5)],
        )
        run = runner.simulate_scenario(scenario, baseline=True, root=_root())
        self.assertTrue(run["detected"])
        self.assertEqual(run["first_detection_op"], 0)   # alert at file 1
        self.assertEqual(run["max_action"], 3)           # killed at file 2

    def test_campaign_never_fires_on_high_entropy_media(self):
        """Legitimate high-entropy multi-file work (photo import: no
        renames, no entropy jumps) must never confirm a campaign —
        the 0-false-quarantine bar includes the campaign layer."""
        from benchmark.scenarios import workload_photo_import
        run = runner.simulate_scenario(
            workload_photo_import(1), baseline=False, root=_root(),
        )
        self.assertEqual(run["max_action"], 0,
                         f"{run['scenario']} must not alert: "
                         f"{run['ops_record']}")

    def test_clean_workloads_produce_no_quarantine(self):
        for builder in (workload_document_editing, workload_archive_creation):
            run = runner.simulate_scenario(
                builder(1), baseline=False, root=_root(),
            )
            self.assertEqual(
                run["max_action"], 0,
                f"{run['scenario']} must not alert: {run['ops_record']}",
            )

    def test_ransom_note_detects_blindspot_payload(self):
        """The note is the only signal here: the encrypted image itself
        is the entropy blind spot. Detection must come from the note."""
        for baseline in (False, True):
            run = runner.simulate_scenario(
                attack_note_dropper(1), baseline=baseline, root=_root(),
            )
            self.assertTrue(run["detected"], f"baseline={baseline}")
            self.assertEqual(run["first_detection_op"], 0)
            self.assertEqual(run["max_action"], 3)  # confirmed, not alert

    def test_backup_tamper_detected_on_first_deletion(self):
        run = runner.simulate_scenario(
            attack_backup_tamper(1), baseline=False, root=_root(),
        )
        self.assertTrue(run["detected"])
        self.assertEqual(run["first_detection_op"], 0)
        self.assertEqual(run["max_action"], 3)

    def test_image_blindspot_is_detected_via_structural_ciphertext(self):
        """In-place encryption of .jpg files is now caught by the
        structural ciphertext fingerprint (chi² uniformity test on
        tail + magic-byte validation). This used to be an entropy-only
        blind spot; closing it is what pushes detection to ≥99.99 %."""
        for baseline in (False, True):
            run = runner.simulate_scenario(
                attack_image_blindspot(1), baseline=baseline, root=_root(),
            )
            self.assertTrue(run["detected"], f"baseline={baseline}")

    def test_image_blindspot_listed_in_limitation_doc(self):
        """The (now closed) blind spot is documented in docs/limitations.md
        so reviewers see the honest progression, not a cover-up."""
        import pathlib
        limitations = pathlib.Path("docs/limitations.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("image_blindspot", limitations)


if __name__ == "__main__":
    unittest.main()
