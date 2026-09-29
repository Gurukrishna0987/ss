# ENTROPY - Honest Limitations (Final Year Major Project)

This project is a **controlled teaching lab with industry-level engineering**, not endpoint protection. Every limitation below is published openly - no hidden failures.

## Detection - What Works & What Doesn't

- **Works**: Shannon entropy + speed/extension + campaign escalation catches slow realistic attacks at file 2. Verified live: WannaCry killed at file 2/18, 18/18 restored.
- **Limitation**: Process attribution is verified only when process has file open. Other guesses stored but cannot terminate. Best-effort, can be dodged by sophisticated malware.
- **Limitation**: Ransom-note signal is signature-based (filenames, phrase list). Unknown note wording with no matching filename relies on entropy/speed signals.
- **Limitation**: Defense-tamper signal watches backup_storage/ and quarantine_storage/ for deletions. Backup store's own housekeeping (manifest rewrites, temp files) exempted by name, but version evictions beyond ENTROPY_BACKUP_MAX_VERSIONS (default 10) can look like tampering - raises alert (safe direction, not missed attack).
- **Former Blind Spot, now CLOSED**: `image_blindspot` - in-place encryption of already-high-entropy media (jpg 7.0-7.8, mp4 7.0-7.9) without rename leaves *Shannon entropy* within the normal range, so no entropy-only detector can see it. The structural fingerprint breaks the tie on **byte distribution, not entropy level**: real JPEG/MP4 carry Huffman tables and format markers, so their histogram is sharply peaked (chi² in the tens of thousands), while AES output is statistically flat (chi² ≈ 255). Combined with magic-byte validation, this is measured at **6/6 detected and 6/6 contained on the first modified file, with 0 false quarantines**. For an extension we have no ground truth for, chi² stays alert-level only (see below).
- **Deliberate trade-off — unknown extensions are alert-level, not quarantine-level**: chi² uniformity and magic-byte validation are only *ground truth* for formats we can recognise (jpg, pdf, zip, mp4, office, ...). A file renamed to a disguise extension such as `.locked` or `.wnaCry` has no signature to invalidate, and an arbitrary new binary format is legitimately uniform. So a single such file is detected and **alerted, never quarantined**; it is quarantined the moment a second file corroborates inside the campaign window (the "kill at file 2" behaviour). This is pinned by `test_single_file_unknown_extension_ciphertext_alerts_only`. Measured cost of relaxing it: the RF path goes from 0 to 3 false quarantines (FP rate 14.3% → 57.1%).

## AI - Honest Scope

- DQN weights optional. Without ai/dqn_weights.pth rule engine decides. Dashboard fields engine/confidence/explanation come from persisted events, not fabricated scores. Torch optional, fallback to rules.
- Training data synthetic, versioned schema_version 1, held-out split.
- Random Forest second classifier (ai/rf_weights.json, python -m ai.train_rf) trained on seeded synthetic data (11 features), opt-in engine ENTROPY_AI_ENGINE=rf. Measured: 48/48 attacks **but 3 false quarantines on `db_dump`** (a legitimate high-entropy binary), so NOT default. Rule engine keeps the 0-FQ bar. SHAP per-incident, fallback to global importances if SHAP missing. Synthetic data does not predict real-world prevalence.
- Eval accuracy/AUC of 1.0 on the RF holdout is **not** evidence of generalisation: the synthetic generator gives the two classes near-disjoint support (ransomware process ages 1-60s vs legitimate 300-7200s, zero overlap), so perfect separation is guaranteed by construction. Treat it as a sanity check, not a result. Real detection numbers come from the benchmark battery.
- Hard-confirmation signals (ransom note, defense tamper, exchange-confirmed fingerprint) applied BEFORE any learned engine, so no model can downgrade confirmed incident.

## Blockchain - Honest

- Modes explicit: ganache, fallback (local SQLite), none. Default fallback=true for demo (works without Ganache).
- Fallback is NOT immutable chain - clearly labeled mode_label.
- logThreat is onlyOwner. Set ENTROPY_WALLET_ADDRESS to deployer.
- Federated exchange simulated with one shared SQLite store, several simulated nodes open - not a network. Fingerprint match corroborating evidence, can only confirm threat already at quarantine-threshold, never standalone detector. Single node's sighting only corroborates (+25 score) never auto-quarantine - independent-node consensus threshold defends against poisoned node.

## Simulator - Safety

- Attacker engines only touch victim_server/user_files via safe_path() check. Never place real documents there.
- Encryption is os.urandom() overwrite + rename to .WNCRY, no key, original destroyed. Quarantine holds ciphertext evidence for forensics, cannot be decrypted by anyone (honest - real ransomware also not decryptable without attacker key).

## Recovery - Honest

- Does NOT decrypt ransomware files - key held by attacker, no product can recover. Recovery = restoring known-good copy captured BEFORE attack.
- Backup capture additive (reads victim file, writes only to backup_storage/) runs every mode including dry-run.
- Restore candidates clean versions only, stored blob must verify SHA-256 before use. Event-time captures labeled clean under strict rule: inside file type's normal range with no 0.5 margin AND no ≥2.0 jump from previous clean. Stops office ciphertext 7.8-8.0 (inside lenient range) from being restored as clean. Trade-off: legitimate edit jumping entropy ≥2.0 makes post-edit non-restorable, falls back to older clean.
- Dry-run: restore simulated (backup verified, file left). ENTROPY_DRY_RUN=false: clean version restored in place after contained.
- Renamed file restored then renamed back to original name, only when original path free, never clobbers attacker file.
- Backup store bounded versions per file (ENTROPY_BACKUP_MAX_VERSIONS default 10). Files only ever existed encrypted not restorable.
- Clean version = entropy within file type's normal range at capture. Random/already-encrypted unknown file (entropy >6.8) never clean, contained but never auto-restored - deliberately refuses to restore encrypted-looking content.
- Deleting file outside protected store raises no signal, invisible to entropy (no file to sample) - published loss, not hidden.
- Recovery drill (python -m benchmark.recovery_drill) authoritative source for measured recovery rate and RTO, counts lost files explicitly.

## Quarantine Decryption - Brutally Honest

- Privileged user (victim_user / 1234) CANNOT decrypt quarantine files. Quarantine holds os.urandom() ciphertext, no key, original destroyed.
- Vault can list, view metadata, forensic reports, but not decrypt.
- This is honest - real ransomware also not decryptable without attacker key. Recovery via backup vault restore, not decryption.
- If you claim "privileged user can decrypt quarantine", you're lying and will fail viva.

## What We Fixed for Final Year (Industry Level)

- Campaign escalation (2+ files in 15s = TERMINATE) stops slow attacks at file 2, previously missed until last file
- Strict clean labeling prevents ciphertext becoming restore source (was bug: restored ciphertext as clean)
- Content-based post-kill verification (hash vs last clean) repairs mid-write files, no entropy false positives on jpgs
- Zombie-aware termination (reap in console finally, treat zombie as success) - instant kill rc=42 not FORCE KILLED after 3s
- SHA3-256 dual fingerprint (not just SHA-256) - industry standard
- Real-time socket.io push verified sub-second
- Neutral victim explorer (no encrypted counts)
- Install-time quarantine folder creation per spec
- Requirements fixed (was ResolutionImpossible due to shap 0.51 + numpy 1.26.4 conflict)

## For Examiners

This is working system with 149 tests pass (0 fail), deterministic benchmark, live demo verified. Not PowerPoint. Show kill at file 2, 18/18 restored, vault evidence. The battery measures 100% detection on 8 attack families - quote it, it is regeneratable - but do not claim the impossible: blockchain immutability (fallback ledger is labelled as not a chain), quarantine decryption, or that synthetic ML data predicts real-world prevalence.
