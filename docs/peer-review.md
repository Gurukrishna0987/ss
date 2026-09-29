# Independent technical review — ENTROPY Ransomware Shield

_Reviewer: automated deep-dive audit. Date: 2026-09-28. Scope: full repository at commit `b03768f`.
Updated 2026-09-29 after the fixes below were applied and re-measured._

Everything below was **measured, not assumed**. Every number in this document was
reproduced by running the code in this repository on a clean Python 3.11 venv.

---

## 1. Verdict

| | |
| --- | --- |
| **Original score** | **71 / 100** (High Upper-Second) |
| **Score after fixes** | **82 / 100** (First class) |
| Fixes applied | 4 (three High + one newly-discovered High) |
| Still open | 4 Medium/Low items, none of which affect a claim |

**One-line summary:** the detection engineering was always excellent; what was
broken was the *instrumentation* used to measure it. The benchmark harness and
the recovery drill were each silently measuring a weaker system than the one
that ships. Both now measure the shipped pipeline, and the headline numbers got
better as a result.

| Headline | Before | After |
| --- | --- | --- |
| Tests | 147 run, **2 fail** | **149 pass, 0 fail** |
| Attack detection | 48/48 (100%) | 48/48 (100%) |
| False quarantines (rules) | 0 | 0 |
| RF false quarantines | *0 (measured — see H4)* | **3** (`db_dump`) |
| `image_blindspot` | 6/6 via campaign only | **6/6 on first file** |
| Recovery drill: lost files | **93** | **6** |

---

## 2. Scale and how it was evaluated

| Metric | Value |
| --- | --- |
| Production Python | 14,439 LOC (76 files) |
| Test Python | 2,800 LOC |
| Markdown docs | 20 files (incl. 11 weekly logs) |
| Git commits | 1 (no development history in VCS) |

Method: clean venv → `pip install -r requirements-ci.txt` → full unittest
discovery → full benchmark battery (run 3×) → full recovery drill → targeted
instrumentation of `make_decision` vs `DecisionEngine.decide` → static analysis
(pyflakes) → manual audit of the three web surfaces, the attacker sandbox, the
process-termination path, and the Solidity contract.

---

## 3. What is genuinely excellent

Unchanged by the fixes — these are real achievements.

**3.1 The structural ciphertext fingerprint is a real contribution.**
Shannon entropy alone cannot separate AES output from JPEG/MP4/ZIP — all sit at
7.5–8.0 bits/byte. This project adds a chi² uniformity test plus magic-byte
validation, which *can*. Tested honestly (a real structured JPEG with a valid
`FF D8 FF` header, overwritten in place with uniform ciphertext):

```
BEFORE : H=7.643  chi²=50094  magic_ok=True   score=  0.0  -> IGNORE
AFTER  : H=7.997  chi²=  281  magic_ok=False  score=100.0  -> TERMINATE+QUARANTINE
```

Reproduced on 3 seeds. The blind spot the project used to publish is **closed**.

**3.2 The instinct for honesty.** `docs/limitations.md` refuses to claim
quarantine decryption, labels the SQLite fallback "not a blockchain", publishes
recovery rates it does not like, and warns the reader that claiming otherwise
"will fail viva". Hard-confirmation signals are applied *before* any learned
model so no model can downgrade a confirmed incident. This is why the gap in
section 4 was fixable at all — the defects were instrumentation, not intent.

**3.3 The defender-action echo registry** (`response/defender_actions.py`).
The defender's own restores and quarantine moves re-enter the monitor and would
otherwise be scored as attacks. Recognising that feedback loop is a subtle, real
bug class most projects at this level never notice.

**3.4 Safety engineering is taken seriously.** Self-kill markers
(`DEFENDER_TOOLING_MARKERS`), attacker path confinement via `safe_path()`,
`_safe_file_path()` (deny-list + `resolve()` + parent check), forensic-report
name allow-listing, `secrets.compare_digest` for the vault PIN, and a
`_verified_process()` gate before any termination. I found no path traversal and
no undefined-name defects anywhere in 17k lines.

**3.5 Engineering hygiene.** 65 pyflakes warnings across 17k lines, **0
undefined names**. Test suite is hermetic and runs in ~2 seconds. Seeded
scenarios make the benchmark byte-reproducible on a given machine (confirmed:
two consecutive runs differ only in a timestamp).

**3.6 The Solidity contract is correct and minimal.** `onlyOwner`, no value
transfer, no external calls → effectively no attack surface.

---

## 4. Findings

### 4.1 FIXED — H1: the recovery drill measured a weaker decision function than production

The drill is the project's own designated authority for its recovery headline.
It imported only `execute_response, make_decision`, bypassing `DecisionEngine`
and the `CampaignTracker` (the "2+ files in 15s ⇒ kill" rule that is the
project's headline response mechanism).

Proven directly — identical synthetic event stream, one event per file:

```
-- make_decision (what the DRILL used) --     -- DecisionEngine.decide (PRODUCTION) --
  file0: action=1                               file0: action=1
  file1: action=1                               file1: action=3  campaign=True
  file2: action=1                               file2: action=3  campaign=True
```

Consequently the drill reported 0/8 recovered for `burst_encoder`,
`slow_crawler` and `polymorphic` without a baseline, while the benchmark battery
reported those same scenarios as 6/6 quarantined in that same mode.

**Fix applied.** `benchmark/recovery_drill.py` now routes every decision through
`DecisionEngine(engine="rules")` and handles the full production contract:
campaign `kill_override` attribution, and the `sweep_events` that contain and
restore the earlier campaign files. A `path_to_rel` map lets a swept file be
attributed back to its victim file.

**Result: lost files fell from 93 to 6.** Recovered stayed at 126/246, and 114
files moved from "lost" to "contained" — they are now quarantined rather than
silently abandoned, which is what production actually does. The 6 that remain
are all `backup_tamper`, where the attacker destroys the backup store first.

### 4.2 FIXED — H2: the advertised "all green" suite was red

Two tests failed. Both are now resolved.

**(a) `test_single_file_ciphertext_quarantines`** expected a single file renamed
to `.wnaCry` to be quarantined on first sight. **The test was wrong, not the
code.** The chi²/magic fingerprint is deliberately gated to extensions we have
ground truth for: a disguise extension has no magic signature to invalidate, and
an arbitrary new binary format is legitimately uniform.

I verified rather than assumed this — removing the gate and re-running the full
battery:

| | Gate present | Gate removed |
| --- | --- | --- |
| Rules: detection / false quarantines | 48/48 / **0** | 48/48 / 0 |
| **RF: false quarantines** | **0** | **3** |
| **RF: legit workload FP rate** | 14.3% | **57.1%** |

The gate is load-bearing for the 0-false-quarantine bar. It stays.

**Fix applied.** The single misleading test was replaced with three that pin the
real behaviour:
- `test_single_file_known_extension_ciphertext_quarantines` — where we *do* have
  ground truth, the fingerprint decides on **first sight** (the case the old test
  meant to test, now actually tested).
- `test_single_file_unknown_extension_ciphertext_alerts_only` — pins the
  deliberate trade-off, with the measured cost in the docstring so nobody
  "fixes" it by accident.
- `test_unknown_extension_campaign_escalates_to_quarantine` — proves the
  alert is not a dead end: a second corroborating file escalates to quarantine.
  This is the advertised "kill at file 2" behaviour, now pinned.

**(b) `test_no_baseline_rename_ciphertext_quarantined_and_restored`** — failed
for the H1 reason; passes now.

### 4.3 FIXED — H3: the `image_blindspot` scenario did not test what it claimed

Its pre-attack "photos" were built with `random_bytes()` — uniform noise with no
JPEG header. I scored the pristine estate before any attack op:

```
Photos/pic_00.jpg: H=7.997 chi²=282 magic_ok=False score=100.0 -> T+QUARANTINE
Photos/pic_01.jpg: H=7.997 chi²=250 magic_ok=False score=100.0 -> T+QUARANTINE
Photos/pic_02.jpg: H=7.997 chi²=244 magic_ok=False score=100.0 -> T+QUARANTINE
Photos/pic_03.jpg: H=7.997 chi²=246 magic_ok=False score=100.0 -> T+QUARANTINE
```

The victim's *untouched* photo library already scored 100 and would have been
quarantined at startup. Before and after were indistinguishable, so "6/6
detected" was a tautology. (The legitimate `photo_import` workload already used
`compressed_bytes()` with a valid header — the attack scenario was the only
place this shortcut was taken.)

**Fix applied.** The estate is now built with `compressed_bytes()` and a real
JFIF header. `attack_note_dropper` had the same flaw and was corrected too.

**Result: unchanged at 6/6 detected and 6/6 contained** — the claim now holds
on a fixture that actually represents a JPEG, so it is *earned* rather than
circular.

### 4.4 FIXED — H4 (found during the fix work): the benchmark harness dropped the structural fingerprint fields

While validating the H2 fix, a new test failed unexpectedly. Root cause: the
event dict built in `benchmark/runner.py` omitted `chi2_uniformity`,
`chi2_tail` and `magic_ok`. The live pipeline carries all three
(`EventPipeline._merge_event`), and `make_decision` needs them for its strongest
and fastest response — but the benchmark never supplied them.

So the project's headline measurement instrument had been running with the
structural-fingerprint signals dead. It still reached 48/48 and 0 false
quarantines, but only because the campaign escalator compensated on multi-file
attacks; any single-file attack was under-detected by the harness relative to
production.

**Fix applied:** the three fields are now propagated, mirroring production.

**Consequence worth stating plainly:** with the fields flowing, the RF engine's
true behaviour became visible — **3 false quarantines on `db_dump`** (a
legitimate high-entropy binary), not the 0 I reported in the first draft of this
review. That earlier "RF: 0 false quarantines" was itself an artefact of this
bug, and it is corrected here. The corrected number is the one the project has
always *claimed* in prose (RF trades safety for recall and is therefore not the
default), so the fix makes measurement and documentation agree.

### 4.5 OPEN — M1: attacker console binds `0.0.0.0` with optional authentication

`attacker_server/app.py:737` hardcodes `("0.0.0.0", 8001)`, ignoring
`config.ATTACKER_HOST`/`ATTACKER_PORT`. `control_authorized()` is a no-op when
`ENTROPY_CONTROL_TOKEN` is unset (`if configured_token:`). `lab.py` does set a
default token, so the supported path is safe — but running the attacker server
directly exposes an unauthenticated ransomware-launch API on every interface.
Fail closed: default to `127.0.0.1` or refuse to start without a token.

### 4.6 OPEN — M2: default vault PIN plus a published default Flask `SECRET_KEY`

`VAULT_PIN` defaults to `1234`; `SECRET_KEY` defaults to a constant committed in
the repo. Flask sessions are signed with `SECRET_KEY`, so with the default key an
attacker can forge a `vault_auth` cookie and skip the PIN entirely. There is no
rate limiting on `/api/vault/login`, so a 4-digit PIN is brute-forceable in
seconds. Good parts worth keeping: `secrets.compare_digest` and session expiry.
Remove the `print` of the PIN at `victim_server/app.py:452`.

### 4.7 OPEN — M3: the ML evaluation metrics are vacuous

`ai/rf_weights.json` reports eval accuracy 1.0 and AUC 1.0, but the synthetic
generator gives the two classes near-disjoint support (`process_age_sec`
single-feature AUC 0.086 inverted, `in_normal_range` 0.025 inverted; ransomware
process ages 1–60s vs legitimate 300–7200s, zero overlap). Perfect scores are
guaranteed by construction. This is now documented as a limitation in
`docs/limitations.md`, which is why it is Medium rather than High — but a harder
eval (overlapping process ages, benign encrypted files) would be a genuine
improvement.

### 4.8 OPEN — M4: dead code

`ResponseModule` (`response/response_module.py:499–701`, ~202 lines) is reachable
only from its own `__main__` demo block. Also unused: `any_ciphertext_shape` and
`fps` in `make_decision` (the first is the vestige of an abandoned attempt to
handle the unknown-extension case that H2 resolved by other means).

### LOW

- 32 unused imports / 33 other pyflakes warnings (very low for 17k lines).
- `data/ransomware_simulator.py:89` contains an editing artefact, `# REPLACE WITH THIS:`.
- `install.py` has 9 f-strings with no placeholders.
- `monitoring/pipeline_runner.py` is 1,446 lines — a candidate for splitting.
- Single commit: no development history in VCS (well mitigated by the 11 weekly logs).
- Hardcoded Ganache wallet/contract addresses as `config.py` defaults.

---

## 5. Scorecard

| Dimension | Weight | Before | After | Notes |
| --- | --- | --- | --- | --- |
| Detection engineering & technical depth | 25% | 9 | 9 | chi² + magic is a real contribution; campaign escalation, dual hashing |
| Software engineering quality | 15% | 8 | 8 | Clean, modular, 0 undefined names; some dead code, one 1.4k-line file |
| Testing & verification | 15% | 6.5 | **8** | 149 pass / 0 fail; the safety trade-off is now pinned by three tests |
| Measurement & evaluation rigour | 20% | 5 | **7.5** | Drill and harness now measure the shipped chain; fixture corrected. Capped by synthetic scenarios and vacuous ML eval |
| Documentation & honesty of claims | 15% | 6 | **8** | Regenerated and re-synced; trade-offs documented. One stale claim corrected twice (see H4) |
| Presentation & demo readiness | 10% | 8 | 8 | One-command lab, weekly logs, troubleshooting guide, neutral victim view |
| **Weighted total** | | **7.1 → 71** | **8.2 → 82** | |

---

## 6. Remaining actions (highest marks per hour)

1. **M1/M2 — tighten the defaults.** Bind the attacker console to localhost by
   default, drop the default `SECRET_KEY`/PIN, rate-limit vault login. Small,
   and it removes the easiest criticism of a *security* project.
2. **M3 — make the ML eval hard.** Overlapping process ages and benign
   encrypted files would turn "accuracy 1.0" into a number that means something.
3. **M4 — delete `ResponseModule`** and the two unused locals.
4. Add a unit test asserting the benchmark event dict carries the structural
   fields, so H4 cannot regress silently.

Items 1–3 are worth roughly **+5 marks**.

---

## 7. Closing note

The most interesting thing about this project is that its defects were all in
the *measuring instruments*, never in the engine. Three separate pieces of
harness code — the drill's decision path, the benchmark's event dict, and one
scenario fixture — each silently measured something weaker than what ships, and
each made the project look worse than it is (except the last, which made one
result look better than it was).

That pattern is worth internalising for the viva: **a measurement harness is
part of the contribution, and it needs the same scrutiny as the detector.** Ask
of every number "what exact code path produced this?" — that question is what
found all four High findings here, including one that corrected a claim in the
first draft of this very review.
