# Final Verification - 200 Marks Project (End-to-End Working)

## Installation & Dependencies - FIXED

**Bug Fixed**: `requirements.txt` had `shap==0.51.0` requires `numpy>=2` but pinned `numpy==1.26.4` → ResolutionImpossible
**Fix**: Compatible set `numpy==1.26.4 + scikit-learn==1.4.2 + shap==0.44.0 + torch==2.2.1 + web3==6.15.1` verified installs

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt  # Now works, no conflict
.venv/bin/python -c "import torch, sklearn, shap, web3; print('all ok')"
```

## Blockchain - FIXED

**Bug**: `ENTROPY_BLOCKCHAIN_FALLBACK=False` default → Ganache offline = "No blockchain connection (fallback disabled)" → dashboard shows 0 tx, claims false
**Fix**: Default `BLOCKCHAIN_FALLBACK=True`, LocalLedger fallback active, clearly labeled mode

Verified:
```
[BLOCKCHAIN] Ganache unreachable — using LOCAL LEDGER fallback ✅
Blockchain status: mode=fallback, tx_count=4, mode_label="Local SQLite ledger (not a blockchain)"
```

## RF Model - FIXED

**Bug**: RF trained with sklearn 1.9.1, running with 1.4.2 → warning "Trying to unpickle estimator from version 1.9.1"
**Fix**: Retrained with `python -m ai.train_rf` → new ai/rf_weights.json (373K), 600 train, 200 eval, 1.0 accuracy

## SHA-3 - FIXED

**Bug**: Pitch claimed SHA-3, code used only SHA-256
**Fix**: `storage/hashing.py` now provides:
- `sha256_file()` - legacy
- `sha3_256_file()` - NIST standard
- `dual_hash_file()` - both for forensic integrity
- `response_module.py` FingerprintGenerator now uses SHA3-256 primary + dual hash method

## Campaign & Restore - FIXED (Major Bugs)

**Bug 1**: Restore put ciphertext back as clean version (xlsx 7.88 inside lenient range +0.5)
**Fix**: Strict clean rule in backup_manager.py: inside normal range NO margin AND no ≥2.0 jump from last clean, computed atomically

**Bug 2**: File being written at kill moment left encrypted (score 30 <40, no alert)
**Fix**: Post-kill verification walk: compare current hash vs last clean hash, repair if differs. Content signal, not entropy-only

**Bug 3**: First fix attempt flagged every file entropy ≥6.8 → quarantined 11 clean jpgs
**Fix**: Content-based (hash diff) not entropy level

**Bug 4**: Kill reported FORCE KILLED after 3s - zombie not reaped
**Fix**: Attacker console reaps in _stream_reader finally, terminator treats zombie/already-gone as success → instant rc=42

## Live Demo Verification (Final)

```
Phase: KILLED_BY_DEFENDER hit=2/18 defender_killed=True rc=42
.WNCRY left: 0
Quarantine: 3 files (evidence, cannot be decrypted)
ALL 18 FILES MATCH PRE-ATTACK (zip content hash + pdf byte compare)
SOC stats: quarantined=3 recovery=3 threats=4 total=13
Blockchain: fallback mode, tx_count=4
```

## Requirements Checklist (Spec)

- [x] SOC real-time feed: socket.io new_event push +0.4s verified with raw frame parser
- [x] Victim explorer neutral: /api/files returns only name/size/modified/icon
- [x] Background auto-response: quarantine BEFORE attack proceeds (campaign at file 2)
- [x] Process killed: verified PID, instant, zombie-aware
- [x] File moved to quarantine folder created by user at install: install.py + config.py + lab.py all create quarantine_storage/ at install time, log message
- [x] Quarantine decryption: HONEST - cannot decrypt (os.urandom, no key), recovery via backup vault, vault PIN protected

## Tests

```
149 tests OK, 0 fail (skipped=2 optional)
py_compile OK all files
benchmark: 48/48 detection (100%) rules, 0 false quarantines, slow_crawler 6/6, polymorphic 6/6
benchmark: image_blindspot 6/6 detected AND 6/6 contained on the corrected JPEG fixture
RF (opt-in): 48/48 detection but 3 false quarantines on db_dump - why rules are the default
recovery drill: 126/246 restored (51.2%), 114 contained, 6 lost
```

## Corrections applied after independent review (see docs/peer-review.md)

Three defects were fixed; all numbers above are post-fix.

1. **Benchmark harness dropped the structural fingerprint fields.** The event
   dict built in `benchmark/runner.py` omitted `chi2_uniformity`, `chi2_tail`
   and `magic_ok`, which the live pipeline carries
   (`EventPipeline._merge_event`). The rule engine's strongest signals were
   therefore dead in the benchmark - it only ever reached quarantine via the
   campaign escalator. Fields now propagated; the battery measures the shipped
   detector.
2. **The image_blindspot fixture was not a JPEG.** The estate was built with
   `random_bytes()`, so the pristine photos already scored 100 and would have
   been quarantined before any attack ran - "6/6 detected" was a tautology.
   Now built with `compressed_bytes()` (valid JFIF header, structured body).
   Result is unchanged at 6/6, so the claim is now *earned*.
3. **The recovery drill bypassed the campaign escalator.** It called
   `make_decision()` instead of `DecisionEngine.decide()`, measuring a weaker
   detector than production. Losses fell from 93 to 6 once the shipped chain
   was used. The 6 that remain are all `backup_tamper`, where the attacker
   destroys the backup store first.

## For Examiners

This is working system, not PowerPoint. Launch attack yourself from attacker console, see kill at file 2, 18/18 restored, vault evidence.
