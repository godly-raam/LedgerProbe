# Benchmark Pre-registration

Status: **sealed before the first target run**. No target scans, rule authoring, or
rule tuning has been performed for these files. The first run is pending.

## Engine Freeze

| Item | Value |
|---|---|
| `git rev-parse HEAD` | `9944bb360807fee64d33251515b503ecc4d12573` |
| `ledgerprobe --version` | `LedgerProbe 1.1.0` |
| Engine policy | The engine is frozen at the above commit for the first run. Any engine change after the first run is a separate post-freeze condition. |

## Target Snapshots

| Target | Upstream snapshot | Image / runtime |
|---|---|---|
| VAmPI | `f16052dce83f05847133ec98f01c5193a41de7d8` | `erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12` |
| crAPI | `700f03d12a392d9e408260b4beae72ed02a4a1a4` (`v1.1.6`) | crAPI source at that commit; no digest claimed in this pre-registration |
| DVR | `d32d09972aec7830f5f1d4a5d274cac7aae7eb82` | Built locally from that commit with Docker Compose; no published image is used |

## Ground-Truth File Hashes

These hashes are part of the pre-registration. They are not regenerated after a
target run.

| File | SHA-256 |
|---|---|
| `benchmark/ground_truth/ext_vampi.yaml` | `70a94850bdaa892cc60c8dc0873eb5114b278f0f958849db080e41f65befe79d` |
| `benchmark/ground_truth/ext_crapi.yaml` | `3b2ac7a762e66551a82ec15120192a97c77c5e1c48bfd82e6771083e6209191a` |
| `benchmark/ground_truth/ext_dvr.yaml` | `d3b356c9b1859d044bdd207f72bf698083dc83269702eb54193c72b7b201bee8` |

## Protocol

1. **Rule authoring.** Rules are written once from each target's own documentation,
   OpenAPI/Postman document, and source only. Access is time-boxed to one authoring
   session per target, and no target response or LedgerProbe output may be used to
   choose or alter a rule. Every edit after the first run is recorded in
   `benchmark/rule_edit_log.md` with timestamp, run, rule file, edit, reason, and the
   first-run result it follows.
2. **Headline run.** The **first run** is the headline result. Rules are not changed
   between the first run and the recorded headline counts.
3. **After-tuning reporting.** Any later change to a rule or the engine is reported
   as a separate **after tuning** row with the before/after counts; it never replaces
   or rewrites the headline row.
4. **Inconclusive outcomes.** `INCONCLUSIVE` on a vulnerable case counts as a miss.
   `INCONCLUSIVE` on a safe case is reported separately in `INC_safe`; it is not
   silently treated as a pass or merged into `FP`.
5. **Metrics table format.** Results are reported per class per target as
   `TP / FP / TN / FN / INC_vuln / INC_safe`, with counts and Wilson 95% confidence
   intervals for rates. Rates are descriptive; the benchmark is same-author and
   small-sample. Same-author construction, rule tuning, and target knowledge remain
   a caveat even when intervals are shown.
6. **Engine freeze.** The engine is frozen at
   `9944bb360807fee64d33251515b503ecc4d12573` during the first run. The frozen
   binary is the `1.1.0` CLI reported above.
7. **No scans in this task.** This pre-registration task writes no rules and runs no
   target scans. The first run is a separate, later event.
8. **Publication.** The maintainer commits the three `ext_*.yaml` files, this
   pre-registration, and `benchmark/rule_edit_log.md` alone before any target scan.
