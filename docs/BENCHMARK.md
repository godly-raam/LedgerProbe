# LedgerProbe real-world benchmark

The v3 VAmPI differential run is clean on its own terms: **8 TP, 5 TN, 0 FP,
0 FN, 0 abstentions** on 13 cases. It is the third tuning round on those same
13 cases, not an independent validation. Including the unchanged crAPI rows,
the aggregate v3 differential result is **13 TP, 0 FP, 9 TN, 0 FN, and 1
abstention** (one safe crAPI case). The pre-tuning number is still **v1**:
0 FP of 10 safe cases, 10 of 13 vulnerable cases detected, and 9 abstentions.
v2 was 0 FP of 10 safe cases, 12 of 13 vulnerable cases detected, and 3
abstentions.

v2 rules were authored after viewing v1 results; v1 is the pre-tuning number.
v3 rules were authored after viewing v2 results. This benchmark is
small and source-derived, not a population estimate. It measures whether
LedgerProbe's differential authorization engine finds documented BOLA/IDOR on
projects the engine's authors did not write. It compares the current engine with
two legacy status-only baselines on identical endpoints. It is not a product
security assessment.

The sample is **23 cases across 18 distinct endpoints**. VAmPI's 13 cases are 8
distinct endpoints run in both target modes (`vulnerable=1` and `vulnerable=0`);
the effective number of independent endpoint observations is therefore smaller
than 23.

## Safety model

`benchmark/run.py` refuses to start unless every target URL is loopback
(`127.0.0.1`, `localhost`, `::1`) or, only with an explicit opt-in, an RFC1918
Docker address or a named Compose service. Public IPs, public hostnames,
link-local/metadata addresses, credentials in URLs, non-HTTP schemes and invalid
ports raise `UnsafeTarget` before a request is opened. `benchmark/tests` contains
the hard-fail tests for that guard, including `8.8.8.8`, `169.254.169.254`,
`127.0.0.1.evil.test` and `0.0.0.0`.

Mutating rules must declare `mutating: true`; the YAML loader rejects any other
rule whose target method is not GET/HEAD/OPTIONS. A mutating rule executes only
when all three conditions hold:

- `--allow-mutations` is present;
- the target host is loopback or explicitly listed with `--allow-host`;
- the scan is not `--read-only`.

Otherwise the rule is `SKIPPED` with reason `mutation_blocked` and a message
naming the missing condition. Every mutating rule requires a `restore:` block;
restore runs through `GuardedClient` in a `finally` path, even after FAIL or
ERROR. A failed restore is `ERROR restore_failed` and a non-zero exit. Mutation
attempts are capped at one per rule, and a rule without a `verify:` block is
`INCONCLUSIVE unverified_mutation` after a 2xx response.

The VAmPI legacy rows in this document were recorded at v1, not re-run for v2 or
v3. The legacy PUT rule predates the `mutating` contract and would need migration
before a full legacy replay. The VAmPI differential set includes the documented password-change mutation.
crAPI rules are read-only and the benchmark runs the engine with `--read-only`.
The legacy VAmPI status baseline is a historical v1 record; its PUT rule predates
the `mutating` contract and would need migration before a full legacy replay.

The separate **56-profile fixture corpus** is also 100%, but those fixtures and
the engine were written by the same author. It is a regression guard for known
behaviors, not an accuracy measurement. The race suite likewise validates the
engine on loopback fixtures; it does not establish that a real target is free of
race conditions. See `docs/RACE.md` for the race design and detection study.

## Targets and versions

| Target | Upstream revision | Runtime | Modes |
| --- | --- | --- | --- |
| VAmPI | `erev0s/VAmPI@f16052dce83f05847133ec98f01c5193a41de7d8` | `erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12` | `vulnerable=1`, `vulnerable=0` |
| crAPI | OWASP/crAPI `v1.1.6` source snapshot (`benchmark/.out/crapi-source`; its `VERSION` file is stale) | eight target images pinned by digest in `targets/crapi/compose.yaml`, including `crapi-identity` `1.1.6` | single deployment |

The recorded v2 run used Docker Engine `28.5.2+dfsg4` and Compose `2.40.3-3`.
The v3 VAmPI differential re-run used the same pinned image and stack. VAmPI's
image reference is mutable, so its manifest digest is pinned. crAPI identifies
only `crapi-identity` as `1.1.6`; the other components have `latest` images,
which are pinned by digest rather than retagged.

## Ground truth provenance

Ground truth was committed as `6eabf48` **before** any LedgerProbe run against
these targets. Labels come only from the targets' README/docs/OpenAPI/service
source; no LedgerProbe output influenced them. Files:

- `benchmark/ground_truth/vampi.yaml` — 13 cases: **8 vulnerable, 5 safe**.
- `benchmark/ground_truth/crapi.yaml` — 10 cases: **5 vulnerable, 5 safe**.

The 23 cases cover 18 distinct endpoints: VAmPI contributes 8 endpoints (each
run in both target modes) and crAPI contributes 10. The secure VAmPI mode is not
a fully patched deployment: three secure-mode endpoints remain vulnerable
ground truth. In particular, `vampi-users-object` is labelled vulnerable in both
target modes; a FAIL on the `vulnerable=0` row is a true positive for that
label, not a false positive caused by the word "safe" in a target-mode column.

The 1.1.5→1.1.6 reconciliation diffed every cited file. No label changed.
`service_requests/{vin}` did not exist in 1.1.5 and was added without
authentication in 1.1.6; it remains vulnerable ground truth.

The final v3 run was checked with:

```bash
git diff bench-v1..HEAD -- benchmark/ground_truth
```

The command was empty. `bench-v1` is commit `78ef225`; the pre-change results are
also copied to `benchmark/results_v1.md`.

## Method

1. `benchmark/targets/<target>/setup.py` creates two identities, obtains tokens
   and seeds owner objects with unique canaries. Auth/setup lives in the target
   adapter, never in the engine. Inputs are written under
   `benchmark/.out/<target>/<instance>/inputs.json` with mode `0600` and are
   gitignored. VAmPI setup also records `original_password` for the mutation
   restore path. Each target run removes generated `inputs.json` token files
   after scoring; use `--keep-out` only when you intentionally need to inspect
   them locally.
2. Modes run through the same OpenAPI snapshot, base URLs, inputs and rate limit:
   - **legacy_strict**: the engine's exact `403` status assertion. This is the
     naive baseline: it has no canary, control, confirmation or soft-deny logic.
   - **legacy_lenient**: a harness-level status evaluator, because the engine
     only supports an exact status code. `{401,403,404}` is PASS, any 2xx is
     FAIL, and anything else (including timeout) is INCONCLUSIVE. It is a
     baseline, not an engine mode.
   - **differential**: scoped owner/other comparison, owner canaries, existential
     controls, confirmations, and bounded pagination where applicable. Rules
     declare `scope: object` (default), `caller`, or `shared`. In v3, a mutating
     rule uses `marker`, `probe` or `state_diff` verification and a mandatory
     restore.
3. Before every run, `benchmark/run.py` removes the Compose project and its
   volumes, starts it again with `--wait`, and re-runs setup. No target state
   survives between runs. The v3 VAmPI differential row used three fresh-reset
   runs.
4. JUnit is scored against frozen labels. `INCONCLUSIVE` on a vulnerable case is
   `INC_VULN`; on a safe case it is `INC_SAFE`. A skipped endpoint and an
   execution error are both inconclusive, never correct. Every row's six counts
   are asserted to sum to N.
5. `Recall` counts `INC_VULN` as a miss: `TP / (TP + FN + INC_VULN)`.
   `Recall excl. INC` is `TP / (TP + FN)`. `Precision` is `TP / (TP + FP)`.

## Version comparison

Differential mode only; the v3 run re-scored VAmPI and left crAPI unchanged.
Cells are `TP/FP/TN/FN/INC_vuln/INC_safe`.

| Target | v1 | v2 | v3 |
| --- | --- | --- | --- |
| VAmPI | 7/0/3/0/1/2 | 7/0/4/0/1/1 | 8/0/5/0/0/0 |
| crAPI | 3/0/1/0/2/4 | 5/0/4/0/0/1 | 5/0/4/0/0/1 |
| **Overall** | **10/0/4/0/3/6** | **12/0/8/0/1/2** | **13/0/9/0/0/1** |

v2 rules were authored after viewing v1 results; v1 is the pre-tuning number.
v3 rules were authored after viewing v2 results. The v3 change is
concentrated in the VAmPI password case: the forbidden mutation's generic 204
response is now verified by an owner login probe, and the owner password is
restored in a `finally` path.

## Results

The v3 row is the re-run differential. The legacy rows are the recorded v1
results; v2 and v3 did not re-run them.

| Target | Mode | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VAmPI | legacy_strict | 13 | 8 | 5 | 0 | 0 | 0 | 0 | 61.5% | 100.0% | 100.0% |
| VAmPI | legacy_lenient | 13 | 8 | 4 | 1 | 0 | 0 | 0 | 66.7% | 100.0% | 100.0% |
| VAmPI | differential (v3) | 13 | 8 | 0 | 5 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| crAPI | legacy_strict | 10 | 4 | 4 | 0 | 0 | 1 | 1 | 50.0% | 80.0% | 100.0% |
| crAPI | legacy_lenient | 10 | 5 | 4 | 1 | 0 | 0 | 0 | 55.6% | 100.0% | 100.0% |
| crAPI | differential | 10 | 5 | 0 | 4 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |

`benchmark/RESULTS.md` is the generated per-case report.

Re-verified on 2026-11-07 at commit c9b347f, 3 fresh-reset runs, identical verdicts.
The VAmPI differential v3 row was identical across three fresh-reset runs; there were zero verdict flips. The crAPI differential row was likewise identical. The VAmPI legacy rows and crAPI legacy rows remain the v1 records: VAmPI legacy predates the `mutating` contract, and crAPI legacy scans could not produce valid rows because the current target returned no 2xx baseline for the deprecated static-context inputs.

The overall differential inconclusive rate fell from **9/23 (39.1%)** in v1 to
**3/23 (13.0%)** in v2 and **1/23 (4.3%)** in v3. The remaining abstention is
`crapi-vehicles`, where the other identity has no vehicle to compare.

## Object-scoped-only cut

The cut below keeps only cases whose rule declares `scope: object` (the default).
Scope is author-declared in the rule, never derived from a ground-truth label.
This avoids giving the engine credit for caller/shared declarations when
comparing against the legacy baselines.

| Target | Mode | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VAmPI | legacy_strict | 6 | 4 | 2 | 0 | 0 | 0 | 0 | 66.7% | 100.0% | 100.0% |
| VAmPI | legacy_lenient | 6 | 4 | 1 | 1 | 0 | 0 | 0 | 80.0% | 100.0% | 100.0% |
| VAmPI | differential (v3) | 6 | 4 | 0 | 2 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| crAPI | legacy_strict | 5 | 3 | 1 | 0 | 0 | 1 | 0 | 75.0% | 75.0% | 100.0% |
| crAPI | legacy_lenient | 5 | 4 | 0 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| crAPI | differential | 5 | 4 | 0 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |

Aggregate differential object-only cut:

| Cut | N | TP | FP | TN | FN | INC_vuln | INC_safe | Recall | Inconclusive rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| v1 object-only | 11 | 5 | 0 | 2 | 0 | 3 | 1 | 62.5% | 36.4% |
| v2 object-only | 11 | 7 | 0 | 2 | 0 | 1 | 1 | 87.5% | 18.2% |
| v3 object-only | 11 | 8 | 0 | 3 | 0 | 0 | 0 | 100.0% | 0.0% |

## Determinism

The VAmPI differential v3 row produced identical verdicts in all three
fresh-reset runs; there were **zero flips**. The legacy and crAPI rows are the
v2 determinism records. The per-run comparison is in `benchmark/RESULTS.md`.

## Before and after, per case

Differential mode. "Target mode" is the deployment switch or single deployment
used for that row; it is not a ground-truth label. "Ground-truth label" is the
frozen label in `benchmark/ground_truth/`. “Same” means the verdict did not
change; reason changes without a verdict change are called out in the findings.

| Target | Case | Target mode | Ground-truth label | v1 | v2 | v3 | Reason for change |
| --- | --- | --- | --- | --- | --- | --- | --- |
| VAmPI | `vampi-books-object` | `vulnerable=1` | vulnerable | FAIL | FAIL | FAIL | Same |
| VAmPI | `vampi-users-password` | `vulnerable=1` | vulnerable | INCONCLUSIVE | INCONCLUSIVE | FAIL | v3 owner-login probe proves the password changed |
| VAmPI | `vampi-users-object` | `vulnerable=1` | vulnerable | FAIL | FAIL | FAIL | Same |
| VAmPI | `vampi-users-list` | `vulnerable=1` | vulnerable | FAIL | FAIL | FAIL | Same; shared scope uses the owner-email canary |
| VAmPI | `vampi-users-debug` | `vulnerable=1` | vulnerable | FAIL | FAIL | FAIL | Same; shared scope uses the owner-email canary |
| VAmPI | `vampi-home` | `vulnerable=1` | safe | PASS | PASS | PASS | Same; shared-data note |
| VAmPI | `vampi-book-list` | `vulnerable=1` | safe | PASS | PASS | PASS | Same; shared-data note |
| VAmPI | `vampi-me` | `vulnerable=1` | safe | INCONCLUSIVE | PASS | PASS | Caller scope: other identity's own profile is non-empty and has no owner canary |
| VAmPI | `vampi-books-object` | `vulnerable=0` | safe | PASS | PASS | PASS | Same |
| VAmPI | `vampi-users-password` | `vulnerable=0` | safe | INCONCLUSIVE | INCONCLUSIVE | PASS | v3 probe shows the owner password was unchanged (`no_effect`) |
| VAmPI | `vampi-users-object` | `vulnerable=0` | vulnerable | FAIL | FAIL | FAIL | Same; secure mode still exposes the profile |
| VAmPI | `vampi-users-list` | `vulnerable=0` | vulnerable | FAIL | FAIL | FAIL | Same; secure mode still exposes the directory |
| VAmPI | `vampi-users-debug` | `vulnerable=0` | vulnerable | FAIL | FAIL | FAIL | Same; debug endpoint remains vulnerable |
| crAPI | `crapi-vehicle-location` | single | vulnerable | FAIL | FAIL | FAIL | Same |
| crAPI | `crapi-mechanic-report` | single | vulnerable | FAIL | FAIL | FAIL | Same |
| crAPI | `crapi-order-object` | single | vulnerable | INCONCLUSIVE | FAIL (reduced confidence; control returned 500) | FAIL (reduced confidence; control returned 500) | Reproduced owner canary yields a reduced-confidence FAIL |
| crAPI | `crapi-community-recent` | single | vulnerable | FAIL | FAIL | FAIL | Same; shared scope uses the vehicle-id canary |
| crAPI | `crapi-service-requests-vin` | single | vulnerable | SKIPPED | FAIL | FAIL | `spec_check: warn` executes the route missing from the published spec |
| crAPI | `crapi-dashboard` | single | safe | INCONCLUSIVE | PASS | PASS | Caller scope: other dashboard is non-empty and owner-canary-free |
| crAPI | `crapi-vehicles` | single | safe | INCONCLUSIVE | INCONCLUSIVE | INCONCLUSIVE | Other identity has an empty vehicle list; abstention is correct |
| crAPI | `crapi-orders-all` | single | safe | ERROR | PASS | PASS | Rule supplies required `limit`/`offset`; caller scope passes |
| crAPI | `crapi-products` | single | safe | INCONCLUSIVE | PASS | PASS | Shared catalogue has no owner canary |
| crAPI | `crapi-video-object` | single | safe | PASS | PASS | PASS | Same |

`crapi-order-object` is a **reduced-confidence FAIL** in v2 and v3. Its
nonexistent-object control returned 500 (`control_unusable`), so the negative
control could not separate generic overlap from owner data. The owner canary was
still reproducible, which is why the result is FAIL rather than INCONCLUSIVE,
but it should not be read with the confidence of the other findings.

No case got a worse verdict in v3. `crapi-vehicles` is the one safe caller case
that remains an abstention: the second identity has no vehicle, and the
caller-scope contract deliberately treats an empty successful response as
`ambiguous_2xx`, not a vacuous pass.

## VAmPI findings

- **legacy_strict FP (5):** `vampi-home`, `vampi-book-list`, `vampi-me`,
  `vampi-books-object` on `vulnerable=0`, and `vampi-users-password` on
  `vulnerable=0`. These are public/self-scoped responses that exact-403 treats
  as findings.
- **legacy_lenient FP (4):** the same rows except secure `vampi-books-object`
  (404 becomes TN). The safe self-password update still returns 204 and remains
  FP.
- **v3 differential password case:** on `vulnerable=1`, the forbidden PUT
  returns 204 and changes the owner's password. VAmPI's source
  (`api_views/users.py:186-196`) updates the username in the path in that mode.
  The owner-login probe with the new password returns an `auth_token`, so the
  verdict is `FAIL state_changed_by_other`. On `vulnerable=0`, the same PUT
  targets the JWT subject instead, the owner-login probe fails, and the verdict
  is `PASS no_effect`. The owner password is restored after either outcome.
- `vampi-me`, `vampi-home`, and `vampi-book-list` are safe PASSes under
  caller/shared scope. The user directory and debug endpoints still fail
  because they expose the owner email to another identity.

## crAPI findings

- **legacy_strict:** 4 TP (`vehicle-location`, `mechanic-report`,
  `order-object`, `community-recent`); 4 FP (`dashboard`, `vehicles`,
  `products`, `video-object`); `service-requests-vin` is `INC_VULN`
  (`endpoint_absent`); `orders-all` is `INC_SAFE` (`execution_error`).
- **legacy_lenient:** 5 TP, including `service-requests-vin`; 4 FP; `video-object`
  is TN (404).
- **differential:** 5 TP, 4 TN, 1 `INC_SAFE` (`vehicles`), no FP or FN.
  `order-object` fails with `leak_detected` and note `control_unusable`;
  `service-requests-vin` fails via `unauthenticated_leak` after spec-drift
  execution; dashboard, orders-all, and products are safe PASSes.
- **`crapi-vehicles` (`INC_SAFE`, `ambiguous_2xx`):** the other identity has no
  vehicle list. Caller scope requires a non-empty other response before a PASS,
  so an empty successful list remains ambiguous. Seeding a vehicle for the other
  identity would change the fixture, not the semantics. The abstention is
  correct.

## ZAP relevance

OWASP ZAP
`sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238`
was available and a **safe API baseline** (`-S`) was run against the crAPI
OpenAPI snapshot in the v1 workspace. It completed with **0 FAIL, 8 WARN-NEW and
114 PASS** over 44 imported endpoints. The warnings were missing security
headers, server-version disclosure, server errors and content-type issues. There
was **no BOLA/IDOR alert** that maps to a ground-truth case. ZAP was
unauthenticated and has no two-identity owner/other comparison, so it neither
confirms nor refutes the differential results and does not affect any score. It
was not rerun for v3 because the engine changes do not alter target content.

## Remaining gaps

- A mutating rule without `verify:` remains `INCONCLUSIVE unverified_mutation`.
  The engine never guesses PASS or FAIL from a generic 2xx body.
- Mutation execution is opt-in and host-limited; it is not enabled in the default
  CI scan. A missing `restore:` is a loader error.
- An empty successful caller response is treated as ambiguous; a caller with no
  objects cannot produce a vacuous PASS.
- `control_unusable` findings are deliberately reduced-confidence: the missing
  negative control means generic overlap cannot be separated from owner data.
- Spec-drift execution synthesizes only path parameters from the rule target;
  absent query/body schema information still fails closed.
- Scope is declared by the rule author. A wrong `caller` or `shared`
  declaration can weaken or misclassify a check; the benchmark cites the target
  source in each rule comment, but this is not independent verification.
- The VAmPI legacy status baseline is a v2 record. Its PUT rule predates the
  `mutating` contract; migrating it before a full legacy replay is future work.
- ZAP's baseline is not an authorization oracle, and crAPI has no secure/fixed
  deployment for comparison.

## Limitations

- The sample is **23 cases across 18 distinct endpoints** (13 VAmPI cases over 8
  endpoints, run in both target modes; 10 crAPI cases), not a population. There
  are no confidence intervals or inter-rater checks; three repeats establish
  determinism, not statistical significance.
- The engine, rules, and benchmark share the same author. The 56-profile fixture
  corpus guards regressions but cannot measure accuracy. Ground truth was frozen
  first, but endpoint selection, canaries, and scope declarations still reflect
  knowledge of the targets. v2 was authored after v1 results and v3 after v2
  results; v1 is the pre-tuning number.
- Scope declarations are author-supplied and were not independently audited.
- VAmPI's ground truth mixes unauthenticated directory/debug exposure with
  classic object BOLA; it is not a pure BOLA benchmark. The `vulnerable=0` mode
  is not a full fix, so a safe-looking target-mode label is not a ground-truth
  label.
- crAPI is a single deployment. Its safe cases are token-scoped controls, not a
  patched/secure version.
- The exact-403 baseline is intentionally strict; 404 and 204 are treated as
  failures even when they are correct denials or self-scoped updates.
- `legacy_lenient` is a harness policy, not an engine feature. Its
  `{401,403,404}` pass set can also hide an existence leak; it is reported as a
  baseline only.
- No secrets, tokens or databases are committed. Runtime artifacts live under
  `benchmark/.out/` and are gitignored.

## What could not run

- The v3 VAmPI differential mode and crAPI differential mode ran. VAmPI legacy
  modes were not re-run for v2/v3; their rows are the recorded v1 results because
  the legacy rule file predates the `mutating` contract.
- The crAPI legacy replay was attempted but could not produce valid rows: every
  legacy rule errored because the current target returned no 2xx baseline for the
  deprecated static-context inputs. Those rows remain the v1 records.
- `crapi-vehicles` could not produce a caller-scoped PASS because the other test
  identity has no vehicle, so its successful response is an empty list.
- A ZAP active scan and an authenticated ZAP scan were not run. The safe
  baseline is the only ZAP evidence.
- crAPI has no secure/fixed deployment, so there is no crAPI secure-mode
  comparison.

## Reproduce

With Docker and Compose v2 available, the v3 VAmPI differential re-score is:

```bash
.venv/bin/python benchmark/run.py --target vampi --modes differential --repeats 3 --merge
```

This starts the pinned Compose stack, resets it before every run, runs setup,
executes the differential mode three times, checks that every count row sums to
N, merges the differential row into the existing results, writes
`benchmark/RESULTS.md` and `benchmark/.out/results.json`, and removes the
Compose project. Add `--keep` to inspect the stack after the final run.

A full legacy replay would additionally require migrating
`benchmark/targets/vampi/rules_legacy.yaml` to the `mutating` contract; the
recorded legacy rows above are the v1 baseline. The pre-change results remain at
`benchmark/results_v1.md`.

Run the guard/scorer tests with:

```bash
.venv/bin/python -m pytest benchmark/tests -q
```
