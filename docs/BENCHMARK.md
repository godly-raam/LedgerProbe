# LedgerProbe real-world benchmark

LedgerProbe differential v2 result: **0 FP of 10 safe cases, 12 of 13 vulnerable
cases detected, and 3 abstentions** (one vulnerable, two safe). The previous
differential result was 0 FP of 10 safe cases, 10 of 13 vulnerable detected, and
9 abstentions. This is a small, source-derived benchmark, not a population
estimate.

This benchmark measures whether LedgerProbe's differential authorization engine
finds documented BOLA/IDOR on projects the engine's authors did not write. It
compares the current engine with two legacy status-only baselines on identical
endpoints. It is deliberately small and fully local; it is not a product
security assessment.

## Safety model

`benchmark/run.py` refuses to start unless every target URL is loopback
(`127.0.0.1`, `localhost`, `::1`) or, only with an explicit opt-in, an RFC1918
Docker address or a named Compose service. Public IPs, public hostnames,
link-local/metadata addresses, credentials in URLs, non-HTTP schemes and invalid
ports raise `UnsafeTarget` before a request is opened. `benchmark/tests` contains
the hard-fail tests for that guard, including `8.8.8.8`, `169.254.169.254`,
`127.0.0.1.evil.test` and `0.0.0.0`.

Both Compose files publish only on `127.0.0.1`. The only target mutation in the
VAmPI rule set is the documented password-change endpoint; all other rules are
GETs. crAPI rules are read-only and the benchmark runs the engine with
`--read-only`.

## Targets and versions

| Target | Upstream revision | Runtime | Modes |
| --- | --- | --- | --- |
| VAmPI | `erev0s/VAmPI@f16052dce83f05847133ec98f01c5193a41de7d8` | `erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12` | `vulnerable=1`, `vulnerable=0` |
| crAPI | OWASP/crAPI `v1.1.6` source snapshot (`benchmark/.out/crapi-source`; its `VERSION` file is stale) | eight release images pinned by digest in `targets/crapi/compose.yaml`, including `crapi-identity` `1.1.6` | single deployment |

The recorded v2 run used Docker Engine `28.5.2+dfsg4` and Compose `2.40.3-3`.
VAmPI's only published tag is mutable, so its manifest digest is pinned. crAPI
publishes a `1.1.6` tag only for `crapi-identity`; the other components only have
release-day `latest` images, which are pinned by digest rather than retagged.

## Ground truth provenance

Ground truth was committed as `6eabf48` **before** any LedgerProbe run against
these targets. Labels come only from the targets' README/docs/OpenAPI/service
source; no LedgerProbe output influenced them. Files:

- `benchmark/ground_truth/vampi.yaml` — 13 cases: **8 vulnerable, 5 safe**.
- `benchmark/ground_truth/crapi.yaml` — 10 cases: **5 vulnerable, 5 safe**.

The 1.1.5→1.1.6 reconciliation diffed every cited file. No label changed.
`service_requests/{vin}` did not exist in 1.1.5 and was added without
authentication in 1.1.6; it remains vulnerable ground truth.

The final v2 run was checked with:

```bash
git diff bench-v1..HEAD -- benchmark/ground_truth
```

The command was empty. `bench-v1` is tag `78ef225`; the pre-change results are
also copied to `benchmark/results_v1.md`.

## Method

1. `benchmark/targets/<target>/setup.py` creates two identities, obtains tokens
   and seeds owner objects with unique canaries. Auth/setup lives in the target
   adapter, never in the engine. Inputs are written under
   `benchmark/.out/<target>/<instance>/inputs.json` with mode `0600` and are
   gitignored.
2. Three modes run through the same OpenAPI snapshot, base URLs, inputs and rate
   limit:
   - **legacy_strict**: the engine's exact `403` status assertion. This is the
     naive baseline: it has no canary, control, confirmation or soft-deny logic.
   - **legacy_lenient**: a harness-level status evaluator, because the engine
     only supports an exact status code. `{401,403,404}` is PASS, any 2xx is
     FAIL, and anything else (including timeout) is INCONCLUSIVE. It is a
     baseline, not an engine mode.
   - **differential**: scoped owner/other comparison, owner canaries, existential
     controls, confirmations, and bounded pagination where applicable. Rules
     declare `scope: object` (default), `caller`, or `shared`.
3. Before every run, `benchmark/run.py` removes the Compose project and its
   volumes, starts it again with `--wait`, and re-runs setup. No target state
   survives between runs.
4. JUnit is scored against frozen labels. `INCONCLUSIVE` on a vulnerable case is
   `INC_VULN`; on a safe case it is `INC_SAFE`. A skipped endpoint and an
   execution error are both inconclusive, never correct. Every row's six counts
   are asserted to sum to N.
5. `Recall` counts `INC_VULN` as a miss: `TP / (TP + FN + INC_VULN)`.
   `Recall excl. INC` is `TP / (TP + FN)`. `Precision` is `TP / (TP + FP)`.

## Results

| Target | Mode | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VAmPI | legacy_strict | 13 | 8 | 5 | 0 | 0 | 0 | 0 | 61.5% | 100.0% | 100.0% |
| VAmPI | legacy_lenient | 13 | 8 | 4 | 1 | 0 | 0 | 0 | 66.7% | 100.0% | 100.0% |
| VAmPI | differential | 13 | 7 | 0 | 4 | 0 | 1 | 1 | 100.0% | 87.5% | 100.0% |
| crAPI | legacy_strict | 10 | 4 | 4 | 0 | 0 | 1 | 1 | 50.0% | 80.0% | 100.0% |
| crAPI | legacy_lenient | 10 | 5 | 4 | 1 | 0 | 0 | 0 | 55.6% | 100.0% | 100.0% |
| crAPI | differential | 10 | 5 | 0 | 4 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |

`benchmark/RESULTS.md` is the generated per-case report. All six v2 rows were
identical across three fresh-reset runs; there were zero verdict flips.

## Object-scoped-only cut

The cut below keeps only cases whose rule declares `scope: object` (the default).
Scope is author-declared in the rule, never derived from a ground-truth label.
This avoids giving the engine credit for caller/shared declarations when
comparing against the legacy baselines.

| Target | Mode | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VAmPI | legacy_strict | 6 | 4 | 2 | 0 | 0 | 0 | 0 | 66.7% | 100.0% | 100.0% |
| VAmPI | legacy_lenient | 6 | 4 | 1 | 1 | 0 | 0 | 0 | 80.0% | 100.0% | 100.0% |
| VAmPI | differential | 6 | 3 | 0 | 1 | 0 | 1 | 1 | 100.0% | 75.0% | 100.0% |
| crAPI | legacy_strict | 5 | 3 | 1 | 0 | 0 | 1 | 0 | 75.0% | 75.0% | 100.0% |
| crAPI | legacy_lenient | 5 | 4 | 0 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| crAPI | differential | 5 | 4 | 0 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |

Aggregate differential object-only cut:

| Cut | N | TP | FP | TN | FN | INC_vuln | INC_safe | Recall | Inconclusive rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| v1 object-only | 11 | 5 | 0 | 2 | 0 | 3 | 1 | 62.5% | 36.4% |
| v2 object-only | 11 | 7 | 0 | 2 | 0 | 1 | 1 | 87.5% | 18.2% |

The overall differential inconclusive rate fell from **9/23 (39.1%)** in v1 to
**3/23 (13.0%)** in v2. The object-only rate fell from **4/11 (36.4%)** to
**2/11 (18.2%)**.

## Determinism

All six target/mode rows produced identical verdicts in all three v2 runs. There
were **zero flips**. The per-run comparison is in `benchmark/RESULTS.md`; the
three reset cycles also reproduced the same counts.

## Before and after, per case

The table is the differential mode, which is the engine mode changed by this
work. The legacy baselines are included in the results table above. “Same”
means the verdict did not change; reason changes without a verdict change are
called out in the diagnosis.

| Target | Case | v1 verdict | v2 verdict | Reason for change |
| --- | --- | --- | --- | --- |
| VAmPI | `vampi-books-object` vulnerable | FAIL | FAIL | Same |
| VAmPI | `vampi-users-password` vulnerable | INCONCLUSIVE | INCONCLUSIVE | Same; generic 204 has no owner canary |
| VAmPI | `vampi-users-object` vulnerable | FAIL | FAIL | Same |
| VAmPI | `vampi-users-list` vulnerable | FAIL | FAIL | Same verdict; shared scope now uses the owner-email canary |
| VAmPI | `vampi-users-debug` vulnerable | FAIL | FAIL | Same verdict; shared scope now uses the owner-email canary |
| VAmPI | `vampi-home` safe | PASS | PASS | Same; shared-data note |
| VAmPI | `vampi-book-list` safe | PASS | PASS | Same; shared-data note |
| VAmPI | `vampi-me` safe | INCONCLUSIVE | PASS | Caller scope: other identity's own profile is non-empty and has no owner canary |
| VAmPI | `vampi-books-object` safe | PASS | PASS | Same |
| VAmPI | `vampi-users-password` safe | INCONCLUSIVE | INCONCLUSIVE | Same; generic 204 remains ambiguous |
| VAmPI | `vampi-users-object` safe | FAIL | FAIL | Same |
| VAmPI | `vampi-users-list` safe | FAIL | FAIL | Same |
| VAmPI | `vampi-users-debug` safe | FAIL | FAIL | Same |
| crAPI | `crapi-vehicle-location` | FAIL | FAIL | Same |
| crAPI | `crapi-mechanic-report` | FAIL | FAIL | Same |
| crAPI | `crapi-order-object` | INCONCLUSIVE | FAIL | Control 500 is `control_unusable`; reproduced owner canary yields reduced-confidence FAIL |
| crAPI | `crapi-community-recent` | FAIL | FAIL | Same; shared scope uses the vehicle-id canary |
| crAPI | `crapi-service-requests-vin` | SKIPPED | FAIL | `spec_check: warn` executes the route missing from the published spec |
| crAPI | `crapi-dashboard` | INCONCLUSIVE | PASS | Caller scope: other identity's dashboard is non-empty and owner-canary-free |
| crAPI | `crapi-vehicles` | INCONCLUSIVE | INCONCLUSIVE | Other identity has an empty vehicle list, so caller scope remains ambiguous |
| crAPI | `crapi-orders-all` | ERROR | PASS | Rule supplies required `limit`/`offset`; caller scope passes |
| crAPI | `crapi-products` | INCONCLUSIVE | PASS | Shared catalogue has no owner canary |
| crAPI | `crapi-video-object` | PASS | PASS | Same |

No case got a worse verdict. `crapi-vehicles` is the one safe caller case that
did not become a PASS: the second identity has no vehicle, and the caller-scope
contract deliberately treats an empty successful response as
`ambiguous_2xx`, not a vacuous pass.

## VAmPI findings

- **legacy_strict FP (5):** `vampi-home`, `vampi-book-list`, `vampi-me`,
  `vampi-books-object` on `vulnerable=0`, and `vampi-users-password` on
  `vulnerable=0`. These are public/self-scoped responses that exact-403 treats
  as findings.
- **legacy_lenient FP (4):** the same rows except secure `vampi-books-object`
  (404 becomes TN). The safe self-password update still returns 204 and remains
  FP.
- **differential INC_VULN:** `vampi-users-password` on `vulnerable=1`. VAmPI
  returns a generic 204 with no owner canary; the password change is real but
  its response cannot prove which account changed.
- **differential INC_SAFE:** secure `vampi-users-password` returns the same
  generic 204.
- `vampi-me`, `vampi-home`, and `vampi-book-list` are now safe PASSes under
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
  `order-object` now fails with `leak_detected` and note `control_unusable`;
  `service-requests-vin` fails via `unauthenticated_leak` after spec-drift
  execution; dashboard, orders-all, and products are safe PASSes.
- **`crapi-vehicles` (`INC_SAFE`, `ambiguous_2xx`):** the other identity has no
  vehicle list. Caller scope requires a non-empty other response before a PASS,
  so an empty successful list remains ambiguous. Seeding a vehicle for the other
  identity would change the fixture, not the semantics.

## ZAP relevance

OWASP ZAP
`ghcr.io/zaproxy/zaproxy@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238`
was available and a **safe API baseline** (`-S`) was run against the crAPI
OpenAPI snapshot in the v1 workspace. It completed with **0 FAIL, 8 WARN-NEW and
114 PASS** over 44 imported endpoints. The warnings were missing security
headers, server-version disclosure, server errors and content-type issues. There
was **no BOLA/IDOR alert** that maps to a ground-truth case. ZAP was
unauthenticated and has no two-identity owner/other comparison, so it neither
confirms nor refutes the differential results and does not affect any score. It
was not rerun for v2 because the engine changes do not alter target content.

## Remaining gaps

- State-changing BOLA without an owner-specific response body stays
  INCONCLUSIVE.
- An empty successful caller response is treated as ambiguous; a caller with no
  objects cannot produce a vacuous PASS.
- `control_unusable` findings are deliberately reduced-confidence: the missing
  negative control means generic overlap cannot be separated from owner data.
- Spec-drift execution synthesizes only path parameters from the rule target;
  absent query/body schema information still fails closed.
- Scope is declared by the rule author. A wrong `caller` or `shared`
  declaration can weaken or misclassify a check; the benchmark cites the target
  source in each rule comment, but this is not independent verification.
- ZAP's baseline is not an authorization oracle, and crAPI has no secure/fixed
  deployment for comparison.

## Limitations

- The sample is 23 endpoint cases (13 VAmPI, 10 crAPI), not a population. There
  are no confidence intervals or inter-rater checks; three repeats establish
  determinism, not statistical significance.
- The engine, rules, and benchmark share the same author. Ground truth was frozen
  first, but endpoint selection, canaries, and scope declarations still reflect
  knowledge of the targets.
- Scope declarations are author-supplied and were not independently audited.
- VAmPI's ground truth mixes unauthenticated directory/debug exposure with
  classic object BOLA; it is not a pure BOLA benchmark.
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

- All required benchmark targets and all three modes ran in v2. There is no
  remaining Docker blocker.
- `crapi-vehicles` could not produce a caller-scoped PASS because the other test
  identity has no vehicle, so its successful response is an empty list.
- `vampi-users-password` remains inconclusive in both vulnerable and secure
  modes because its 204 response has no owner evidence.
- A ZAP active scan and an authenticated ZAP scan were not run. The safe
  baseline is the only ZAP evidence.
- crAPI has no secure/fixed deployment, so there is no crAPI secure-mode
  comparison.

## Reproduce

With Docker and Compose v2 available, one command for both targets:

```bash
python benchmark/run.py --target all --repeats 3
```

Or one command per target (the second merges into the first target's results):

```bash
python benchmark/run.py --target vampi --repeats 3
python benchmark/run.py --target crapi --repeats 3 --merge
```

Each command starts the pinned Compose stack, resets it before every run, runs
setup, executes all three modes three times, checks that every count row sums to
N, writes `benchmark/RESULTS.md` and `benchmark/.out/results.json`, and removes
the Compose projects. Add `--keep` to inspect the stack after the final run.
The pre-change results remain at `benchmark/results_v1.md`.

Run the guard/scorer tests with:

```bash
python -m pytest benchmark/tests -q
```
