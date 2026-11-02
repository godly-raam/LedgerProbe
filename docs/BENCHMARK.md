# LedgerProbe real-world benchmark

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

The recorded run used Docker Engine `28.5.2+dfsg4` and Compose `2.40.3-3`.
VAmPI's only published tag is mutable, so its manifest digest is pinned. crAPI
publishes a `1.1.6` tag only for `crapi-identity`; the other components only have
release-day `latest` images, which are pinned by digest rather than retagged.

The crAPI source snapshot and the pinned images are both `1.1.6`. The snapshot's
`VERSION` file still says `1.1.5`; a file-by-file diff against tag `v1.1.6`
confirmed the content. This is why the provenance commit is `be7e5ef`, not a
label change.

## Ground truth provenance

Ground truth was committed as `6eabf48` **before** any LedgerProbe run against
these targets. Labels come only from the targets' README/docs/OpenAPI/service
source; no LedgerProbe output influenced them. Files:

- `benchmark/ground_truth/vampi.yaml` — 13 cases: **8 vulnerable, 5 safe**.
  Sources include `api_views/books.py:50-58` (book BOLA),
  `api_views/users.py:186-192` (password BOLA), and
  `api_views/users.py:19-26,45-49` (unauthenticated user directory/debug/read-by-name
  exposure). The secure toggle is represented by `api_views/books.py:61-73` and
  `api_views/users.py:193-196`; the README's warning that secure mode does not
  fix every endpoint is reflected by keeping the directory/debug cases
  vulnerable in both modes.
- `benchmark/ground_truth/crapi.yaml` — 10 cases: **5 vulnerable, 5 safe**.
  Sources include `docs/challenges.md:17-33` and
  `VehicleServiceImpl.java:145-164` / `mechanic/views.py:223-244` for the two
  documented BOLA challenges; `shop/views.py:109-165` and
  `merchant/views.py:157-180` for source-derived order/VIN IDOR; the official
  solution's vehicle-id leak (`docs/challengeSolutions.md:22-23`,
  `community/api/models/post.go:114-130`) for the feed exposure. Safe cases cite
  token-scoped queries (`UserServiceImpl.java:199-229`,
  `VehicleServiceImpl.java:115-133`, `shop/views.py:267-294`,
  `ProfileServiceImpl.java:122-133`) and the public product catalogue.

The 1.1.5→1.1.6 reconciliation diffed every cited file. No label changed.
`service_requests/{vin}` did not exist in 1.1.5 and was added without
authentication in 1.1.6; it remains vulnerable ground truth.

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
   - **differential**: owner/other comparison, nonexistent-object and
     unauthenticated controls, canaries/unique-overlap, two confirmations, and
     bounded pagination where applicable.
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

Measured over three fresh-reset runs per target and mode. `benchmark/RESULTS.md`
is the generated per-case report.

| Target | Mode | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VAmPI | legacy_strict | 13 | 8 | 5 | 0 | 0 | 0 | 0 | 61.5% | 100.0% | 100.0% |
| VAmPI | legacy_lenient | 13 | 8 | 4 | 1 | 0 | 0 | 0 | 66.7% | 100.0% | 100.0% |
| VAmPI | differential | 13 | 7 | 0 | 3 | 0 | 1 | 2 | 100.0% | 87.5% | 100.0% |
| crAPI | legacy_strict | 10 | 4 | 4 | 0 | 0 | 1 | 1 | 50.0% | 80.0% | 100.0% |
| crAPI | legacy_lenient | 10 | 5 | 4 | 1 | 0 | 0 | 0 | 55.6% | 100.0% | 100.0% |
| crAPI | differential | 10 | 3 | 0 | 1 | 0 | 2 | 4 | 100.0% | 60.0% | 100.0% |

Differential precision is 100% on both targets. Its inclusive recall is lower
than the baselines because it refuses to turn an ambiguous or blocked case into
a finding. On VAmPI the only miss is the state-changing password BOLA; on crAPI
the misses are an order object whose nonexistent-object control returns 500 and
a vulnerable endpoint absent from the official spec.

## Determinism

All six target/mode rows produced identical verdicts in all three runs. There
were **zero flips**. The per-run comparison is in `benchmark/RESULTS.md`; the
three reset cycles also reproduced the same counts.

| Target | Mode | Runs | Identical | Flips |
| --- | --- | ---: | --- | --- |
| VAmPI | legacy_strict | 3 | yes | none |
| VAmPI | legacy_lenient | 3 | yes | none |
| VAmPI | differential | 3 | yes | none |
| crAPI | legacy_strict | 3 | yes | none |
| crAPI | legacy_lenient | 3 | yes | none |
| crAPI | differential | 3 | yes | none |

## VAmPI findings

No vulnerable case is a decisive `FN`; the one miss is `INC_VULN`.

- **legacy_strict FP (5):** `vampi-home`, `vampi-book-list`, `vampi-me`,
  `vampi-books-object` on `vulnerable=0`, and `vampi-users-password` on
  `vulnerable=0`. All are correct public/self-scoped responses (200/204/404)
  that the exact-403 baseline labels as findings.
- **legacy_lenient FP (4):** the same public/self-scoped rows except
  `vampi-books-object`; its 404 is denied by the lenient policy and becomes TN.
  The self-password update still returns 204 and remains FP.
- **differential INC_VULN:** `vampi-users-password` on `vulnerable=1` is
  `ambiguous_2xx`. VAmPI returns a generic 204 with no owner canary; the engine
  cannot prove the state change targeted the owner. This is a real
  state-changing-BOLA gap.
- **differential INC_SAFE (2):** `vampi-me` and secure `vampi-users-password`.
  Both return a 2xx with no owner-data overlap or denial shape, so the engine
  reports `ambiguous_2xx` instead of inventing a pass.

## crAPI findings

- **legacy_strict:** 4 TP (`vehicle-location`, `mechanic-report`,
  `order-object`, `community-recent`); 4 FP (`dashboard`, `vehicles`,
  `products`, `video-object`); `service-requests-vin` is `INC_VULN`
  (`endpoint_absent`); `orders-all` is `INC_SAFE` (`execution_error`).
  The video endpoint correctly returns 404, but exact-403 treats it as a finding.
- **legacy_lenient:** 5 TP, including `service-requests-vin` (direct 200);
  4 FP (`dashboard`, `vehicles`, `orders-all`, `products`); `video-object` is
  TN (404). The lenient policy reaches the endpoint the engine inventory skips.
- **differential:** 3 TP (`vehicle-location`, `mechanic-report`,
  `community-recent`); 1 TN (`video-object`); 2 `INC_VULN`
  (`order-object`, `service-requests-vin`); 4 `INC_SAFE` (`dashboard`,
  `vehicles`, `orders-all`, `products`). There are no FP or decisive FN.
- **`order-object` (`INC_VULN`, `server_error`):** the engine matched the owner
  canary and saw an unauthenticated 200 with 17 overlapping values, but its
  nonexistent-order control received HTTP 500, so it returned `INCONCLUSIVE`
  with reduced confidence. Direct owner and other-user reads both returned 200
  with owner data. Strict and lenient both mark it TP. The target does not
  handle a missing order cleanly, and the engine's control gate suppresses an
  otherwise supported finding.
- **`service-requests-vin` (`INC_VULN`, `endpoint_absent`):** the official
  OpenAPI snapshot lacks this 1.1.6 path, so the engine's inventory never sends
  the request. The lenient baseline calls it directly and gets 200. This is a
  target-spec gap, not evidence that the endpoint is safe.
- **`orders-all` (`INC_SAFE`, `execution_error`):** the spec marks `limit` and
  `offset` as required query parameters; the benchmark rule supplies neither,
  so the engine refuses to issue the request. A direct call returns the caller's
  own orders with 200. This is an input/rule integration gap; the endpoint is
  safe ground truth.
- **`dashboard`, `vehicles`, `products` (`INC_SAFE`, `ambiguous_2xx`):** the
  other identity receives its own scoped data, not the owner's object. There is
  no owner overlap and no denial, so the engine correctly declines to call it a
  pass. The lenient baseline sees 200 and calls all three FP.
- **`video-object` (`TN` differential):** the other identity gets 404, which is
  a correct denial. Strict calls 404 a failure and therefore records FP.

## ZAP relevance

OWASP ZAP `ghcr.io/zaproxy/zaproxy@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238`
was available and a **safe API baseline** (`-S`) was run against the same
OpenAPI snapshot, with the host overridden to the isolated Compose network. It
completed with **0 FAIL, 8 WARN-NEW and 114 PASS** over 44 imported endpoints.
The warnings were missing security headers, server-version disclosure, server
errors and content-type issues. There was **no BOLA/IDOR alert** that maps to a
ground-truth case.

ZAP was unauthenticated and has no two-identity owner/other comparison. It
touched `/workshop/api/shop/orders/1` only for a missing-header warning; its
vehicle-location, dashboard, community-feed and video requests received client
errors. It could not test the service-requests path, which is absent from the
spec. ZAP therefore neither confirms nor refutes the differential results and
does not affect any score.

## Before and after

No engine or rule logic was changed in these benchmark commits. The engine
baseline is commit `15ae40a`; the benchmark adds targets, ground truth, scoring,
baselines and reports only. The VAmPI differential result remains 7 TP / 0 FP /
3 TN / 1 INC_VULN / 2 INC_SAFE under the corrected accounting. The old
single-`INCONCLUSIVE` bucket was 3; it is now split into one vulnerable miss and
two safe inconclusive rows. The legacy strict result is unchanged at 8 TP / 5
FP. crAPI was not measured before this run, so no before/after claim is made.

If a later commit fixes the state-changing-BOLA or control-error gap, it must
not touch `benchmark/ground_truth/`; update this section with the new numbers
and keep the old row visible.

## What could not run

- All required benchmark targets and all three modes ran. There is no remaining
  Docker blocker.
- The engine could not execute `service-requests-vin` or `orders-all` in either
  engine mode for the spec/parameter reasons above. The lenient harness reached
  both directly, so their target behavior is known but their engine-mode result
  is not.
- A ZAP active scan and an authenticated ZAP scan were not run. The safe
  baseline is the only ZAP evidence; it is not a BOLA oracle.
- crAPI has no secure/fixed deployment, so there is no crAPI before/after secure
  comparison.

## Limitations

- The sample is 23 endpoint cases (13 VAmPI, 10 crAPI), not a population. There
  are no confidence intervals or inter-rater checks; three repeats establish
  determinism, not statistical significance.
- The engine and rules were written by the same project that wrote the
  benchmark. Ground truth was frozen first, but endpoint selection and canary
  choice still reflect knowledge of the targets.
- VAmPI's ground truth mixes unauthenticated directory/debug exposure
  (IDOR/excessive data exposure) with classic object BOLA. It is not a pure BOLA
  benchmark.
- crAPI is a single deployment. Its safe cases are token-scoped controls, not a
  patched/secure version.
- The exact-403 baseline is intentionally strict; 404 and 204 are treated as
  failures even when they are correct denials or self-scoped updates.
- `legacy_lenient` is a harness policy, not an engine feature. Its 401/403/404
  pass set can also hide an existence leak; it is reported as a baseline only.
- The official crAPI spec omits `service_requests/{vin}` and requires
  `limit`/`offset` on `orders/all`; those input defects limit engine coverage.
- Differential detection needs owner-specific evidence. Generic 2xx responses
  and state-changing endpoints without a canary remain inconclusive.
- ZAP's baseline is unauthenticated and generic; it cannot substitute for
  two-user authorization testing.
- No secrets, tokens or databases are committed. Runtime artifacts live under
  `benchmark/.out/` and are gitignored.

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
The harness exits 2 if a target cannot run; an engine execution error is still
recorded as `INCONCLUSIVE`, not hidden.

Run the guard/scorer tests with:

```bash
python -m pytest benchmark/tests -q
```

The recorded ZAP baseline artifacts are under `benchmark/.out/zap/`
(`zap-report.json`, `.md`, `.html`). They are not committed.
