# LedgerProbe real-world benchmark results

Generated: 2026-11-02T08:42:12+00:00

Targets were run locally on loopback only. Labels come from `benchmark/ground_truth/`, frozen before any scan. Each mode was run three times with a fresh target reset between runs.

## Scores

| Target | Mode | Status | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vampi | legacy_strict | ok | 13 | 8 | 5 | 0 | 0 | 0 | 0 | 61.5% | 100.0% | 100.0% |
| vampi | legacy_lenient | ok | 13 | 8 | 4 | 1 | 0 | 0 | 0 | 66.7% | 100.0% | 100.0% |
| vampi | differential | ok | 13 | 7 | 0 | 3 | 0 | 1 | 2 | 100.0% | 87.5% | 100.0% |
| crapi | legacy_strict | ok | 10 | 4 | 4 | 0 | 0 | 1 | 1 | 50.0% | 80.0% | 100.0% |
| crapi | legacy_lenient | ok | 10 | 5 | 4 | 1 | 0 | 0 | 0 | 55.6% | 100.0% | 100.0% |
| crapi | differential | ok | 10 | 3 | 0 | 1 | 0 | 2 | 4 | 100.0% | 60.0% | 100.0% |

`Recall` counts `INC_vuln` as a miss: `TP / (TP + FN + INC_vuln)`. `Recall excl. INC` is `TP / (TP + FN)`. Every row's six outcome counts must sum to N; a runtime assertion enforces this. `INCONCLUSIVE` is never counted as correct.

## Determinism

| Target | Mode | Runs | Identical verdicts | Flips |
| --- | --- | ---: | --- | --- |
| vampi | legacy_strict | 3 | yes | none |
| vampi | legacy_lenient | 3 | yes | none |
| vampi | differential | 3 | yes | none |
| crapi | legacy_strict | 3 | yes | none |
| crapi | legacy_lenient | 3 | yes | none |
| crapi | differential | 3 | yes | none |

## Detail

### vampi

#### legacy_strict

| Case | Label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- |
| `vampi-books-object` GET `/books/v1/{book_title}` | vulnerable | FAIL | assertion_failed | TP | api_views/books.py:50-58 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:186-192 |
| `vampi-users-object` GET `/users/v1/{username}` | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:45-49; models/user_model.py:55-56,70-81 |
| `vampi-users-list` GET `/users/v1` | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:19-21; models/user_model.py:62-63 |
| `vampi-users-debug` GET `/users/v1/_debug` | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:24-26; models/user_model.py:58-59,65-67 |
| `vampi-home` GET `/` | safe | FAIL | assertion_failed | FP | api_views/main.py:14-18 |
| `vampi-book-list` GET `/books/v1` | safe | FAIL | assertion_failed | FP | api_views/books.py:12-14; models/books_model.py:23-24 |
| `vampi-me` GET `/me` | safe | FAIL | assertion_failed | FP | api_views/users.py:28-42 |
| `vampi-books-object` GET `/books/v1/{book_title}` | safe | FAIL | assertion_failed | FP | api_views/books.py:61-73 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | safe | FAIL | assertion_failed | FP | api_views/users.py:193-196 |
| `vampi-users-object` GET `/users/v1/{username}` | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:45-49 |
| `vampi-users-list` GET `/users/v1` | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:19-21 |
| `vampi-users-debug` GET `/users/v1/_debug` | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:24-26; app.py:4-7 |

#### legacy_lenient

| Case | Label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- |
| `vampi-books-object` GET `/books/v1/{book_title}` | vulnerable | FAIL | status_200 | TP | api_views/books.py:50-58 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | vulnerable | FAIL | status_204 | TP | api_views/users.py:186-192 |
| `vampi-users-object` GET `/users/v1/{username}` | vulnerable | FAIL | status_200 | TP | api_views/users.py:45-49; models/user_model.py:55-56,70-81 |
| `vampi-users-list` GET `/users/v1` | vulnerable | FAIL | status_200 | TP | api_views/users.py:19-21; models/user_model.py:62-63 |
| `vampi-users-debug` GET `/users/v1/_debug` | vulnerable | FAIL | status_200 | TP | api_views/users.py:24-26; models/user_model.py:58-59,65-67 |
| `vampi-home` GET `/` | safe | FAIL | status_200 | FP | api_views/main.py:14-18 |
| `vampi-book-list` GET `/books/v1` | safe | FAIL | status_200 | FP | api_views/books.py:12-14; models/books_model.py:23-24 |
| `vampi-me` GET `/me` | safe | FAIL | status_200 | FP | api_views/users.py:28-42 |
| `vampi-books-object` GET `/books/v1/{book_title}` | safe | PASS | status_404 | TN | api_views/books.py:61-73 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | safe | FAIL | status_204 | FP | api_views/users.py:193-196 |
| `vampi-users-object` GET `/users/v1/{username}` | vulnerable | FAIL | status_200 | TP | api_views/users.py:45-49 |
| `vampi-users-list` GET `/users/v1` | vulnerable | FAIL | status_200 | TP | api_views/users.py:19-21 |
| `vampi-users-debug` GET `/users/v1/_debug` | vulnerable | FAIL | status_200 | TP | api_views/users.py:24-26; app.py:4-7 |

#### differential

| Case | Label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- |
| `vampi-books-object` GET `/books/v1/{book_title}` | vulnerable | FAIL | leak_detected | TP | api_views/books.py:50-58 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | vulnerable | INCONCLUSIVE | ambiguous_2xx | INC_VULN | api_views/users.py:186-192 |
| `vampi-users-object` GET `/users/v1/{username}` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:45-49; models/user_model.py:55-56,70-81 |
| `vampi-users-list` GET `/users/v1` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:19-21; models/user_model.py:62-63 |
| `vampi-users-debug` GET `/users/v1/_debug` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:24-26; models/user_model.py:58-59,65-67 |
| `vampi-home` GET `/` | safe | PASS | — | TN | api_views/main.py:14-18 |
| `vampi-book-list` GET `/books/v1` | safe | PASS | — | TN | api_views/books.py:12-14; models/books_model.py:23-24 |
| `vampi-me` GET `/me` | safe | INCONCLUSIVE | ambiguous_2xx | INC_SAFE | api_views/users.py:28-42 |
| `vampi-books-object` GET `/books/v1/{book_title}` | safe | PASS | — | TN | api_views/books.py:61-73 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | safe | INCONCLUSIVE | ambiguous_2xx | INC_SAFE | api_views/users.py:193-196 |
| `vampi-users-object` GET `/users/v1/{username}` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:45-49 |
| `vampi-users-list` GET `/users/v1` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:19-21 |
| `vampi-users-debug` GET `/users/v1/_debug` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:24-26; app.py:4-7 |

#### FP, FN and INCONCLUSIVE diagnoses

- **FP** (legacy_strict) `vampi-home` GET `/` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: api_views/main.py:14-18.
- **FP** (legacy_strict) `vampi-book-list` GET `/books/v1` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: api_views/books.py:12-14; models/books_model.py:23-24.
- **FP** (legacy_strict) `vampi-me` GET `/me` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: api_views/users.py:28-42.
- **FP** (legacy_strict) `vampi-books-object` GET `/books/v1/{book_title}` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: api_views/books.py:61-73.
- **FP** (legacy_strict) `vampi-users-password` PUT `/users/v1/{username}/password` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: api_views/users.py:193-196.
- **FP** (legacy_lenient) `vampi-home` GET `/` — FAIL, reason `status_200`. Safe endpoint returned FAIL (`status_200`); the status baseline treats this non-leaking response as a finding. Source: api_views/main.py:14-18.
- **FP** (legacy_lenient) `vampi-book-list` GET `/books/v1` — FAIL, reason `status_200`. Safe endpoint returned FAIL (`status_200`); the status baseline treats this non-leaking response as a finding. Source: api_views/books.py:12-14; models/books_model.py:23-24.
- **FP** (legacy_lenient) `vampi-me` GET `/me` — FAIL, reason `status_200`. Safe endpoint returned FAIL (`status_200`); the status baseline treats this non-leaking response as a finding. Source: api_views/users.py:28-42.
- **FP** (legacy_lenient) `vampi-users-password` PUT `/users/v1/{username}/password` — FAIL, reason `status_204`. Safe endpoint returned FAIL (`status_204`); the status baseline treats this non-leaking response as a finding. Source: api_views/users.py:193-196.
- **INC_VULN** (differential) `vampi-users-password` PUT `/users/v1/{username}/password` — INCONCLUSIVE, reason `ambiguous_2xx`. Vulnerable endpoint was INCONCLUSIVE (`ambiguous_2xx`); counted as a miss, not a true negative. Source: api_views/users.py:186-192.
- **INC_SAFE** (differential) `vampi-me` GET `/me` — INCONCLUSIVE, reason `ambiguous_2xx`. Safe endpoint was INCONCLUSIVE (`ambiguous_2xx`); not counted as a true negative. Source: api_views/users.py:28-42.
- **INC_SAFE** (differential) `vampi-users-password` PUT `/users/v1/{username}/password` — INCONCLUSIVE, reason `ambiguous_2xx`. Safe endpoint was INCONCLUSIVE (`ambiguous_2xx`); not counted as a true negative. Source: api_views/users.py:193-196.

### crapi

#### legacy_strict

| Case | Label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- |
| `crapi-vehicle-location` GET `/identity/api/v2/vehicle/{vehicleId}/location` | vulnerable | FAIL | assertion_failed | TP | docs/challenges.md:17-23; services/identity/src/main/java/com/crapi/controller/VehicleController.java:108-114; services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:145-164 |
| `crapi-mechanic-report` GET `/workshop/api/mechanic/mechanic_report` | vulnerable | FAIL | assertion_failed | TP | docs/challenges.md:25-33; services/workshop/crapi/mechanic/views.py:223-244 |
| `crapi-order-object` GET `/workshop/api/shop/orders/{order_id}` | vulnerable | FAIL | assertion_failed | TP | services/workshop/crapi/shop/views.py:109-165 |
| `crapi-community-recent` GET `/community/api/v2/community/posts/recent` | vulnerable | FAIL | assertion_failed | TP | docs/challenges.md:45-49; docs/challengeSolutions.md:22-23; services/community/api/models/post.go:36,79-80,114-130 |
| `crapi-service-requests-vin` GET `/workshop/api/merchant/service_requests/{vin}` | vulnerable | SKIPPED | endpoint_absent | INC_VULN | services/workshop/crapi/merchant/views.py:157-180 |
| `crapi-dashboard` GET `/identity/api/v2/user/dashboard` | safe | FAIL | assertion_failed | FP | services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229 |
| `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` | safe | FAIL | assertion_failed | FP | services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133 |
| `crapi-orders-all` GET `/workshop/api/shop/orders/all` | safe | ERROR | execution_error | INC_SAFE | services/workshop/crapi/shop/views.py:267-294 |
| `crapi-products` GET `/workshop/api/shop/products` | safe | FAIL | assertion_failed | FP | services/workshop/crapi/shop/views.py:52-80 |
| `crapi-video-object` GET `/identity/api/v2/user/videos/{video_id}` | safe | FAIL | assertion_failed | FP | services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java:122-133 |

#### legacy_lenient

| Case | Label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- |
| `crapi-vehicle-location` GET `/identity/api/v2/vehicle/{vehicleId}/location` | vulnerable | FAIL | status_200 | TP | docs/challenges.md:17-23; services/identity/src/main/java/com/crapi/controller/VehicleController.java:108-114; services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:145-164 |
| `crapi-mechanic-report` GET `/workshop/api/mechanic/mechanic_report` | vulnerable | FAIL | status_200 | TP | docs/challenges.md:25-33; services/workshop/crapi/mechanic/views.py:223-244 |
| `crapi-order-object` GET `/workshop/api/shop/orders/{order_id}` | vulnerable | FAIL | status_200 | TP | services/workshop/crapi/shop/views.py:109-165 |
| `crapi-community-recent` GET `/community/api/v2/community/posts/recent` | vulnerable | FAIL | status_200 | TP | docs/challenges.md:45-49; docs/challengeSolutions.md:22-23; services/community/api/models/post.go:36,79-80,114-130 |
| `crapi-service-requests-vin` GET `/workshop/api/merchant/service_requests/{vin}` | vulnerable | FAIL | status_200 | TP | services/workshop/crapi/merchant/views.py:157-180 |
| `crapi-dashboard` GET `/identity/api/v2/user/dashboard` | safe | FAIL | status_200 | FP | services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229 |
| `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` | safe | FAIL | status_200 | FP | services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133 |
| `crapi-orders-all` GET `/workshop/api/shop/orders/all` | safe | FAIL | status_200 | FP | services/workshop/crapi/shop/views.py:267-294 |
| `crapi-products` GET `/workshop/api/shop/products` | safe | FAIL | status_200 | FP | services/workshop/crapi/shop/views.py:52-80 |
| `crapi-video-object` GET `/identity/api/v2/user/videos/{video_id}` | safe | PASS | status_404 | TN | services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java:122-133 |

#### differential

| Case | Label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- |
| `crapi-vehicle-location` GET `/identity/api/v2/vehicle/{vehicleId}/location` | vulnerable | FAIL | leak_detected | TP | docs/challenges.md:17-23; services/identity/src/main/java/com/crapi/controller/VehicleController.java:108-114; services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:145-164 |
| `crapi-mechanic-report` GET `/workshop/api/mechanic/mechanic_report` | vulnerable | FAIL | leak_detected | TP | docs/challenges.md:25-33; services/workshop/crapi/mechanic/views.py:223-244 |
| `crapi-order-object` GET `/workshop/api/shop/orders/{order_id}` | vulnerable | INCONCLUSIVE | server_error | INC_VULN | services/workshop/crapi/shop/views.py:109-165 |
| `crapi-community-recent` GET `/community/api/v2/community/posts/recent` | vulnerable | FAIL | leak_detected | TP | docs/challenges.md:45-49; docs/challengeSolutions.md:22-23; services/community/api/models/post.go:36,79-80,114-130 |
| `crapi-service-requests-vin` GET `/workshop/api/merchant/service_requests/{vin}` | vulnerable | SKIPPED | endpoint_absent | INC_VULN | services/workshop/crapi/merchant/views.py:157-180 |
| `crapi-dashboard` GET `/identity/api/v2/user/dashboard` | safe | INCONCLUSIVE | ambiguous_2xx | INC_SAFE | services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229 |
| `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` | safe | INCONCLUSIVE | ambiguous_2xx | INC_SAFE | services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133 |
| `crapi-orders-all` GET `/workshop/api/shop/orders/all` | safe | ERROR | execution_error | INC_SAFE | services/workshop/crapi/shop/views.py:267-294 |
| `crapi-products` GET `/workshop/api/shop/products` | safe | INCONCLUSIVE | ambiguous_2xx | INC_SAFE | services/workshop/crapi/shop/views.py:52-80 |
| `crapi-video-object` GET `/identity/api/v2/user/videos/{video_id}` | safe | PASS | — | TN | services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java:122-133 |

#### FP, FN and INCONCLUSIVE diagnoses

- **INC_VULN** (legacy_strict) `crapi-service-requests-vin` GET `/workshop/api/merchant/service_requests/{vin}` — SKIPPED, reason `endpoint_absent`. Vulnerable endpoint was SKIPPED (`endpoint_absent`); counted as a miss, not a true negative. Source: services/workshop/crapi/merchant/views.py:157-180.
- **FP** (legacy_strict) `crapi-dashboard` GET `/identity/api/v2/user/dashboard` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229.
- **FP** (legacy_strict) `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133.
- **INC_SAFE** (legacy_strict) `crapi-orders-all` GET `/workshop/api/shop/orders/all` — ERROR, reason `execution_error`. Safe endpoint was ERROR (`execution_error`); not counted as a true negative. Source: services/workshop/crapi/shop/views.py:267-294.
- **FP** (legacy_strict) `crapi-products` GET `/workshop/api/shop/products` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: services/workshop/crapi/shop/views.py:52-80.
- **FP** (legacy_strict) `crapi-video-object` GET `/identity/api/v2/user/videos/{video_id}` — FAIL, reason `assertion_failed`. Safe endpoint returned FAIL (`assertion_failed`); the strict baseline treats this non-leaking response as a finding. Source: services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java:122-133.
- **FP** (legacy_lenient) `crapi-dashboard` GET `/identity/api/v2/user/dashboard` — FAIL, reason `status_200`. Safe endpoint returned FAIL (`status_200`); the status baseline treats this non-leaking response as a finding. Source: services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229.
- **FP** (legacy_lenient) `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` — FAIL, reason `status_200`. Safe endpoint returned FAIL (`status_200`); the status baseline treats this non-leaking response as a finding. Source: services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133.
- **FP** (legacy_lenient) `crapi-orders-all` GET `/workshop/api/shop/orders/all` — FAIL, reason `status_200`. Safe endpoint returned FAIL (`status_200`); the status baseline treats this non-leaking response as a finding. Source: services/workshop/crapi/shop/views.py:267-294.
- **FP** (legacy_lenient) `crapi-products` GET `/workshop/api/shop/products` — FAIL, reason `status_200`. Safe endpoint returned FAIL (`status_200`); the status baseline treats this non-leaking response as a finding. Source: services/workshop/crapi/shop/views.py:52-80.
- **INC_VULN** (differential) `crapi-order-object` GET `/workshop/api/shop/orders/{order_id}` — INCONCLUSIVE, reason `server_error`. Vulnerable endpoint was INCONCLUSIVE (`server_error`); counted as a miss, not a true negative. Source: services/workshop/crapi/shop/views.py:109-165.
- **INC_VULN** (differential) `crapi-service-requests-vin` GET `/workshop/api/merchant/service_requests/{vin}` — SKIPPED, reason `endpoint_absent`. Vulnerable endpoint was SKIPPED (`endpoint_absent`); counted as a miss, not a true negative. Source: services/workshop/crapi/merchant/views.py:157-180.
- **INC_SAFE** (differential) `crapi-dashboard` GET `/identity/api/v2/user/dashboard` — INCONCLUSIVE, reason `ambiguous_2xx`. Safe endpoint was INCONCLUSIVE (`ambiguous_2xx`); not counted as a true negative. Source: services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229.
- **INC_SAFE** (differential) `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` — INCONCLUSIVE, reason `ambiguous_2xx`. Safe endpoint was INCONCLUSIVE (`ambiguous_2xx`); not counted as a true negative. Source: services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133.
- **INC_SAFE** (differential) `crapi-orders-all` GET `/workshop/api/shop/orders/all` — ERROR, reason `execution_error`. Safe endpoint was ERROR (`execution_error`); not counted as a true negative. Source: services/workshop/crapi/shop/views.py:267-294.
- **INC_SAFE** (differential) `crapi-products` GET `/workshop/api/shop/products` — INCONCLUSIVE, reason `ambiguous_2xx`. Safe endpoint was INCONCLUSIVE (`ambiguous_2xx`); not counted as a true negative. Source: services/workshop/crapi/shop/views.py:52-80.


## ZAP relevance

A safe OWASP ZAP API baseline (`-S`) ran against the same crAPI OpenAPI
snapshot, overridden to `http://crapi-web` on the isolated Compose network.
ZAP reported **0 FAIL, 8 WARN-NEW and 114 PASS** across 44 imported endpoints.
Its warnings were missing security headers, server-version disclosure, server
errors and content-type issues. No ZAP alert maps to a BOLA/IDOR ground-truth
case. ZAP was unauthenticated and has no owner/other comparison, so it neither
confirms nor refutes the differential results and does not affect any score.

Image:
`ghcr.io/zaproxy/zaproxy@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238`.
The full report is in `benchmark/.out/zap/` (gitignored).

## Limitations

- 23 endpoint cases total; no confidence intervals or population claim.
- Three repeats establish determinism, not statistical significance.
- crAPI is one deployment, not a secure/fixed comparison.
- The exact-403 baseline treats correct 404/204 responses as failures.
- `legacy_lenient` is a harness policy (`{401,403,404}` PASS), not an engine mode.
- The official crAPI spec omits `service_requests/{vin}` and requires
  `limit`/`offset` for `orders/all`; those input gaps block two engine cases.
- Differential detection needs owner-specific evidence; generic 2xx and
  state-changing endpoints without a canary stay inconclusive.
- ZAP's unauthenticated baseline is not an authorization oracle.
- No secrets, tokens or databases are committed; runtime artifacts are
  gitignored.

## Reproduction

```bash
python benchmark/run.py --target all --repeats 3
```

Or one command per target:

```bash
python benchmark/run.py --target vampi --repeats 3
python benchmark/run.py --target crapi --repeats 3 --merge
```

Each run resets the Compose project and volumes before every mode run, re-runs
setup, scores JUnit against the frozen labels, asserts every outcome row sums to
N, writes this file and `benchmark/.out/results.json`, then removes the stack.
Use `--keep` to inspect the final stack. An engine execution error is recorded
as `INCONCLUSIVE`, never as a pass.

Run the guard/scorer tests with:

```bash
python -m pytest benchmark/tests -q
```
