# LedgerProbe real-world benchmark results

Generated: 2026-11-02T19:36:45+00:00

Targets were run locally on loopback only. Labels come from `benchmark/ground_truth/`, frozen before any scan. Each mode was run three times with a fresh target reset between runs.

## Scores

| Target | Mode | Status | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vampi | legacy_strict | ok | 13 | 8 | 5 | 0 | 0 | 0 | 0 | 61.5% | 100.0% | 100.0% |
| vampi | legacy_lenient | ok | 13 | 8 | 4 | 1 | 0 | 0 | 0 | 66.7% | 100.0% | 100.0% |
| vampi | differential | ok | 13 | 8 | 0 | 5 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| crapi | legacy_strict | ok | 10 | 4 | 4 | 0 | 0 | 1 | 1 | 50.0% | 80.0% | 100.0% |
| crapi | legacy_lenient | ok | 10 | 5 | 4 | 1 | 0 | 0 | 0 | 55.6% | 100.0% | 100.0% |
| crapi | differential | ok | 10 | 5 | 0 | 4 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |

`Recall` counts `INC_vuln` as a miss: `TP / (TP + FN + INC_vuln)`. `Recall excl. INC` is `TP / (TP + FN)`. Every row's six outcome counts must sum to N; a runtime assertion enforces this. `INCONCLUSIVE` is never counted as correct.

## Object-scoped-only cut

This cut keeps only cases whose rule declares `scope: object` (the default). Scope is author-declared in the rule, never derived from a ground-truth label.

| Target | Mode | Status | N | TP | FP | TN | FN | INC_vuln | INC_safe | Precision | Recall | Recall excl. INC |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vampi (object) | legacy_strict | ok | 6 | 4 | 2 | 0 | 0 | 0 | 0 | 66.7% | 100.0% | 100.0% |
| vampi (object) | legacy_lenient | ok | 6 | 4 | 1 | 1 | 0 | 0 | 0 | 80.0% | 100.0% | 100.0% |
| vampi (object) | differential | ok | 6 | 4 | 0 | 2 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| crapi (object) | legacy_strict | ok | 5 | 3 | 1 | 0 | 0 | 1 | 0 | 75.0% | 75.0% | 100.0% |
| crapi (object) | legacy_lenient | ok | 5 | 4 | 0 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| crapi (object) | differential | ok | 5 | 4 | 0 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |

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

| Case | Scope | Target mode | Ground-truth label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `vampi-books-object` GET `/books/v1/{book_title}` | object | vulnerable=1 | vulnerable | FAIL | assertion_failed | TP | api_views/books.py:50-58 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | object | vulnerable=1 | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:186-192 |
| `vampi-users-object` GET `/users/v1/{username}` | object | vulnerable=1 | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:45-49; models/user_model.py:55-56,70-81 |
| `vampi-users-list` GET `/users/v1` | shared | vulnerable=1 | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:19-21; models/user_model.py:62-63 |
| `vampi-users-debug` GET `/users/v1/_debug` | shared | vulnerable=1 | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:24-26; models/user_model.py:58-59,65-67 |
| `vampi-home` GET `/` | shared | vulnerable=1 | safe | FAIL | assertion_failed | FP | api_views/main.py:14-18 |
| `vampi-book-list` GET `/books/v1` | shared | vulnerable=1 | safe | FAIL | assertion_failed | FP | api_views/books.py:12-14; models/books_model.py:23-24 |
| `vampi-me` GET `/me` | caller | vulnerable=1 | safe | FAIL | assertion_failed | FP | api_views/users.py:28-42 |
| `vampi-books-object` GET `/books/v1/{book_title}` | object | vulnerable=0 | safe | FAIL | assertion_failed | FP | api_views/books.py:61-73 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | object | vulnerable=0 | safe | FAIL | assertion_failed | FP | api_views/users.py:193-196 |
| `vampi-users-object` GET `/users/v1/{username}` | object | vulnerable=0 | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:45-49 |
| `vampi-users-list` GET `/users/v1` | shared | vulnerable=0 | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:19-21 |
| `vampi-users-debug` GET `/users/v1/_debug` | shared | vulnerable=0 | vulnerable | FAIL | assertion_failed | TP | api_views/users.py:24-26; app.py:4-7 |

#### legacy_lenient

| Case | Scope | Target mode | Ground-truth label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `vampi-books-object` GET `/books/v1/{book_title}` | object | vulnerable=1 | vulnerable | FAIL | status_200 | TP | api_views/books.py:50-58 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | object | vulnerable=1 | vulnerable | FAIL | status_204 | TP | api_views/users.py:186-192 |
| `vampi-users-object` GET `/users/v1/{username}` | object | vulnerable=1 | vulnerable | FAIL | status_200 | TP | api_views/users.py:45-49; models/user_model.py:55-56,70-81 |
| `vampi-users-list` GET `/users/v1` | shared | vulnerable=1 | vulnerable | FAIL | status_200 | TP | api_views/users.py:19-21; models/user_model.py:62-63 |
| `vampi-users-debug` GET `/users/v1/_debug` | shared | vulnerable=1 | vulnerable | FAIL | status_200 | TP | api_views/users.py:24-26; models/user_model.py:58-59,65-67 |
| `vampi-home` GET `/` | shared | vulnerable=1 | safe | FAIL | status_200 | FP | api_views/main.py:14-18 |
| `vampi-book-list` GET `/books/v1` | shared | vulnerable=1 | safe | FAIL | status_200 | FP | api_views/books.py:12-14; models/books_model.py:23-24 |
| `vampi-me` GET `/me` | caller | vulnerable=1 | safe | FAIL | status_200 | FP | api_views/users.py:28-42 |
| `vampi-books-object` GET `/books/v1/{book_title}` | object | vulnerable=0 | safe | PASS | status_404 | TN | api_views/books.py:61-73 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | object | vulnerable=0 | safe | FAIL | status_204 | FP | api_views/users.py:193-196 |
| `vampi-users-object` GET `/users/v1/{username}` | object | vulnerable=0 | vulnerable | FAIL | status_200 | TP | api_views/users.py:45-49 |
| `vampi-users-list` GET `/users/v1` | shared | vulnerable=0 | vulnerable | FAIL | status_200 | TP | api_views/users.py:19-21 |
| `vampi-users-debug` GET `/users/v1/_debug` | shared | vulnerable=0 | vulnerable | FAIL | status_200 | TP | api_views/users.py:24-26; app.py:4-7 |

#### differential

| Case | Scope | Target mode | Ground-truth label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `vampi-books-object` GET `/books/v1/{book_title}` | object | vulnerable=1 | vulnerable | FAIL | leak_detected | TP | api_views/books.py:50-58 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | object | vulnerable=1 | vulnerable | FAIL | state_changed_by_other | TP | api_views/users.py:186-192 |
| `vampi-users-object` GET `/users/v1/{username}` | object | vulnerable=1 | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:45-49; models/user_model.py:55-56,70-81 |
| `vampi-users-list` GET `/users/v1` | shared | vulnerable=1 | vulnerable | FAIL | leak_detected | TP | api_views/users.py:19-21; models/user_model.py:62-63 |
| `vampi-users-debug` GET `/users/v1/_debug` | shared | vulnerable=1 | vulnerable | FAIL | leak_detected | TP | api_views/users.py:24-26; models/user_model.py:58-59,65-67 |
| `vampi-home` GET `/` | shared | vulnerable=1 | safe | PASS | — | TN | api_views/main.py:14-18 |
| `vampi-book-list` GET `/books/v1` | shared | vulnerable=1 | safe | PASS | — | TN | api_views/books.py:12-14; models/books_model.py:23-24 |
| `vampi-me` GET `/me` | caller | vulnerable=1 | safe | PASS | — | TN | api_views/users.py:28-42 |
| `vampi-books-object` GET `/books/v1/{book_title}` | object | vulnerable=0 | safe | PASS | — | TN | api_views/books.py:61-73 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | object | vulnerable=0 | safe | PASS | — | TN | api_views/users.py:193-196 |
| `vampi-users-object` GET `/users/v1/{username}` | object | vulnerable=0 | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:45-49 |
| `vampi-users-list` GET `/users/v1` | shared | vulnerable=0 | vulnerable | FAIL | leak_detected | TP | api_views/users.py:19-21 |
| `vampi-users-debug` GET `/users/v1/_debug` | shared | vulnerable=0 | vulnerable | FAIL | leak_detected | TP | api_views/users.py:24-26; app.py:4-7 |

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

### crapi

#### legacy_strict

| Case | Scope | Target mode | Ground-truth label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `crapi-vehicle-location` GET `/identity/api/v2/vehicle/{vehicleId}/location` | object | single | vulnerable | FAIL | assertion_failed | TP | docs/challenges.md:17-23; services/identity/src/main/java/com/crapi/controller/VehicleController.java:108-114; services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:145-164 |
| `crapi-mechanic-report` GET `/workshop/api/mechanic/mechanic_report` | object | single | vulnerable | FAIL | assertion_failed | TP | docs/challenges.md:25-33; services/workshop/crapi/mechanic/views.py:223-244 |
| `crapi-order-object` GET `/workshop/api/shop/orders/{order_id}` | object | single | vulnerable | FAIL | assertion_failed | TP | services/workshop/crapi/shop/views.py:109-165 |
| `crapi-community-recent` GET `/community/api/v2/community/posts/recent` | shared | single | vulnerable | FAIL | assertion_failed | TP | docs/challenges.md:45-49; docs/challengeSolutions.md:22-23; services/community/api/models/post.go:36,79-80,114-130 |
| `crapi-service-requests-vin` GET `/workshop/api/merchant/service_requests/{vin}` | object | single | vulnerable | SKIPPED | endpoint_absent | INC_VULN | services/workshop/crapi/merchant/views.py:157-180 |
| `crapi-dashboard` GET `/identity/api/v2/user/dashboard` | caller | single | safe | FAIL | assertion_failed | FP | services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229 |
| `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` | caller | single | safe | FAIL | assertion_failed | FP | services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133 |
| `crapi-orders-all` GET `/workshop/api/shop/orders/all` | caller | single | safe | ERROR | execution_error | INC_SAFE | services/workshop/crapi/shop/views.py:267-294 |
| `crapi-products` GET `/workshop/api/shop/products` | shared | single | safe | FAIL | assertion_failed | FP | services/workshop/crapi/shop/views.py:52-80 |
| `crapi-video-object` GET `/identity/api/v2/user/videos/{video_id}` | object | single | safe | FAIL | assertion_failed | FP | services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java:122-133 |

#### legacy_lenient

| Case | Scope | Target mode | Ground-truth label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `crapi-vehicle-location` GET `/identity/api/v2/vehicle/{vehicleId}/location` | object | single | vulnerable | FAIL | status_200 | TP | docs/challenges.md:17-23; services/identity/src/main/java/com/crapi/controller/VehicleController.java:108-114; services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:145-164 |
| `crapi-mechanic-report` GET `/workshop/api/mechanic/mechanic_report` | object | single | vulnerable | FAIL | status_200 | TP | docs/challenges.md:25-33; services/workshop/crapi/mechanic/views.py:223-244 |
| `crapi-order-object` GET `/workshop/api/shop/orders/{order_id}` | object | single | vulnerable | FAIL | status_200 | TP | services/workshop/crapi/shop/views.py:109-165 |
| `crapi-community-recent` GET `/community/api/v2/community/posts/recent` | shared | single | vulnerable | FAIL | status_200 | TP | docs/challenges.md:45-49; docs/challengeSolutions.md:22-23; services/community/api/models/post.go:36,79-80,114-130 |
| `crapi-service-requests-vin` GET `/workshop/api/merchant/service_requests/{vin}` | object | single | vulnerable | FAIL | status_200 | TP | services/workshop/crapi/merchant/views.py:157-180 |
| `crapi-dashboard` GET `/identity/api/v2/user/dashboard` | caller | single | safe | FAIL | status_200 | FP | services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229 |
| `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` | caller | single | safe | FAIL | status_200 | FP | services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133 |
| `crapi-orders-all` GET `/workshop/api/shop/orders/all` | caller | single | safe | FAIL | status_200 | FP | services/workshop/crapi/shop/views.py:267-294 |
| `crapi-products` GET `/workshop/api/shop/products` | shared | single | safe | FAIL | status_200 | FP | services/workshop/crapi/shop/views.py:52-80 |
| `crapi-video-object` GET `/identity/api/v2/user/videos/{video_id}` | object | single | safe | PASS | status_404 | TN | services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java:122-133 |

#### differential

| Case | Scope | Target mode | Ground-truth label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `crapi-vehicle-location` GET `/identity/api/v2/vehicle/{vehicleId}/location` | object | single | vulnerable | FAIL | leak_detected | TP | docs/challenges.md:17-23; services/identity/src/main/java/com/crapi/controller/VehicleController.java:108-114; services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:145-164 |
| `crapi-mechanic-report` GET `/workshop/api/mechanic/mechanic_report` | object | single | vulnerable | FAIL | leak_detected | TP | docs/challenges.md:25-33; services/workshop/crapi/mechanic/views.py:223-244 |
| `crapi-order-object` GET `/workshop/api/shop/orders/{order_id}` | object | single | vulnerable | FAIL | leak_detected | TP | services/workshop/crapi/shop/views.py:109-165 |
| `crapi-community-recent` GET `/community/api/v2/community/posts/recent` | shared | single | vulnerable | FAIL | leak_detected | TP | docs/challenges.md:45-49; docs/challengeSolutions.md:22-23; services/community/api/models/post.go:36,79-80,114-130 |
| `crapi-service-requests-vin` GET `/workshop/api/merchant/service_requests/{vin}` | object | single | vulnerable | FAIL | unauthenticated_leak | TP | services/workshop/crapi/merchant/views.py:157-180 |
| `crapi-dashboard` GET `/identity/api/v2/user/dashboard` | caller | single | safe | PASS | — | TN | services/identity/src/main/java/com/crapi/controller/UserController.java:43-44; services/identity/src/main/java/com/crapi/service/Impl/UserServiceImpl.java:199-229 |
| `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` | caller | single | safe | INCONCLUSIVE | ambiguous_2xx | INC_SAFE | services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133 |
| `crapi-orders-all` GET `/workshop/api/shop/orders/all` | caller | single | safe | PASS | — | TN | services/workshop/crapi/shop/views.py:267-294 |
| `crapi-products` GET `/workshop/api/shop/products` | shared | single | safe | PASS | — | TN | services/workshop/crapi/shop/views.py:52-80 |
| `crapi-video-object` GET `/identity/api/v2/user/videos/{video_id}` | object | single | safe | PASS | — | TN | services/identity/src/main/java/com/crapi/service/Impl/ProfileServiceImpl.java:122-133 |

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
- **INC_SAFE** (differential) `crapi-vehicles` GET `/identity/api/v2/vehicle/vehicles` — INCONCLUSIVE, reason `ambiguous_2xx`. Safe endpoint was INCONCLUSIVE (`ambiguous_2xx`); not counted as a true negative. Source: services/identity/src/main/java/com/crapi/service/Impl/VehicleServiceImpl.java:115-133.
