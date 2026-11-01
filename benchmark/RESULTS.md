# LedgerProbe real-world benchmark results

Generated: 2026-11-01T20:09:34+00:00

Targets were run locally on loopback only. Labels come from `benchmark/ground_truth/`, frozen before any scan.

## Scores

| Target | Mode | Status | TP | FP | TN | FN | INCONCLUSIVE | Precision | Recall |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vampi | legacy | ok | 8 | 5 | 0 | 0 | 0 | 61.5% | 100.0% |
| vampi | differential | ok | 7 | 0 | 3 | 1 | 3 | 100.0% | 87.5% |
| crapi | — | blocked | 0 | 0 | 0 | 0 | 0 | n/a | n/a |

INCONCLUSIVE is reported separately and is never counted as correct. A vulnerable endpoint that is not FAIL is counted as FN; a safe endpoint that is neither PASS nor FAIL is INCONCLUSIVE and is not counted as TN.

## Detail

### vampi

#### legacy

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

#### differential

| Case | Label | Verdict | Reason | Outcome | Source |
| --- | --- | --- | --- | --- | --- |
| `vampi-books-object` GET `/books/v1/{book_title}` | vulnerable | FAIL | leak_detected | TP | api_views/books.py:50-58 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | vulnerable | INCONCLUSIVE | ambiguous_2xx | FN | api_views/users.py:186-192 |
| `vampi-users-object` GET `/users/v1/{username}` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:45-49; models/user_model.py:55-56,70-81 |
| `vampi-users-list` GET `/users/v1` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:19-21; models/user_model.py:62-63 |
| `vampi-users-debug` GET `/users/v1/_debug` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:24-26; models/user_model.py:58-59,65-67 |
| `vampi-home` GET `/` | safe | PASS | — | TN | api_views/main.py:14-18 |
| `vampi-book-list` GET `/books/v1` | safe | PASS | — | TN | api_views/books.py:12-14; models/books_model.py:23-24 |
| `vampi-me` GET `/me` | safe | INCONCLUSIVE | ambiguous_2xx | INCONCLUSIVE | api_views/users.py:28-42 |
| `vampi-books-object` GET `/books/v1/{book_title}` | safe | PASS | — | TN | api_views/books.py:61-73 |
| `vampi-users-password` PUT `/users/v1/{username}/password` | safe | INCONCLUSIVE | ambiguous_2xx | INCONCLUSIVE | api_views/users.py:193-196 |
| `vampi-users-object` GET `/users/v1/{username}` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:45-49 |
| `vampi-users-list` GET `/users/v1` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:19-21 |
| `vampi-users-debug` GET `/users/v1/_debug` | vulnerable | FAIL | unauthenticated_leak | TP | api_views/users.py:24-26; app.py:4-7 |

#### FP/FN list

- **FP** (legacy) `vampi-home` GET `/` — verdict `FAIL`, reason `assertion_failed`. safe label; source: api_views/main.py:14-18.
- **FP** (legacy) `vampi-book-list` GET `/books/v1` — verdict `FAIL`, reason `assertion_failed`. safe label; source: api_views/books.py:12-14; models/books_model.py:23-24.
- **FP** (legacy) `vampi-me` GET `/me` — verdict `FAIL`, reason `assertion_failed`. safe label; source: api_views/users.py:28-42.
- **FP** (legacy) `vampi-books-object` GET `/books/v1/{book_title}` — verdict `FAIL`, reason `assertion_failed`. safe label; source: api_views/books.py:61-73.
- **FP** (legacy) `vampi-users-password` PUT `/users/v1/{username}/password` — verdict `FAIL`, reason `assertion_failed`. safe label; source: api_views/users.py:193-196.
- **FN** (differential) `vampi-users-password` PUT `/users/v1/{username}/password` — verdict `INCONCLUSIVE`, reason `ambiguous_2xx`. vulnerable label; source: api_views/users.py:186-192.

### crapi

Not executed: Docker daemon is not reachable by this user; no containers were started.

