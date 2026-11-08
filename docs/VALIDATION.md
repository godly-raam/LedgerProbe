# Extension validation: VAmPI, crAPI, and DVR

This is the first-run report for the preregistered extension benchmark. It is a
same-author, source-derived validation, not a population estimate. Rules were
authored once from each target's README, source, OpenAPI, and tests before the
first target scan. No rule was changed after a verdict was observed.

## Run identity

| Item | Value |
|---|---|
| Pre-registration commit | `97d733f` (`docs(benchmark): pre-register extension ground-truth targets`) |
| Repository HEAD at run | `5f2962a6514089a6d33f51ac20287a3d58370546` |
| Branch | `main` |
| Engine commit | `9944bb360807fee64d33251515b503ecc4d12573` |
| Engine version | `LedgerProbe 1.1.0` |
| Engine diff from freeze | `0` bytes (`ledgerprobe.py pkg schemas`) |
| Run 1 | 2026-11-08, 20:35–20:39 UTC |
| Runs 2 and 3 | 2026-11-08, fresh resets after each run |
| Scored ground truth | `ext_vampi.yaml`, `ext_crapi.yaml`, `ext_dvr.yaml` only |
| Cases | 19 total: 8 vulnerable, 11 safe |
| Experimental cases | DVR's `mass_assignment` rules were run with `--experimental`; all `mass_assignment` rows are marked `(exp.)` below. |
| Docker / Compose | Engine `28.5.2+dfsg4`; Compose `2.40.3-3` |

The frozen CLI was invoked directly for each target. There is no committed
`ext_*.yaml` runner in `benchmark/run.py`; the ext rules were supplied through the
CLI's normal `--rules` argument and scored from the JUnit output. This is a
harness gap, not an engine change. A sidecar at
`benchmark/.out/run-metadata.json` records the engine SHA and target versions;
run JSON still records only the tool version.

## Ground truth and target snapshots

| Target | Upstream revision | Runtime | PREREG hash |
|---|---|---|---|
| VAmPI | `f16052dce83f05847133ec98f01c5193a41de7d8` | `erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12`; local image `d7394e7e4d2a` | `70a94850bdaa892cc60c8dc0873eb5114b278f0f958849db080e41f65befe79d` |
| crAPI | `700f03d12a392d9e408260b4beae72ed02a4a1a4` (`v1.1.6`) | source at that commit; no image digest claimed | `3b2ac7a762e66551a82ec15120192a97c77c5e1c48bfd82e6771083e6209191a` |
| DVR | `d32d09972aec7830f5f1d4a5d274cac7aae7eb82` | built locally; image `sha256:47e1bd64a00f8aae8aac8b2d7a5d0c5e788be68b867bdb8eda7104d9c79088b4` | `d3b356c9b1859d044bdd207f72bf698083dc83269702eb54193c72b7b201bee8` |

New target source or spec files were not added. DVR and crAPI sources were fetched
into `benchmark/.out` at run time; the existing tracked VAmPI OpenAPI snapshot was
reused. The local image IDs above are the images actually used; the VAmPI digest
is the PREREG-pinned multi-arch digest.

## DVR setup

DVR is a FastAPI application with PostgreSQL, seeded from `app/init.py`. The
Compose project publishes only `127.0.0.1:8091`; the database has no host port.
The image is built from the pinned source snapshot, not pulled from a registry.

| Role | Upstream seed users | Benchmark use |
|---|---|---|
| Chef | `chef` | Not used; the admin-stats safe case expects a non-Chef denial. |
| Employee | `Mike`, `Saul` | Not used as scanner identities. |
| Customer | `hhm`, `johndoe`, `alicesmith` | Seeded by upstream; not used as scanner identities. |
| Customer | `lp_owner_<suffix>`, `lp_other_<suffix>` | Created by `benchmark/targets/dvr/setup.py`; each gets one order and one referral coupon. |

`setup.py` writes `ledgerprobe-auth.yaml`, `inputs.json`, and a `0600`
password file under `benchmark/.out/dvr/default`. The scanner identities use
`provider: script`: DVR's `/token` endpoint accepts
`OAuth2PasswordRequestForm`, while the engine's `login_request` provider sends a
JSON body. The script bridge calls the form endpoint and returns the token in
memory. This is a **protocol deviation** from the required `login_request`
path; it is the only target using it. The password file and generated auth/input
files were removed after the runs. No token was written to disk.

### Restore handling

| Target | Case | Mutation | Restore handling |
|---|---|---|---|
| VAmPI | `vampi-mass-assignment-register-admin` | register an admin | No self-delete/account cleanup API; NOT RUN. |
| VAmPI | `vampi-mass-assignment-register-admin-secure` | register | Same; NOT RUN. |
| VAmPI | `vampi-bola-email-ignores-path-user` | change another user's email | Restore both users' emails through `PUT /users/v1/{username}/email` in `finally`; ran. |
| VAmPI | `vampi-bfla-delete-user-admin-only` | delete a user | Deleted account cannot be recreated with the same identity; NOT RUN. |
| crAPI | `crapi-mass-assignment-negative-order-quantity` | create a negative-quantity order | No cancel/refund API that restores stock and credit exactly; NOT RUN. |
| crAPI | `crapi-bfla-admin-delete-video` | delete another user's video | No API to recreate the deleted video; NOT RUN. |
| DVR | `dvr-bola-profile-update` | update another Customer's profile | `PUT /profile` with the saved original fields; ran. |
| DVR | `dvr-bfla-update-role` | promote a Customer to Employee | `PUT /users/update_role` back to `Customer`; ran. |
| DVR | `dvr-bfla-menu-delete` | delete a menu item | No API to recreate the same numeric id; NOT RUN. |
| DVR | `dvr-bfla-menu-create-safe` | create a menu item | No clean restore path for a created row; NOT RUN. |
| DVR | `dvr-bfla-menu-update-safe` | update a menu item | No restore-to-original API; NOT RUN. |
| DVR | `dvr-mass-assignment-profile-patch` | patch the caller's role | `PATCH /profile` with `role: Customer`; ran, but the mutation returned 500. |
| DVR | `dvr-mass-assignment-profile-put-safe` | inject an undeclared role | `PUT /profile` with the saved original fields; ran. |

Every mutating rule that ran had a `restore:` block. Rules without a complete
restore path were omitted rather than weakening the gate. They are reported as
NOT RUN and count as misses when the ground-truth label is vulnerable.

## Run 1 results

Counts are `TP / FP / TN / FN / INC_vuln / INC_safe / NOT RUN`. Detection is
`TP / (TP + FN + INC_vuln)`; NOT RUN is in the denominator as a miss because the
case could not produce a verdict. Specificity is `TN / (TN + FP + INC_safe +
NOT RUN)`; `INC_safe` is reported separately and is never counted as a pass.
Every rate shows its numerator and denominator. Intervals are Wilson 95%
intervals and are descriptive only.

| Target | Class | Nv | TP | FN | INC_v | NR_v | Detection (95% CI) | Ns | TN | FP | INC_s | NR_s | Specificity (95% CI) |
|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---|
| VAmPI | mass_assignment (exp.) | 1 | 0 | 0 | 0 | 1 | 0/1 = 0.0% (0.0–79.3) | 1 | 0 | 0 | 0 | 1 | 0/1 = 0.0% (0.0–79.3) |
| VAmPI | bola | 0 | 0 | 0 | 0 | 0 | — | 1 | 0 | 0 | 1 | 0 | 0/1 = 0.0% (0.0–79.3) |
| VAmPI | bfla | 0 | 0 | 0 | 0 | 0 | — | 1 | 0 | 0 | 0 | 1 | 0/1 = 0.0% (0.0–79.3) |
| crAPI | mass_assignment (exp.) | 1 | 0 | 0 | 0 | 1 | 0/1 = 0.0% (0.0–79.3) | 0 | 0 | 0 | 0 | 0 | — |
| crAPI | bfla | 1 | 0 | 0 | 0 | 1 | 0/1 = 0.0% (0.0–79.3) | 0 | 0 | 0 | 0 | 0 | — |
| DVR | bola | 2 | 1 | 0 | 1 | 0 | 1/2 = 50.0% (9.5–90.5) | 4 | 2 | 2 | 0 | 0 | 2/4 = 50.0% (15.0–85.0) |
| DVR | bfla | 2 | 1 | 0 | 0 | 1 | 1/2 = 50.0% (9.5–90.5) | 3 | 1 | 0 | 0 | 2 | 1/3 = 33.3% (6.1–79.2) |
| DVR | mass_assignment (exp.) | 1 | 0 | 0 | 1 | 0 | 0/1 = 0.0% (0.0–79.3) | 1 | 1 | 0 | 0 | 0 | 1/1 = 100.0% (20.7–100.0) |
| **Overall** | **all** | **8** | **2** | **0** | **2** | **4** | **2/8 = 25.0% (7.1–59.1)** | **11** | **4** | **2** | **1** | **4** | **4/11 = 36.4% (15.2–64.6)** |

Per target:

| Target | Nv | TP | FN | INC_v | NR_v | Detection (95% CI) | Ns | TN | FP | INC_s | NR_s | Specificity (95% CI) |
|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---|
| VAmPI | 1 | 0 | 0 | 0 | 1 | 0/1 = 0.0% (0.0–79.3) | 3 | 0 | 0 | 1 | 2 | 0/3 = 0.0% (0.0–56.1) |
| crAPI | 2 | 0 | 0 | 0 | 2 | 0/2 = 0.0% (0.0–65.8) | 0 | 0 | 0 | 0 | 0 | — |
| DVR | 5 | 2 | 0 | 2 | 1 | 2/5 = 40.0% (11.8–76.9) | 8 | 4 | 2 | 0 | 2 | 4/8 = 50.0% (21.5–78.5) |
| **Overall** | **8** | **2** | **0** | **2** | **4** | **2/8 = 25.0% (7.1–59.1)** | **11** | **4** | **2** | **1** | **4** | **4/11 = 36.4% (15.2–64.6)** |

No false negatives occurred; the limiting outcomes were NOT RUN, one execution
error, one target 500, two false positives from caller-scope overlap, and one
safe verification abstention.

## Case-by-case results

`TP`/`TN` rows are included for completeness. Every case that is not a TP or TN
has a diagnosis and the run evidence that supports it. "Rule authoring" means
the rule's declared check produced the wrong outcome; no rule was edited after
run 1.

| Case | Ground truth | Run 1 verdict | Outcome | Reason | Diagnosis | Evidence |
|---|---|---|---|---|---|---|
| `vampi-mass-assignment-register-admin` (exp.) | vulnerable | NOT RUN | NR_v | `restore_contract` | restore-contract limitation | No self-delete/registration cleanup API; rule omitted. |
| `vampi-mass-assignment-register-admin-secure` (exp.) | safe | NOT RUN | NR_s | `restore_contract` | restore-contract limitation | Same account-creation cleanup gap; rule omitted. |
| `vampi-bola-email-ignores-path-user` | safe | INCONCLUSIVE | INC_safe | `verify_unavailable` | rule authoring problem | `run1.log`: "State snapshot was unavailable before the mutation"; snapshot used `/me` field `email`, actual payload nests it under `data.email`; no request sent. |
| `vampi-bfla-delete-user-admin-only` | safe | NOT RUN | NR_s | `restore_contract` | restore-contract limitation | A deleted user cannot be restored with the same credentials/identity. |
| `crapi-mass-assignment-negative-order-quantity` (exp.) | vulnerable | NOT RUN | NR_v | `restore_contract` | restore-contract limitation | No exact cancel/refund restore; two-case crAPI ruleset therefore had no runnable rules. |
| `crapi-bfla-admin-delete-video` | vulnerable | NOT RUN | NR_v | `restore_contract` | restore-contract limitation | Deleted video cannot be recreated through the API. The empty ruleset was rejected with `ValueError`; see findings. |
| `dvr-bola-profile-update` | vulnerable | ERROR | INC_v | `execution_error` | engine limitation | `run1.log`: "Required request schema is unresolved"; OpenAPI request body is a `$ref` the executor cannot resolve (engine `pkg/rules/__init__.py:800`). |
| `dvr-bola-order-read` | vulnerable | FAIL | **TP** | `leak_detected` | — | `canary_matched=true`, `overlap_count=7`, `confirm_runs=2`; nonexistent object 404, unauthenticated 401. |
| `dvr-bola-order-status-safe` | safe | PASS | **TN** | denial | — | Forbidden request denied; `overlap_count=0`, `canary_matched=false`. |
| `dvr-bola-orders-list-safe` | safe | FAIL | **FP** | `leak_detected` | rule authoring problem | Caller scope returned only the other Customer's own order; `canary_matched=false`, `overlap_count=2` generic fields; no `require_primary_canary`. |
| `dvr-bola-profile-read-safe` | safe | PASS | **TN** | `caller_scoped` | — | Other Customer's own profile; `overlap_count=1`, `canary_matched=false`. |
| `dvr-bola-coupons-safe` | safe | FAIL | **FP** | `leak_detected` | rule authoring problem | Caller scope returned only the other Customer's coupons; `canary_matched=false`, `overlap_count=3` generic fields; no `require_primary_canary`. |
| `dvr-bfla-menu-delete` | vulnerable | NOT RUN | NR_v | `restore_contract` | restore-contract limitation | No API to recreate the deleted numeric menu-item id. |
| `dvr-bfla-update-role` | vulnerable | FAIL | **TP** | `state_changed_by_other` | — | Mutation 200; role snapshot changed from `da9675c4…` to `b60c7652…`; restored to `Customer`. |
| `dvr-bfla-menu-create-safe` | safe | NOT RUN | NR_s | `restore_contract` | restore-contract limitation | A regression would create a row with no clean cleanup path. |
| `dvr-bfla-menu-update-safe` | safe | NOT RUN | NR_s | `restore_contract` | restore-contract limitation | No restore-to-original API for a menu-item update. |
| `dvr-bfla-admin-stats-safe` | safe | PASS | **TN** | assertion | — | Non-Chef request returned the asserted denial (403). |
| `dvr-mass-assignment-profile-patch` (exp.) | vulnerable | INCONCLUSIVE | INC_v | `unexpected_status` | engine limitation | Mutation returned 500; DVR log shows SQLAlchemy `DataError: invalid input value for enum userrole: "lp-marker-…"`. The injected string cannot satisfy the role enum; no valid state comparison. |
| `dvr-mass-assignment-profile-put-safe` (exp.) | safe | PASS | **TN** | no effect | — | Mutation 200; injected `role` was not persisted; restore ran. |

## Determinism

All executed cases were compared by rule id, verdict, reason, and evidence
across runs 1–3. Runs 2 and 3 were fresh resets, not reruns against surviving
state.

| Target | Cases with a verdict in run 1 | Run 2 = run 1 | Run 3 = run 1 | Flips |
|---|---:|---|---|---:|
| VAmPI `vulnerable` | 1 | yes | yes | 0 |
| VAmPI `secure` | 1 | yes | yes | 0 |
| crAPI `default` | 0 | no scan | no scan | n/a |
| DVR `default` | 10 executed; 3 NOT RUN | yes | yes | 0 |

VAmPI's one case was `INCONCLUSIVE verify_unavailable` in all three runs. DVR's
four PASSes, four FAILs, one INCONCLUSIVE, and one ERROR were identical in all
three runs, including reason codes and evidence values. The three DVR NOT RUN
cases were not executed in any run. crAPI produced no verdicts because both
cases lack a restore path; its three boots/seeds succeeded, but each scan exited
with the same configuration error.

## Rule edit log

`benchmark/rule_edit_log.md` contains no edits. No rule failed to load and no
schema/syntax error prevented a verdict, so the allowed post-run syntax/schema
fix was not used. The two FP rules and the VAmPI snapshot rule were left exactly
as authored; changing them would be post-run tuning.

## Findings (not fixed)

| Finding | Evidence | Scope |
|---|---|---|
| Unresolved `$ref` request body aborts a mutating build. | `dvr-bola-profile-update` ERROR `execution_error`; "Required request schema is unresolved." | Engine limitation. The DVR OpenAPI body is referenced; path/body schema resolution is incomplete. |
| Caller-scope overlap can produce a FAIL without an owner canary. | `dvr-bola-orders-list-safe` and `dvr-bola-coupons-safe` FAIL with `canary_matched=false`, `overlap_count=2/3`. | Engine/rule interaction. The rules used `scope: caller` and a baseline canary but not `require_primary_canary`; generic leaf overlap was sufficient. |
| Mass-assignment injection cannot select an enum-compatible value. | `dvr-mass-assignment-profile-patch` INCONCLUSIVE `unexpected_status`; mutation 500; DVR `invalid input value for enum userrole`. | Engine limitation. `inject: role, type: string` generates a marker string; DVR accepts only `Chef`, `Employee`, `Customer`. |
| Empty rules files raise `ValueError` instead of producing an empty valid result. | `benchmark/.out/crapi/default/run1.log`–`run3.log`: `error: scan/configuration failure (ValueError)`. | Engine limitation; no scan verdict for crAPI. |
| PASS cases can omit the `ledgerprobe.verdict` JUnit property. | `dvr-bfla-admin-stats-safe` and other PASS testcases have no `ledgerprobe.verdict`; scorer infers PASS from the absence of `<failure>`/`<error>`. | Reporter/contract issue. It does not change the verdict, but it makes scoring depend on inference. |
| DVR's `/token` is form-only. | `benchmark/targets/dvr/login.py`; engine `login_request` sends JSON. | Adapter deviation, not an engine bug. The script bridge is disclosed above. |

## Checks

| Check | Command / evidence | Exit |
|---|---|---:|
| Full test suite | `.venv/bin/python -m pytest tests benchmark/tests -q`; 569 passed, 47 warnings, 138 subtests | `0` |
| Corpus gate | `.venv/bin/python tests/corpus_metrics.py`; `TP=19 TN=23 FP=0 FN=0`; gate passed | `0` |
| Gitleaks | pinned `8.28.0`; copied tracked plus new files, ran `gitleaks dir . -i .gitleaksignore` from the copied root; the current-tree fingerprint suppresses the pre-existing synthetic Vault fixture | `0` |
| Trivy FS secrets | `trivy fs --scanners secret`, excluding `benchmark/.out`, `.venv`, `dashboard/.next` only; no findings | `0` |
| Engine diff | `git diff 9944bb360807fee64d33251515b503ecc4d12573..HEAD -- ledgerprobe.py pkg schemas \| wc -c` | `0` |

The first gitleaks scan found one synthetic value in
`tests/test_auth.py:391` (`VAULT-SECRET-…` inside a mocked Vault response). It is
a pre-existing test-only fake; the existing ignore fingerprint referenced an
older line number. The current-tree fingerprint was added to `.gitleaksignore`;
no test or engine code was changed to silence it. The DVR directory itself was
clean.

## Limitations

| Limitation | Consequence |
|---|---|
| Small N per class: 1–4 cases per class; 8 vulnerable and 11 safe overall. | Wilson intervals span most of 0–100%; do not read rates as population estimates. |
| Same author wrote the engine, ground truth, and rules. | Target knowledge and rule-authoring choices remain a bias; no inter-rater check. |
| DVR contributes 13 of 19 cases. | The aggregate is dominated by one target, and DVR is a teaching application, not a production architecture. |
| VAmPI contributes 1 vulnerable case and 3 safe cases. | One VAmPI result cannot establish VAmPI coverage. |
| crAPI contributes 2 vulnerable cases and no safe cases, and neither ran. | crAPI's 0/2 is NOT RUN, not evidence that the engine misses those cases. |
| Four vulnerable cases and four safe cases cannot satisfy the restore contract. | They count as misses/NOT RUN in the headline; no gate was weakened. |
| No documented business-limit or race cases exist on these real targets. | Those checks remain fixture-only; this validation says nothing about them. |
| DVR uses a script form-login bridge. | The auth path is not the required `login_request` path; it is a target-specific deviation. |
| Runs 2 and 3 measure only determinism. | They do not add independent samples or reduce interval width. |
| No target source or specs are committed. | Reproduction requires network fetches at the pinned commits/digests and the ignored `.out` tree. |

## Reproduction notes

The runtime evidence is under `benchmark/.out/` and is not committed:
`dvr/default/run{1,2,3}.{json,xml,log}`,
`vampi/{vulnerable,secure}/run{1,2,3}.{json,xml,log}`, and
`crapi/default/run{1,2,3}.log`. Generated auth, input, password, and token files
were removed after scoring. Target containers were stopped after the runs.
