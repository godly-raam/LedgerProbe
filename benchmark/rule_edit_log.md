# Rule Edit Log

All edits below were completed in one rules pass before the after-Amendments
headline scan. The first-run report and first-run rules are unchanged.

| Timestamp (UTC) | Run | Rule file | Case id | Edit | Motivation | First-run result |
|---|---|---|---|---|---|---|
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/vampi/rules_ext.yaml` | `vampi-mass-assignment-register-admin` | Added a mass-assignment rule with a generated username/password, `admin: true` injection, `_debug` readback, and admin `fixture.cleanup` delete. | Amendment 2 disposable fixtures; first-run restore contract had no account cleanup API. | NOT RUN, `restore_contract` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/vampi/rules_ext.yaml` | `vampi-mass-assignment-register-admin-secure` | Added the secure-mode counterpart with the same generated account, readback, and admin cleanup. | Amendment 2 disposable fixtures; first-run secure case was NOT RUN. | NOT RUN, `restore_contract` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/vampi/rules_ext.yaml` | `vampi-bfla-delete-user-admin-only` | Added a disposable victim-user creation via the documented registration endpoint, non-admin DELETE attack, 404 probe verification, and admin cleanup. | Amendment 2 disposable fixtures; first-run case was NOT RUN because a deleted account could not be recreated. | NOT RUN, `restore_contract` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/vampi/rules_ext.yaml` | `vampi-bola-email-ignores-path-user` | Changed the state-diff snapshot field from `email` to the documented `/me` response path `data.email`. | First-run report: snapshot used `/me` field `email`, but the payload nests it under `data.email`; the run was INCONCLUSIVE `verify_unavailable`. | INCONCLUSIVE, `verify_unavailable` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/crapi/rules_ext.yaml` | `crapi-bfla-admin-delete-video` | Added a BFLA rule against the owner's per-reset uploaded video, 204 owner-readback probe, and admin-route cleanup. The upload remains in target setup because the engine fixture schema has no multipart body. | Amendment 2 disposable cleanup; first-run case was NOT RUN because the deleted video could not be recreated. | NOT RUN, `restore_contract` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/crapi/rules_ext.yaml` | `crapi-mass-assignment-negative-order-quantity` | No rule added. | No exact cancel/refund restore exists and the credit balance has no disposable counterpart; adding a rule would require weakening the restore or gate contract. | NOT RUN, `restore_contract` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/dvr/rules_ext.yaml` | `dvr-bfla-menu-delete` | Added a Chef-created disposable menu item, Customer DELETE attack, Chef 404 probe, and `when_defined` Chef cleanup. | Amendment 2 disposable fixtures; first-run case was NOT RUN because the numeric id could not be recreated. | NOT RUN, `restore_contract` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/dvr/rules_ext.yaml` | `dvr-bfla-menu-create-safe` | Added a Chef-created disposable item, Customer PUT create attack with marker readback, attack-id capture, and two `when_defined` Chef cleanups. | Amendment 2 disposable fixtures; first-run safe case was NOT RUN because a regression would create an unrestorable row. | NOT RUN, `restore_contract` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/dvr/rules_ext.yaml` | `dvr-bfla-menu-update-safe` | Added a Chef-created disposable item, Customer PUT update attack, marker readback, and Chef cleanup. | Amendment 2 disposable fixtures; first-run safe case was NOT RUN because there was no restore-to-original API. | NOT RUN, `restore_contract` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/dvr/rules_ext.yaml` | `dvr-bola-profile-update` | No semantic rule edit; retained the inline body. | Amendment 1 request-body `$ref`/composition resolution now supplies the documented body schema; first-run failed with `execution_error` before selection. | ERROR, `execution_error` |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/dvr/rules_ext.yaml` | `dvr-bola-orders-list-safe`, `dvr-bola-coupons-safe` | Retained the owner-delivery-address and owner-coupon-id canaries and `require_owner_canary_in_baseline: true`; no semantic change. | Amendment 1 caller/shared canary requirement; first run used generic overlap and returned false positives with `canary_matched=false`. | FAIL `leak_detected` (FP) for both |
| 2026-11-12T10:46Z | after rewrite | `benchmark/targets/dvr/rules_ext.yaml` | `dvr-mass-assignment-profile-patch` | Replaced the string marker candidate with the schema/source enum value `Employee` in `inject.values`. | Amendment 1 enum-aware mass-assignment values; first run sent `lp-marker-...` and DVR returned 500 (`invalid input value for enum userrole`). | INCONCLUSIVE, `unexpected_status` |

## Post-headline correction

The row below was applied after the after-Amendments headline run was scored. It
is a post-headline correction, not a pre-headline rule edit: the rule was fixed
only after its false negative was observed in the headline. No engine change, no
ground-truth change, and no headline number in `README.md` or
`docs/VALIDATION.md` is altered by it. Its outcome is reported separately as
"post-headline; not the headline".

| Timestamp (UTC) | Run | Rule file | Case id | Edit | Reason | First-run result | Headline result (after Amendments) | Post-correction result |
|---|---|---|---|---|---|---|---|---|
| 2026-11-12T11:18Z | post-headline correction | `benchmark/targets/crapi/rules_ext.yaml` | `crapi-bfla-admin-delete-video` | Changed the owner readback probe `expected_status` from `204` to `404`. | Rule authoring error found after the headline run: the probe declared the identity controller's `NO_CONTENT` branch, but the deleted state is 404, because `ProfileServiceImpl.getProfileVideo` throws `CRAPIExceptionHandler(VIDEO_NOT_FOUND, 404)` when the user has no video row (`ProfileServiceImpl.java:126-132`) and `ExceptionHandler` returns that status (`ExceptionHandler.java:48-50`). The wrong expectation made the real deletion read as "no effect" and scored a false negative. | NOT RUN, `restore_contract` | PASS (`FN`), `no_effect` | FAIL (`TP`), `state_changed_by_other` (3/3 runs) |
