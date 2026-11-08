# Amendment 1: engine changes after the first extension run

This amendment records post-first-run tuning. The first-run report in
[`docs/VALIDATION.md`](../docs/VALIDATION.md) remains the record of the
pre-registered run. Any results produced with these changes must be reported
separately as **after tuning**; they are not a rerun of the frozen first-run
results.

`benchmark/PREREGISTRATION.md` and `benchmark/ground_truth/ext_vampi.yaml`,
`benchmark/ground_truth/ext_crapi.yaml`, and `benchmark/ground_truth/ext_dvr.yaml`
are unchanged. The post-change engine SHA is intentionally a placeholder until
the maintainer commits this amendment.

| Item | Change | First-run finding addressed | Regression tests |
|---|---|---|---|
| 1 | Resolve `$ref` in request bodies, parameters, and responses, including components and nested refs; flatten basic `allOf`/`oneOf`/`anyOf`; preserve `enum`, `required`, and `readOnly`; retain the circular-ref termination guard; name an unresolvable ref in the error. | `dvr-bola-profile-update` — `Required request schema is unresolved` on a referenced request body. | `tests/test_amendment1.py::test_refs_in_request_body_parameters_and_responses_resolve`, `::test_composition_keywords_merge_and_keep_constraints`, `::test_unresolvable_ref_names_the_reference_without_a_traceback`, `::test_circular_refs_terminate`; existing `tests/test_parser.py` reference tests |
| 2 | Add `login_request.params.body_format: json|form` (default `json`). Form mode sends `application/x-www-form-urlencoded` with credential fields resolved from secret refs. | DVR `/token` is an `OAuth2PasswordRequestForm`; the first run used a target-specific script bridge. | `tests/test_amendment1.py::test_form_login_posts_urlencoded_credentials_and_extracts_token`, `::test_form_login_wrong_credentials_fail_fast_and_never_echo_password`; existing `tests/test_auth.py::AuthProviderTests::test_attempt_cap` |
| 3 | For `caller` and `shared` scope, require non-empty declared canaries and require an owner canary in the other identity's response for FAIL. Generic unique-value overlap alone is `INCONCLUSIVE` with `overlap_without_canary`. | `dvr-bola-orders-list-safe` and `dvr-bola-coupons-safe` — caller-scope false positives from generic overlap with `canary_matched=false`. | `tests/test_amendment1.py::test_caller_scope_generic_overlap_is_inconclusive_without_a_canary`, `::test_shared_caller_loader_requires_nonempty_canaries`; corpus profile `caller_scoped_generic_overlap`; existing caller/shared corpus profiles |
| 4 | Accept `inject[].values` candidates, try them in order up to `max_attempts` (default 2, maximum 3), restore after every attempt, and use the first differing enum value when the resolved field schema is an enum and no values are supplied. Keep evidence to field names/counts and report non-2xx statuses without the injected value. | `dvr-mass-assignment-profile-patch` — marker string caused an enum 500 and `unexpected_status`. | `tests/test_amendment1.py::test_mass_assignment_uses_enum_value_that_differs_from_before`, `::test_mass_assignment_values_are_tried_in_order_and_stopped_at_max_attempts`, `::test_mass_assignment_enum_allowlist_is_pass_and_restores_each_attempt`, `::test_mass_assignment_invalid_enum_is_inconclusive_without_echoing_value`, `::test_mass_assignment_max_attempts_is_bounded` |
| 5 | Missing or empty rules files produce a rules-specific message, exit code 2, and no traceback. | crAPI empty rules — `ValueError` and no verdict. | `tests/test_amendment1.py::test_missing_or_empty_rules_file_is_a_clear_exit_two` |
| 6 | Every JUnit testcase carries `ledgerprobe.verdict` for PASS, FAIL, INCONCLUSIVE, SKIPPED, and ERROR. The benchmark scorer reads that property and does not infer PASS from the absence of a failure element. | PASS cases omitted `ledgerprobe.verdict`; the scorer inferred PASS. | `tests/test_amendment1.py::test_every_junit_testcase_declares_its_verdict`, `::test_benchmark_scorer_reads_verdict_property_and_never_infers_pass` |

## Scope boundaries

- This amendment does not add ephemeral fixtures or change restore semantics.
- No benchmark target was run for this amendment.
- Existing ground truth, including all `ext_*.yaml` files, and
  `benchmark/PREREGISTRATION.md` are unchanged.
- The first-run numbers in `docs/VALIDATION.md` are unchanged. The amendment
  there is a pointer only.
- Post-change engine SHA: `370d2c9198f0bb7d2ebbb67c97802011feb94191`
