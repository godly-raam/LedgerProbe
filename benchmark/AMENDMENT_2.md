# Amendment 2: disposable fixtures

Engine SHA: `a5a8d60c67c11c40c80500d0adb3dc5ddfaf2fdf`

## Change

Rules may now declare a strict `fixture:` block that creates a disposable
object, captures its identifier, and removes it in an always-running cleanup
path. `capture` is also allowed on the attack request, and
`variables.generated` supplies per-run names prefixed with `lp_`. Captured
values are available as `{{fixture.<name>}}` and generated values as
`{{gen.<name>}}` in attack, verification and cleanup requests.

`fixture.cleanup` satisfies the restore requirement only for objects created by
that rule's fixture or attack. Rules that mutate pre-existing objects still
require `restore:`. All fixture, attack and verify requests pass the existing
mutation gates; cleanup runs after a kill switch but is otherwise subject to
the same guarded transport.

New failure reasons are `fixture_failed`, `capture_failed` and
`cleanup_failed`. Cleanup failure is exit code 2 and names only the rule.

## First-run findings addressed

The first run reported 19 cases, of which 8 were NOT RUN because the restore
contract could not restore pre-existing victim data. The case IDs from
`docs/VALIDATION.md` are:

- `vampi-mass-assignment-register-admin`
- `vampi-mass-assignment-register-admin-secure`
- `vampi-bfla-delete-user-admin-only`
- `crapi-mass-assignment-negative-order-quantity`
- `crapi-bfla-admin-delete-video`
- `dvr-bfla-menu-delete`
- `dvr-bfla-menu-create-safe`
- `dvr-bfla-menu-update-safe`

These cases can now be expressed against disposable objects where the target
supports creating and removing them. This amendment does not run any benchmark
target and does not claim that all eight targets expose such an API.

## Tests

- `tests/test_disposable_fixtures.py::test_disposable_rules_are_idempotent_and_keep_fingerprints`
- `tests/test_disposable_fixtures.py::test_fixture_creation_failure_never_sends_the_attack`
- `tests/test_disposable_fixtures.py::test_capture_failure_still_runs_cleanup`
- `tests/test_disposable_fixtures.py::test_cleanup_failure_runs_later_steps_and_exits_two`
- `tests/test_disposable_fixtures.py::test_kill_switch_stops_attack_but_cleanup_runs`
- `tests/test_disposable_fixtures.py::test_every_mutation_gate_sends_no_fixture_traffic`
- `tests/test_disposable_fixtures.py::test_captured_and_generated_values_never_reach_report_surfaces`
- `tests/test_disposable_fixtures.py::test_fixture_cleanup_satisfies_restore_only_without_a_restore_block`
- `tests/test_disposable_fixtures.py::test_fixture_schema_is_strict`
- `tests/test_corpus.py::test_corpus_profile` for every new disposable profile

## Frozen files

`benchmark/PREREGISTRATION.md` and all `benchmark/ground_truth/ext_*.yaml` files
are unchanged by this amendment.