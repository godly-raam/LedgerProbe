# Threat model

## Assets

- **Target data:** tenant objects, response fields, canaries, and state used to prove an authorization difference.
- **Credentials:** API tokens, cookies, login passwords, OAuth client secrets, and Vault/AWS references.
- **Reports:** SARIF, JUnit, JSON results, drift inventories, logs, and metrics.
- **Tickets:** Jira, Linear, Slack, and DefectDojo payloads or links.
- **Policy and evidence:** rule files, generated candidates, suppressions, and benchmark ground truth.

## Actors

| Actor | Capability |
| --- | --- |
| Operator | Chooses targets, rules, identities, mutation opt-ins, and report destinations. |
| Malicious rule author | Controls endpoints, canaries, scopes, and evidence paths in a rule. |
| Malicious target response | Returns misleading status codes, HTML, huge/cyclic JSON, canaries, or errors. |
| Compromised CI | Can read repository files, environment secrets, logs, and generated artifacts. |

## Trust boundaries

1. **CLI and local files to engine:** specs, rules, auth files, suppressions, and inputs are untrusted until validated.
2. **Engine to target:** every HTTP request crosses a host allowlist and mutation/read-only policy.
3. **Target response to verdict:** status, headers, JSON, and timing are untrusted evidence.
4. **Engine to reporters:** only allowlisted metadata may cross into SARIF, JUnit, JSON, logs, and tickets.
5. **Engine to external services:** Jira, Linear, Slack, and DefectDojo are separate network destinations with explicit opt-ins.

## Risks and controls

| Risk | Actual control | Test that backs it |
| --- | --- | --- |
| A rule mutates a target without consent | `mutating: true`, `--allow-mutations`, non-production host, no `--read-only`, and a mandatory `restore:` block are required before execution. | `tests/test_controls.py::test_production_hard_blocks_mutation_without_http`; `tests/test_bfla_e2e.py::test_bfla_mutation_gates`; `tests/test_corpus.py` mutation tests |
| Credentials or mutations reach an unexpected host | Target, identity, redirect, and synchronized-request hosts are checked; redirects and automatic retries are disabled. Synchronized requests re-check the allowlist. | `tests/test_auth.py::AuthProviderTests::test_auth_host_must_be_allowed`; `tests/test_guardrails.py` transport/redirect tests; `pkg/guardrails/sync.py::_host_allowed` |
| Production is mutated or scanned read-only without consent | Production mutation/race is hard-blocked; production read-only requires `--allow-production-read-only`. | `tests/test_controls.py::test_production_hard_blocks_mutation_without_http`; `tests/test_step12_debt.py::test_environment_matrix_production_read_only_and_mutation_blocked` |
| A run cannot be stopped without leaving state behind | `--kill-file` is checked before requests and between race rounds; pending restore runs; remaining rules are skipped; exit 4. | `tests/test_controls.py::test_kill_file_skips_remaining_rules_and_exits_four`; `tests/test_step12_debt.py::test_mid_race_kill_restores_and_skips_with_exit_four` |
| Secrets leak into reports, logs, or tickets | Secret wrappers render as `***`; a global redactor covers logs and errors; reporters and ticket bodies use allowlisted evidence only. | `tests/test_auth.py::AuthProviderTests::test_static_env_and_redaction`; `tests/test_observability.py::test_json_log_has_required_fields_and_redacts_sentinel`; `tests/test_reporter.py::test_differential_evidence_is_allowlisted_in_sarif_and_junit`; `tests/test_integrations.py::test_body_contains_only_allowlisted_evidence_and_no_secret_values` |
| A malicious target injects values into evidence | Evidence is reduced to counts, booleans, hashes, statuses, and typed known fields; response bodies and expanded IDs are not persisted. | `pkg/reporter/_evidence.py`; `tests/test_results.py::test_schema_document_validates_and_contains_no_secret_values`; `tests/test_reporter.py::test_differential_evidence_is_allowlisted_in_sarif_and_junit` |
| Login attempts cause lockout or unbounded cost | Login/token attempts are capped per identity per run; 403 is never refreshed; only 401 can trigger opt-in refresh. | `tests/test_auth.py::AuthProviderTests::test_attempt_cap`; `tests/test_auth.py::AuthProviderTests::test_baseline_401_and_403_no_refresh`; `tests/test_auth.py::AuthProviderTests::test_401_refresh_when_enabled` |
| Generated rules execute without human review | Generated rules require `--accept-generated`; mutation candidates are disabled and require restore/verify. | `tests/test_traffic.py::test_generated_review_required_and_disabled_rules_are_not_executed`; `tests/test_traffic.py::test_end_to_end_generated_rule_fails_vulnerable_and_passes_fixed` |
| Suppressions hide findings indefinitely | Expiry is capped, reasons/owners/dates are required, high/critical findings need ticket and approval, expired entries count again. | `tests/test_suppressions.py::test_active_suppression_and_boundary_and_expiry`; `tests/test_suppressions.py::test_stale_suppression_is_reported_and_error_cannot_be_suppressed` |
| A second identity is silently treated as authorized after a 403 | A 403 is the authorization signal and is never refreshed; only opt-in 401 refresh exists. | `tests/test_auth.py::AuthProviderTests::test_baseline_401_and_403_no_refresh` |
| Reports or tickets fail and change a scan verdict | Reports are written before notifications; tracker failures are warnings unless `--fail-on-tracker-error`; report schemas are tested. | `tests/test_integrations.py::test_persistent_5xx_is_sanitized_tracker_error_and_results_are_unchanged`; `tests/test_reporter.py`; `tests/test_dojo.py` |
| A scan contacts a public target through the benchmark harness | Benchmark target validation accepts loopback, or RFC1918 Docker hosts only with explicit opt-in, before opening a socket. | `benchmark/tests/test_safety.py::test_public_or_malformed_targets_hard_fail`; `benchmark/tests/test_safety.py::test_docker_private_addresses_require_explicit_opt_in` |
| A generated or author-declared check overclaims coverage | The rule schema requires explicit scopes; the benchmark marks author-declared scope and reduced-confidence cases; the corpus is a regression guard, not accuracy evidence. | `tests/test_rules.py`; `benchmark/tests/test_safety.py::test_scorer_never_counts_inconclusive_as_correct` |
| A race result is mistaken for proof | Weak rounds, rate limits, errors, and failed resets become INCONCLUSIVE; the report says "no violation observed," not "safe." | `tests/test_race.py::test_race_verdict_weak_and_errors`; `tests/test_race.py::test_race_verdict_violation_and_pass` |

## Residual risks

- **Author-declared scopes:** `object`, `caller`, and `shared` come from the rule author; a wrong declaration can weaken or misclassify a check.
- **Heuristic evidence:** canaries, overlap counts, soft-deny detection, and pagination are heuristics. Ambiguous evidence becomes INCONCLUSIVE, but the boundary can still be wrong.
- **Client-side race timing:** last-byte release measures the client's spread, not server-side interleaving. Network or server scheduling can hide or create a race.
- **Same-author benchmark:** endpoint selection, canaries, scopes, and rules share an author. The 23-case result is not an independent population estimate and has no confidence interval.
- **Compromised host or CI:** an attacker who can alter the Python process, rule files, or environment can bypass in-process controls. Run in an isolated runner with least-privilege credentials.
- **Target-side secrets:** a malicious target can return secrets in response bodies; allowlisting reduces persistence, but the tool cannot prevent the target from exposing its own data.
- **External services:** Jira/Linear/Slack tests use `MockTransport`; no live tenant or workspace is part of this repository.
