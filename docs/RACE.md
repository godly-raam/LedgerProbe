# Race-condition checks

LedgerProbe's race path is for **authorized sandbox testing** of double-spend,
single-use coupon, and idempotency-key behavior. It is not a production load
generator and it cannot prove that a target is free of races.

## Design

A race rule is a normal mutating rule with a `race:` block. The strict loader
requires `mutating: true`, a non-safe target method, `restore:`, and all of the
usual mutation gates. A run is refused unless `--allow-mutations` is present,
the target host is loopback or listed by `--allow-host`, and the scan is not
`--read-only`. Every reset, snapshot, race request, and restore request goes
through `GuardedClient`; the synchronized path applies its read-only/path
allowlist, host allowlist, rate bucket, and cooldown.

Each round has a bounded lifecycle:

1. Run every `race.reset` request. Failure stops the run as
   `INCONCLUSIVE reset_failed`.
2. Read the declared ledger snapshot before the raced requests. Failure is
   `INCONCLUSIVE verify_unavailable`.
3. Send `race.requests` requests with the configured synchronization mode.
4. Read the ledger snapshot again and evaluate the invariant.
5. Run the required `restore:` block in a `finally` path. A failed restore is
   `ERROR restore_failed`, even if a finding was already observed.

`requests` defaults to 10 and is capped at 50. `rounds` defaults to 5, is capped
at 20, and a PASS requires at least five strong rounds. A round is strong when
the client-side release spread is at or below `max_spread_ms` (default 5 ms).

The invariant must declare at least one of:

- `max_successes`: accepted responses (responses in `success_status`) must be at
  most this value.
- `ledger`: `|final - initial| <= max_total_effect` and
  `final - initial == delta_per_success * accepted_count`. `delta_per_success`
  is signed; a debit is negative. This catches both double-effects and the
  “told failure but state moved” case.

With `race.idempotency.mode: same`, one key is reused for all requests and one
effect is required. With `mode: unique`, each request gets a fresh key and the
ledger bounds total effect. `mode: none` is the default.

## Synchronization modes

| Mode | Mechanism | Notes |
| --- | --- | --- |
| `last_byte` | One fresh HTTP/1.1 connection per request (TLS when needed); sends each request minus its final byte, waits on a barrier, writes all final bytes in one tight pass, then reads status lines. | Default. Measures release spread; no response bodies enter evidence. |
| `burst` | Existing concurrent request behavior after a barrier. | Legacy behavior; PASS carries note `weak_sync_mode` because release is scheduler-dependent. |
| `h2_single_packet` | Optional HTTP/2 mode: N streams on one connection, final empty DATA frame withheld, all final frames written together. | **Experimental, unverified against a real HTTP/2 server.** Requires the optional `h2` package (`pip install -r requirements-race.txt`) and ALPN `h2`. Falls back to `last_byte` with note `h2_unavailable` when unavailable. Coalescing limit is 1200 bytes; above it the run falls back with note `h2_coalesce_limit`. The fallback must not be reported as an h2 measurement. |

`last_byte` is HTTP/1.1 only. The h2 fallback is deliberate: a missing optional
dependency or a server that does not negotiate HTTP/2 must not turn a race check
into a false PASS.

## Verdicts

| Outcome | Meaning |
| --- | --- |
| `FAIL race_invariant_violated` | At least one round violated `max_successes`, the ledger equation, or the same-key idempotency requirement. Evidence includes rounds executed, strong rounds, violating rounds, hit rate, median spread, and accepted counts. |
| `PASS` note `no_violation_observed` | At least five strong rounds, at least half of all rounds strong, and no invariant violation. The report says “no violation observed in R rounds,” never “safe” or “not vulnerable.” |
| `INCONCLUSIVE weak_synchronization` | Fewer than five strong rounds, or fewer than half of all rounds strong. |
| `INCONCLUSIVE rate_limited` / `server_error` / `timeout` | Transport failures exceeded the threshold (25% of attempted raced requests by default); no invariant violation was observed. |
| `INCONCLUSIVE reset_failed` / `verify_unavailable` | Reset or ledger read-back did not produce a usable state observation. |
| `ERROR restore_failed` | Restore failed after the run; non-zero exit, rule named. |
| `SKIPPED mutation_blocked` | A mutation gate was missing; no race traffic was sent. |

A PASS is evidence about the tested window only. It does **not** prove the
absence of a race: the server may have a wider critical section, the test may
miss the interleaving, a CDN/WAF may coalesce or reject traffic, and network
jitter can make a weak release look strong. Treat `weak_synchronization` as a
failed experiment, not as a clean result.

## Worked example

```yaml
id: wallet-double-spend
name: Concurrent wallet debit must preserve the accounting invariant
severity: HIGH
owasp_category: API6:2023
cvss_score: 8.1
target_endpoints:
  - path: /wallet/spend
    method: POST
auth_contexts:
  primary: owner
  forbidden: other
mutating: true
body:
  amount: 10
race:
  requests: 10
  rounds: 5
  sync: last_byte
  identity: other
  reset:
    - {method: POST, path: /test/reset, auth: none}
  success_status: [200]
  max_spread_ms: 5
  invariant:
    max_successes: 1
    ledger:
      snapshot: {method: GET, path: /wallet, auth: none}
      path: balance
      delta_per_success: -10
      max_total_effect: 10
restore:
  - {method: POST, path: /test/reset, auth: none}
```

## Fixture corpus

The race fixtures run as a real uvicorn subprocess on an ephemeral loopback
port. The test skips only if binding is impossible. CI must not point these
tests at anything except that local fixture.

| Profile | Expected | Actual |
| --- | --- | --- |
| `wallet_race_vulnerable` | FAIL `race_invariant_violated` | FAIL `race_invariant_violated` |
| `wallet_race_vulnerable_narrow_deterministic` | FAIL `race_invariant_violated` | FAIL `race_invariant_violated` |
| `wallet_race_vulnerable_narrow_yield` | not asserted in pytest | excluded from pytest/corpus; yield-only timing study below |
| `wallet_race_safe` | PASS `no_violation_observed` | PASS `no_violation_observed` |
| `coupon_single_use_vulnerable` | FAIL `race_invariant_violated` | FAIL `race_invariant_violated` |
| `coupon_single_use_safe` | PASS `no_violation_observed` | PASS `no_violation_observed` |
| `idempotency_key_ignored` | FAIL `race_invariant_violated` | FAIL `race_invariant_violated` |
| `idempotency_key_honored` | PASS `no_violation_observed` | PASS `no_violation_observed` |
| `weak_sync` | INCONCLUSIVE `weak_synchronization` | INCONCLUSIVE `weak_synchronization` |
| `rate_limit_429_during_race` | INCONCLUSIVE `rate_limited` | INCONCLUSIVE `rate_limited` |
| `reset_failure` | INCONCLUSIVE `reset_failed` | INCONCLUSIVE `reset_failed` |
| `race_mutation_blocked` | SKIPPED `mutation_blocked` | SKIPPED `mutation_blocked` |
| `restore_failure` | ERROR `restore_failed` | ERROR `restore_failed` |

Reports contain counts, hashes, status counts, medians, and booleans only. They
do not contain object IDs, market/account values, tokens, idempotency keys, or
request/response bodies. `tests/test_race.py` scans every generated SARIF/JUnit
report for the fixture's balance value and identity tokens.

<!-- race-study:start -->
## Detection study

N=50 fresh runs per fixture/mode. Each run used 10 requests and 5 rounds.
The wide fixture (`wallet_race_vulnerable`) has a 30 ms check/write gap.
The narrow fixture (`wallet_race_vulnerable_narrow_yield`) has only
`await asyncio.sleep(0)` between the check and the write; it is
timing-dependent and is excluded from pytest and the corpus gate. CI uses
`wallet_race_vulnerable_narrow_deterministic` instead.

| Fixture | Mode | Runs | FAIL count | FAIL rate | Wilson 95% CI | Median release spread (ms) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `wallet_race_vulnerable` (wide (30 ms gap)) | `burst` | 50 | 50 | 100.0% | 92.9%–100.0% | 2.237580 |
| `wallet_race_vulnerable` (wide (30 ms gap)) | `last_byte` | 50 | 50 | 100.0% | 92.9%–100.0% | 0.152838 |
| `wallet_race_vulnerable_narrow_yield` (narrow (yield-only)) | `burst` | 50 | 2 | 4.0% | 1.1%–13.5% | 2.350920 |
| `wallet_race_vulnerable_narrow_yield` (narrow (yield-only)) | `last_byte` | 50 | 48 | 96.0% | 86.5%–98.9% | 0.174859 |

`last_byte` on the yield-only narrow fixture detected 48/50 runs (96.0%), **below 100%**.

The interval is a Wilson score interval for the observed FAIL count.
Median release spread is the median of each run's evidence field; it is
not a detection-rate estimate.

| Mode | Status |
| --- | --- |
| `h2_single_packet` | **not tested** — optional `h2` package is not installed; no h2 measurement was performed. |

<!-- race-study:end -->

## Safe use

- Sandbox or isolated lab only. Never run against production or a third-party
  service without explicit authorization.
- Keep `requests` small (10 is a sensible default) and `rounds` small. The hard
  caps are 50 and 20.
- Use a dedicated test account and reset endpoint. Race rounds intentionally
  mutate state; the restore block is not a substitute for a disposable tenant.
- Prefer loopback. A non-loopback host requires `--allow-host` and
  `--allow-mutations`; both are explicit opt-ins.
- Do not interpret a PASS as a security certification. Report it as “no
  violation observed in R rounds” and report the synchronization evidence.
