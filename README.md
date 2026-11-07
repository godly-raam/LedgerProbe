# LedgerProbe

[![CI](https://github.com/godly-raam/LedgerProbe/actions/workflows/ci.yml/badge.svg)](https://github.com/godly-raam/LedgerProbe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

LedgerProbe is an API authorization and business-logic testing engine. It reads an OpenAPI, Swagger, or Postman document plus YAML policies, then compares an owner's successful baseline with a forbidden identity, negative controls, unauthenticated controls, and owner-specific canaries before it emits a verdict. The difference is the evidence discipline: differential checks with controls, PASS / FAIL / INCONCLUSIVE verdicts, and reports that retain only allowlisted metadata. `mock-bank-api` is a local test fixture, not the product.

## Results first

Counts are `TP/FP/TN/FN/INC_vuln/INC_safe`. `INCONCLUSIVE` is never counted as correct. The v1 number is the pre-tuning result; **v2 and v3 rules were authored after viewing earlier results**. This is a same-author benchmark with no confidence intervals and a small sample: **23 cases across 18 distinct endpoints**. VAmPI contributes 13 cases over 8 endpoints in both target modes; crAPI contributes 10 cases. Legacy rows were recorded at v1 and not re-run for v2/v3. The v3 differential row was re-run.

| Target | Mode | v1 | v2 | v3 |
| --- | --- | --- | --- | --- |
| VAmPI | `legacy_strict` | 8/5/0/0/0/0 | 8/5/0/0/0/0 | 8/5/0/0/0/0 |
| VAmPI | `legacy_lenient` | 8/4/1/0/0/0 | 8/4/1/0/0/0 | 8/4/1/0/0/0 |
| VAmPI | `differential` | 7/0/3/0/1/2 | 7/0/4/0/1/1 | 8/0/5/0/0/0 |
| crAPI | `legacy_strict` | 4/4/0/0/1/1 | 4/4/0/0/1/1 | 4/4/0/0/1/1 |
| crAPI | `legacy_lenient` | 5/4/1/0/0/0 | 5/4/1/0/0/0 | 5/4/1/0/0/0 |
| crAPI | `differential` | 3/0/1/0/2/4 | 5/0/4/0/0/1 | 5/0/4/0/0/1 |

`legacy_strict` is the engine's exact-403 assertion. `legacy_lenient` is a benchmark-harness policy that passes `{401,403,404}`; it is not an engine mode. `differential` adds scoped owner/other comparison, canaries, controls, and confirmation. `crapi-order-object` is a **reduced-confidence FAIL** in v2 and v3 because its nonexistent-object control returned 500 and could not separate generic overlap from owner data. See [`docs/BENCHMARK.md`](docs/BENCHMARK.md) for the per-case table, target-mode and ground-truth columns, object-scoped cut, provenance, and determinants.

## Quick start

Docker image:

```bash
docker build -t ledgerprobe:local .
docker run --rm ledgerprobe:local --version
```

Python install:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

Five-minute lab fixture demo. Start the fixture, then prepare the spec and auth references. The demo password is read from `LEDGERPROBE_DEMO_PASSWORD` at scan time and is not written to disk:

```bash
export LEDGERPROBE_DEMO_PASSWORD=demo1234
docker compose up -d --build --wait mock-bank-api
curl --fail http://127.0.0.1:8000/health
.venv/bin/python -m examples.prepare_demo \
  --base-url http://127.0.0.1:8000 --out .demo/quickstart
```

Then run the read-only differential policy. The lab is intentionally vulnerable, so the scan exits **1** after reporting a FAIL:

```bash
.venv/bin/python ledgerprobe.py \
  --spec .demo/quickstart/openapi.json \
  --base-url http://127.0.0.1:8000 \
  --rules rulesets/abac_isolation.yaml \
  --auth .demo/quickstart/ledgerprobe-auth.yaml \
  --inputs .demo/quickstart/inputs.json \
  --read-only --max-rps 5 \
  --sarif .demo/quickstart/results.sarif \
  --junit .demo/quickstart/results.xml
```

Real output from this workspace:

```text
[*] 11 endpoints; 0 dependency candidates
[failed] bola-cross-tenant-access GET /api/v1/family/allowance/{teen_id}: Forbidden response reproducibly exposed owner-object evidence.
[+] SARIF: .demo/quickstart/results.sarif; {'failed': 1}
```

Stop the fixture with `docker compose down`.

## How a verdict is reached

```text
owner baseline request
  |-- not 2xx / missing identity ---------------------> ERROR or SKIPPED
  v
forbidden request
  |-- 401 / 403 / 404 (accepted denial) --------------> PASS
  |-- 2xx
        |-- negative control (nonexistent object) ----+
        |-- unauthenticated control -----------------+
        |-- owner canaries / unique-value overlap ----+
        |-- confirmation repeats (default 2) ---------+
        v
   reproducible owner-specific evidence + usable control -> FAIL
   generic 2xx / empty / HTML / unstable / control invalid -> INCONCLUSIVE
```

Reason codes include `leak_detected`, `unauthenticated_leak`, `state_changed_by_other`, `no_effect`, `ambiguous_2xx`, `invalid_control`, `control_unusable`, `weak_synchronization`, `rate_limited`, `timeout`, `server_error`, `not_reproducible`, and `restore_failed`. A FAIL is a policy failure; INCONCLUSIVE is not treated as a pass and normally exits 0 unless `--fail-on-inconclusive` is set.

## Check types

| Check | Status |
| --- | --- |
| BOLA / IDOR | Benchmarked on VAmPI and crAPI. |
| State-changing BOLA | Benchmarked on VAmPI (owner-login probe and restore). |
| Race conditions | Fixtures only; no live VAmPI/crAPI race benchmark. |
| BFLA | Fixtures only; not yet benchmarked on real targets. |
| Mass assignment | **Experimental, untested**; requires `--experimental`. |
| Business limits | **Experimental, untested**; requires `--experimental`. |

Race synchronization supports `burst`, HTTP/1.1 `last_byte`, and an optional `h2_single_packet` mode that is **not tested** because `h2` is not installed here. See [`docs/RACE.md`](docs/RACE.md) for the N=50 fixture study and honest detection rates. BFLA and the experimental checks are documented in [`docs/CHECKS_NEW.md`](docs/CHECKS_NEW.md).

## Integrations

| Integration | How it was tested |
| --- | --- |
| SARIF 2.1.0 | Reporter tests, including fingerprints, rule metadata, and official-schema validation when the schema is available. |
| JUnit XML | Reporter tests for PASS, FAIL, INCONCLUSIVE, ERROR, suppressions, and XML escaping. |
| DefectDojo export | JSON exporter is schema-tested. **Upload is not implemented.** |
| Jira / Linear | `MockTransport` tests cover request shapes, plan/apply, deduplication, retries, cooldowns, and flood caps. No live tenant is tested. |
| Slack | Mocked digest test; one metadata-only message per apply run. No live workspace is tested. |
| GitHub Action | Composite action and workflow YAML are parsed and tested. No marketplace/live-run test is documented. |
| Docker image | Built and smoke-tested locally with `--version`, `diff`, and `drift`. |

See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for configuration and [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for operational controls.

## Safety model

- **Mutation gates:** mutating rules require `mutating: true`, `--allow-mutations`, a loopback or explicitly allowed host, no `--read-only`, and a `restore:` block.
- **Host allowlist:** target and identity hosts are checked before HTTP; redirects and automatic retries are disabled.
- **Environment gating:** production read-only requires an explicit flag; production mutation/race is hard-blocked.
- **Kill switch:** `--kill-file` stops before the next request, runs pending restores, skips remaining rules, writes reports, and exits 4.
- **Identification:** every request carries `User-Agent: LedgerProbe/<version>` and `X-LedgerProbe-Run: <run_id>`.
- **Secrets:** tokens and secrets are never written to disk or reports by the engine; lab fixtures may use static test credentials.

## Limitations

- INCONCLUSIVE means the evidence did not support PASS or FAIL. It is not a clean result.
- The benchmark is 23 cases across 18 endpoints, same-author, source-derived, and has no confidence intervals.
- Race results are local fixture measurements; a PASS only means no violation was observed in the tested rounds.
- Scope declarations (`object`, `caller`, `shared`) are supplied by the rule author and are not independently verified.
- Host allowlisting and mutation gates are not a network sandbox; scan only systems you are authorized to test.
- `h2_single_packet` remains experimental and untested against a real HTTP/2 server.

## Repository layout, development, test commands, and license

```text
ledgerprobe.py       CLI entry point
pkg/                 parser, rules, verdicts, guardrails, reporters, integrations
rulesets/            reviewed example policies
examples/            synthetic lab setup and auth input template
tests/               engine, fixture, corpus, and end-to-end tests
benchmark/           frozen ground truth, benchmark harness, race study
mock-bank-api/       local FastAPI/SQLite test fixture
dashboard/           Next.js report and benchmark console
```

```bash
python -m pip install -e ".[dev]"
python -m pytest tests -q
python -m pytest benchmark/tests -q
python tests/corpus_metrics.py
```

The corpus gate must remain at zero false positives and zero false negatives. `ledgerprobe --version` reports `1.1.0`. Licensed under the [MIT License](LICENSE).
