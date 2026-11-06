# Operations and SOC runbook

## CI tool versions

Gitleaks is pinned to **8.28.0** in `.github/workflows/ci.yml`. CI downloads the
v8.28.0 Linux x64 release archive and verifies its SHA-256 checksum before
running the full-history scan.

## Identifying scan traffic

Every target request carries `User-Agent: LedgerProbe/<version>` and
`X-LedgerProbe-Run: <run_id>`. The run ID defaults to a random value; CI can pass
a pipeline ID with `--run-id`. Non-secret SOC correlation headers can be added
under top-level `extra_headers` in `ledgerprobe-auth.yaml` or with
`--extra-header NAME:VALUE`. Header names or values that look like credentials
are rejected. Allowlist these headers and the authorized source ranges at the
edge; they are identification, not authentication.

## JSON logs

`--log-format json` reserves stdout for one JSON object per line. Each check
event has: `ts`, `level`, `event`, `run_id`, `rule_id`, `fingerprint`, `verdict`,
`reason`, `duration_ms`, `http_status`, `target`, `tool_version`, and
`path_template`. A final `run_summary` event adds `status_counts`,
`verdict_counts`, and `inconclusive_rate`. Paths are templates; expanded object
IDs and evidence values are not logged. All text passes through the secret
redactor before serialization.

For Splunk, ingest stdout as `_json` with `run_id` as a correlation field. For
Elastic, use the JSON codec and index on `event`, `run_id`, and `fingerprint`.
Keep stderr separate: configuration and delivery failures remain human-readable
there.

## Prometheus metrics

`--metrics-file /path/ledgerprobe.prom` writes text-format metrics suitable for
node_exporter's textfile collector:

```text
ledgerprobe_verdict_count{verdict="FAIL"} 2
ledgerprobe_inconclusive_ratio 0.1
ledgerprobe_run_duration_seconds 4.2
ledgerprobe_tracker_errors_total 0
```

Use a per-run temporary file and atomically move it into the collector directory.

## Stopping a run

Create the file named by `--kill-file`. The client checks it before every
request and between race rounds. The active rule stops, pending restore steps
run, remaining rules are `SKIPPED` with reason `kill_switch`, reports and metrics
are written, and the process exits **4**. Remove the file before the next run.
Deleting the run's process is a last resort because it can strand mutated test
state.

## Environment gates

`--environment` defaults to `lab`.

| Environment | Read-only | Mutating / race | Identity environment |
| --- | --- | --- | --- |
| `lab` | allowed | allowed only with existing mutation gates | must equal `lab` |
| `staging` | allowed | allowed only with existing mutation gates | must equal `staging` |
| `production` | requires `--allow-production-read-only` | hard-blocked as `mutation_blocked_production` | must equal `production` |

## Safe-use checklist

- Use only authorized targets and test identities in staging.
- Start read-only; review the exact mutation allowlist before enabling writes.
- Account for login/token side effects: SMS/OTP cost, notifications, lockout,
  and session creation.
- Pin the run ID and keep `--kill-file` available during the run.
- Treat production as read-only; do not expect an override for race or mutation.
- Review [AUTH.md](AUTH.md), [RACE.md](RACE.md), and [INTEGRATIONS.md](INTEGRATIONS.md).
