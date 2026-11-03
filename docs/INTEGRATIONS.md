# Ticket integrations

LedgerProbe's scan path stays independent of ticketing. Scan reports are written
before any tracker or Slack call. Tracker failures never change findings or
verdicts. Ticket mode defaults to **dry-run**, which prints planned actions with
only fingerprints and rule IDs and performs no network I/O.

## Configuration

Create `ledgerprobe-integrations.yaml`. The loader rejects unknown fields,
inline credentials, unsafe target labels, and non-HTTPS endpoints (HTTP is
allowed only for loopback tests). Secrets are referenced only by environment
variable name.

### Jira Cloud REST v3

```yaml
schema_version: ledgerprobe-integrations/1
tracker:
  provider: jira
  base_url: https://your-tenant.atlassian.net
  project: SEC
  issue_type: Task
  token_env: JIRA_API_TOKEN
  email_env: JIRA_EMAIL
  target_label: staging-api
  labels: [security]
  components: [api]
  assignee: security-oncall
  priority_map:
    critical: Highest
    high: High
    medium: Medium
    low: Low
    none: Lowest
  reopen_transition: Reopen
  resolved_transition: Done
  auto_close: false
  comment_cooldown_days: 7
  max_new_tickets_per_run: 20
  max_api_calls: 100
  retry_attempts: 3
  timeout_seconds: 10
slack:
  webhook_url_env: LEDGERPROBE_SLACK_WEBHOOK
```

`JIRA_API_TOKEN` and `JIRA_EMAIL` are read at runtime. The email is used for
Jira Basic authentication; without it the token is sent as a Bearer token.

### Linear GraphQL

```yaml
schema_version: ledgerprobe-integrations/1
tracker:
  provider: linear
  endpoint: https://api.linear.app/graphql
  team_id: "00000000-0000-0000-0000-000000000000"
  token_env: LINEAR_API_KEY
  target_label: staging-api
  labels: [security]
  assignee: "linear-user-id"
  state_open_id: "linear-todo-state-id"
  state_resolved_id: "linear-done-state-id"
  auto_close: false
  max_new_tickets_per_run: 20
slack:
  webhook_url_env: LEDGERPROBE_SLACK_WEBHOOK
```

Linear labels are created on demand unless `label_ids` maps names to existing
IDs. The GraphQL mutation sends the generated `lp-...` and `lp-target-...`
labels, title, body, priority, assignee, and team. Jira sends labels,
components, assignee, and the CVSS-derived priority. Neither provider receives
tokens, object IDs, payloads, markers, response bodies, or balances.

## Lifecycle

```text
FAIL finding
  |-- no ticket --------------------------------> create
  |-- open ticket + material change -----------> one comment (7-day cooldown)
  |-- closed ticket ----------------------------> reopen + lp-regression + comment
  |-- PASS + open ticket -----------------------> retest-passed comment
  |     `-- auto_close and 2 marked runs ------> resolve
  `-- suppressed --------------------------------> no create; one existing-ticket comment

INCONCLUSIVE / ERROR / SKIPPED ------------------> no ticket action; digest counts only
```

The dedup key is `(fingerprint, target_label)`. The ticket carries the
`lp-<16 hex>` label, `lp-target-<slug>`, and a first-line marker:

```text
ledgerprobe-fingerprint: lp1:...; target: staging-api
```

Lookup is by labels first and description marker second; titles are never used
for identity. A post-create re-query handles the best-effort create race: if two
tickets share a key, the oldest is kept, the newer gets a link comment and
`lp-duplicate`. This is not a transactional guarantee across CI runners.

The flood guard creates at most `max_new_tickets_per_run` individual tickets;
beyond that it creates one summary ticket with the omitted count and rule IDs
and emits a warning. A tracker error is a warning unless
`--fail-on-tracker-error` is set, in which case the scan exits 3 after reports
are written.

## Commands and CI

```bash
# No network. Prints create/comment/reopen/noop plans with fingerprints and rule IDs.
python ledgerprobe.py --spec openapi.yaml --rules rulesets/abac_isolation.yaml \
  --tickets dry-run --integrations ledgerprobe-integrations.yaml

# Explicitly permits tracker and Slack writes.
python ledgerprobe.py --spec openapi.yaml --rules rulesets/abac_isolation.yaml \
  --tickets apply --integrations ledgerprobe-integrations.yaml \
  --fail-on-tracker-error

# Disable ticket processing entirely.
python ledgerprobe.py --spec openapi.yaml --rules rulesets/abac_isolation.yaml --tickets off
```

GitHub Actions should use dry-run on pull requests and apply only on `main`:

```yaml
- name: LedgerProbe ticket dry-run
  if: github.event_name == 'pull_request'
  env:
    JIRA_API_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
    JIRA_EMAIL: ${{ secrets.JIRA_EMAIL }}
  run: python ledgerprobe.py --spec openapi.yaml --rules rulesets/abac_isolation.yaml --tickets dry-run

- name: LedgerProbe ticket apply
  if: github.ref == 'refs/heads/main'
  env:
    JIRA_API_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
    JIRA_EMAIL: ${{ secrets.JIRA_EMAIL }}
    LEDGERPROBE_SLACK_WEBHOOK: ${{ secrets.LEDGERPROBE_SLACK_WEBHOOK }}
  run: python ledgerprobe.py --spec openapi.yaml --rules rulesets/abac_isolation.yaml --tickets apply --fail-on-tracker-error
```

The digest is one Slack message per apply run: new, regressed, resolved,
suppressed, inconclusive, and error counts, the CI run URL when available, and
up to ten ticket links. It contains no evidence.

## Suppression approval

[`CODEOWNERS`](../.github/CODEOWNERS) requires the security owner to review
`.ledgerprobe-suppressions.yaml` and `rulesets/`. A merged PR is the approval
record for a suppression; direct unreviewed changes to `main` are out of
policy. This is review process, not an authenticated in-tool approval.
