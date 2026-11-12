# Rules interface

```python
from pkg.rules import load_rules, run_rules

rules = load_rules(["rules/ownership.yaml"])
results = await run_rules(inventory, rules, guarded_client,
    contexts={
        "parent_user_a": {"Authorization": "Bearer ..."},
        "other_user": {"Authorization": "Bearer ..."},
    },
    variables={"account": {"id": "account-123"}})
```

Requires **PyYAML**. `load_rules(paths: iterable[str]) -> list[dict]` accepts a
single rule, a list of rules, or `{rules: [...]}` per YAML file. It uses a safe
loader, rejects duplicate mapping keys/IDs, unknown fields, non-JSON values,
invalid types and malformed rules with `ValueError`. File I/O errors propagate.
`run_rules` revalidates rules before making requests; invalid global rule,
context, variable or base-URL configuration raises `ValueError`.

## Experimental checks

BFLA is **validated on fixtures only; not yet benchmarked on real targets**.

`check: mass_assignment` and `check: business_limit` are **experimental, untested; require --experimental**.
They are rejected at load time unless `--experimental` is passed. The flag only
permits loading; all normal mutation gates, restore requirements, and
read-only/production blocking still apply.

## Exact YAML format

```yaml
id: account-ownership
name: Another user cannot read the same account
severity: high
owasp_category: API1:2023
cvss_score: 8.1
target_endpoints:
  - path: /accounts/{account_id}
    method: GET
auth_contexts:
  primary: parent_user_a
  forbidden: other_user
parameters:
  path:
    account_id: "{{account.id}}"
  query:
    include: summary
  header:
    X-Request-Mode: audit
assertions:
  - type: status_code
    expected: 403
  - type: header
    name: Content-Type
    expected: application/json
  - type: body
    path: error.code
    expected: forbidden
  - type: body
    path: error.code
    exists: true
    value_type: string
  - type: body
    path: account.secret
    exists: false
```

Required metadata: `id`, `name`, `severity`, `owasp_category`, `cvss_score`.
IDs/names/categories are nonempty strings. Severity is one of `info`, `low`,
`medium`, `high`, `critical`; score is a finite JSON number in `[0, 10]`, not a
boolean. Severity is case-insensitive and normalized to lowercase in results.
`target_endpoints` and `assertions` are nonempty lists. Optional `remediation`
is a nonempty string copied into tracker ticket bodies only; it is never sent
to the target. Methods are uppercase HTTP methods. Paths/methods match inventory entries exactly; there
are no wildcards or automatic discovery attacks.

### CVSS 3.1 scoring

`cvss_score` is retained as a deprecated compatibility field; it is not used to
choose exit codes or the headline result. New results carry a computed `cvss`
object (`vector`, `score`, `rating`). A rule may override the default with a
justification:

```yaml
cvss:
  vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  justification: Internet-facing, pre-auth object destruction.
```

The vector must be a complete CVSS 3.1 base vector; malformed, duplicate,
missing, or non-3.1 vectors are rejected. Defaults are deliberately scoped to
the check's exploit model:

| `check_type` | Default vector | Rationale |
| --- | --- | --- |
| `bola` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | Authenticated cross-object read/write. |
| `state_change` | same as `bola` | Authenticated mutation of another principal's state. |
| `race` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | Integrity/availability loss after a concurrent business-flow check. |
| `caller_scope` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | Caller-scoped response with limited disclosure. |
| `shared_scope` | same as `caller_scope` | Shared catalogue response with limited disclosure. |
| `unauthenticated_access` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | No privileges required; high confidentiality impact. |

Reduced-confidence findings retain their CVSS score and carry `confidence`
separately. `cvss_score` should be treated as the old compatibility grade, not
as the authoritative score.

Optional `parameters` is a location mapping (`path`, `query`, `header`), each
containing name-to-JSON-value pairs. Optional `body` is an explicit JSON value:

```yaml
body:
  account_id: "{{account.id}}"
  amount: 100
```

An entire `{{dotted.name}}` placeholder preserves the variable's JSON type;
placeholders embedded in strings require scalar values. Variable lookup first
checks a literal dotted key, then traverses objects/zero-based array indexes.
Missing placeholders are errors. Variables are never interpreted as templates
recursively. Body assertion paths also use dot notation; `""` selects the root.
Body assertions support `expected`, boolean `exists`, and `value_type`
(`string`, `number`, `integer`, `boolean`, `object`, `array`, `null`). Multiple
checks in an assertion are ANDed. `exists: false` cannot include value checks.
Header comparison is case-insensitive for names, exact for values. JSON body
comparisons distinguish booleans from numbers. Assertions never echo actual or
expected values into results.

`auth_contexts` is optional. Named contexts must exist. Omit `primary` to skip
the baseline and disable dependency execution/state collection. Omit `forbidden`
to send the assertion request without context headers. If primary is supplied,
it must return 2xx before the forbidden request is sent. Authorization, Cookie,
Proxy-Authorization, Host, and headers used by either named context cannot be
shared rule parameter headers; put authentication in named contexts instead.
Contexts must not set Host. The runner passes `auth=None` and an empty Cookie
header when a context does not provide Cookie, preventing HTTPX cookie-jar state
from leaking between contexts. Use a transport with no default credential
headers; the supplied `pkg.guardrails.GuardedClient` meets this requirement.

## Inventory and input resolution

The input is the parser inventory specified by the caller:

```python
{
    "base_url": "https://api.example.test/v1",
    "endpoints": [{
        "path": "/accounts/{account_id}", "method": "GET",
        "operation_id": "getAccount",
        "parameters": [{"name": "account_id", "in": "path", "required": True,
                        "schema": {"type": "string"}}],
        "request_body": {},  # original, resolved OpenAPI requestBody
        "security": [], "response_fields": ["id"],
    }],
    "graph": [{"source": "createAccount", "target": "getAccount",
               "field": "id", "parameter": "account_id"}],
}
```

Swagger bodies must already be converted into OpenAPI `request_body.content`.
The runner does not infer credentials from `security`, fetch schemas, or use
`example`, schema defaults or fabricated IDs as input. Required path/query/header
parameters resolve from explicit rule parameters, then variables
(`path.name` / `query.name` / `header.name`, then `name`), then a graph edge.
Authentication headers can be supplied by the current context. Even undeclared
`{path}` placeholders are treated as required. Path substitutions are percent
encoded as a single segment; empty values and dot traversal are rejected.

A missing graph input runs only its declared source operation, recursively,
under the **primary context**. Only 2xx primary/dependency JSON responses are
stored, keyed by context name and operation ID, for this `run_rules` call.
Forbidden responses never update state. Graph fields accept dot paths; a bare
field also resolves through an envelope if exactly one matching nested field
exists. Cycles, ambiguous edges, missing operations, missing response fields,
non-2xx dependencies, depth over 16 or more than 32 dependency executions per
target fail closed. No graph activity occurs for already supplied inputs or
optional inputs. Dependencies get only declared parameter values, not extra
target parameters or the target's explicit body.

Required JSON bodies are resolved from explicit `body`, then `variables.body`.
Missing required object properties resolve from `variables['body.field']` (or
nested `variables.body.field`), then variable name/graph parameter name. Nested
objects and arrays are checked recursively for required inputs and basic JSON
types. Optional bodies are not invented. Unsupported required media types and
unresolved schemas fail closed. This is not a complete JSON Schema validator.
The exact resolved target path/query/body and shared headers are reused for the
primary and forbidden requests; only context headers change.

## Guarded transport and results

The supplied transport must implement:

```python
async def request(method, url, *, params, headers, follow_redirects=False, auth=None, json=...):
    ...  # json omitted when no body is present
```

Responses expose integer `status_code`, mapping `headers`, synchronous `.json()`.
All HTTP, including dependencies, goes through this transport. Redirect following
is explicitly disabled. `pkg.guardrails.UnsafeRequest` (including subclasses)
is recognized as a safety block (`skipped`); other request exceptions produce
`error`. The caller remains responsible for configuring the guarded client's
URL/network/write-safety policies.

One result is returned per rule target, in input order:

```python
{"rule_id": "account-ownership", "name": "...", "severity": "high",
 "owasp_category": "API1:2023", "cvss_score": 8.1,
 "path": "/accounts/{account_id}", "method": "GET",
 "fingerprint": "lp1:...", "path_template": "/accounts/{account_id}",
 "check_type": "bola", "identity_roles": ["other_user", "parent_user_a"],
 "cvss": {"vector": "CVSS:3.1/...", "score": 8.1, "rating": "high"},
 "status": "passed", "message": "All assertions passed.",
 "assertions": [{"index": 0, "type": "status_code", "passed": True}]}
```

`passed` means every assertion matched; `failed` means an assertion did not
match. Missing selected endpoints and safety blocks are `skipped`. Resolution,
context, baseline, transport and other execution problems are `error`, never
vulnerability findings. Results contain no expanded URLs, request headers,
input values, exception text or response bodies. Rules' own metadata is returned
unchanged, so do not place secrets in metadata.

## Disposable fixtures

Mutating rules may create their own disposable object instead of restoring an
existing one. These fields are strict: unknown keys, duplicate capture names,
unknown status codes and unresolved `when_defined` references are rejected at
load time.

```yaml
fixture:
  create:
    - identity: owner
      request:
        method: POST
        path: /api/v1/items
        body: {name: "{{gen.item_name}}"}
      capture:
        - {name: id, from: json, path: id}
      expect_status: [200, 201]
  cleanup:
    - identity: owner
      when_defined: fixture.id
      request:
        method: DELETE
        path: /api/v1/items/{{fixture.id}}
      ok_status: [200, 202, 204, 404]
capture:
  - {name: id, from: json, path: id}
variables:
  generated:
    - {name: item_name, pattern: "lp_{rand10}"}
```

`fixture.create` and `fixture.cleanup` are ordered lists. A create step uses a
named authentication context as `identity`; its `expect_status` defaults to any
2xx. A cleanup step defaults to `[200, 202, 204, 404]` and is skipped when its
`when_defined` variable was not captured. Cleanup always runs after an attempted
fixture creation, including after capture failure, an attack failure, or a kill
switch; cleanup requests bypass only the kill-switch check so they can remove
the disposable object. The remaining cleanup steps still run after one fails.

`capture` may also appear on the attack request. Captured values are available
as `{{fixture.<name>}}` in the attack, verify and cleanup requests. Generated
values are available as `{{gen.<name>}}` in the same places. `variables.generated`
patterns must start with `lp_` and use `{randN}` (N from 1 to 64) for lowercase
alphanumeric randomness; the `lp_` prefix lets operators find leftovers.

A mutating rule must still declare `restore:` when it changes pre-existing
state. `fixture.cleanup` satisfies the restore requirement only for objects
created by that rule's own fixture or attack; it does not authorize mutating
someone else's object. Every fixture, attack and verify request passes the
normal mutation gates: `--allow-mutations`, `--allow-host`, non-read-only mode,
the production hard block, the kill switch, `GuardedClient`, and scan headers.
Cleanup passes the same gates except that it is allowed to finish after a kill.

Fixture failures produce `ERROR fixture_failed` and the attack is never sent.
A missing capture path or header produces `ERROR capture_failed`; cleanup still
runs. Cleanup rejection or timeout produces `ERROR cleanup_failed` (exit code 2)
with only the rule ID in the message. Captured and generated values are never
written to results, SARIF, JUnit, tickets, DefectDojo, JSON logs, metrics or the
GitHub summary.

## Differential ABAC isolation extension

The rules above are the **legacy assertion schema**. A status-only rule remains
an exact status contract: `assertions: [{type: status_code, expected: 403}]`
accepts only `403` after its optional primary baseline. It neither accepts
hide-existence `404` responses nor establishes owner-specific leak evidence.

A differential ABAC rule is selected by `leak_detection`. It is a separate,
strict schema: a legacy rule requires nonempty `assertions`; a differential
rule has no `assertions`. The usual metadata, target, context, and parameter
rules still apply. Unknown fields are rejected, and there is no automatic
migration between the two schemas.

```yaml
# Complete differential shape used by rulesets/abac_isolation.yaml.
leak_detection:
  canaries: ["{{teen_id}}"]
  min_unique_leaf_values: 1
  ignore_fields: [detail]
controls:
  nonexistent_object: true
  unauthenticated: true
confirm: 2
```

### Strict fields and defaults

| Field | Required / type | Exact meaning |
| --- | --- | --- |
| `acceptable_status` | Optional nonempty list of unique integer `400..499` statuses, excluding `429`. Default: `[401, 403, 404]`. | An initial forbidden response in this deny set is **PASS** unless the unauthenticated control proves an owner-data leak. Controls still execute; denials alone need no confirmations. `404` is a valid hide-existence pattern. Overload/success statuses cannot be configured as denials. |
| `leak_detection` | Mapping; its presence opts into differential evaluation. | May contain only `canaries`, `min_unique_leaf_values`, and `ignore_fields`. Cannot be combined with legacy `assertions`. Other differential fields without this block are rejected. |
| `leak_detection.canaries` | Optional list of unique nonempty strings/templates. Default: `[]`. | Templates resolve from input `variables` using normal placeholder resolution and may yield any scalar JSON value, never an object/array. These are comparison **values**, not response-field paths. Supply values known to occur only in the owner's object. A canary counts only if found in the baseline, not ignored, and absent from the nonexistent response. |
| `leak_detection.min_unique_leaf_values` | Optional positive integer. Default: `2`. | Minimum distinct scalar values shared by primary and forbidden JSON responses **after subtracting** every value also seen in the nonexistent response. Repeated leaves count once; boolean/number types remain distinct. Any single qualifying canary independently satisfies the leak criterion. |
| `leak_detection.ignore_fields` | Optional list of unique nonempty dot paths. Default: `[]`. | Excludes matching subtrees from **all** comparisons, including overlap, canaries, public equality, and soft-deny shape. Paths use object keys and zero-based array indexes, e.g. `metadata.request_id`, `rows.0.timestamp`. No wildcard/JSONPath syntax. |
| `controls` | Optional mapping containing only booleans `nonexistent_object` and `unauthenticated`. | When `leak_detection` is present, both controls default to `true`; omitted keys also default to `true`. |
| `confirm` | Optional integer in `[0, 100]` (booleans rejected). Default: `2`. | Additional identical requests with the leaking identity (forbidden or unauthenticated) for a would-be FAIL only. Every repeat must reproduce stable owner-specific evidence. `0` disables repeats; the upper bound prevents accidental unbounded traffic. PASS and ambiguous outcomes are not repeated. |
| `pagination` | Optional `{param: string, max_pages: 1..100}`. | Sets integer query values `1..max_pages`; every page uses the guarded client and is independently evaluated. Any FAIL takes priority, then ERROR. Ambiguous pages without an owner canary do not block PASS after an owner-canary-positive page has been tested successfully; other inconclusives remain. Without such a page, ambiguity stays INCONCLUSIVE. This is bounded page-number traversal, not cursor/link discovery. |
| `require_primary_canary` | Optional boolean, default `false`. | Requires the initial primary response to contain a configured canary; otherwise ERROR `baseline_missing_canary`. Use for list/profile checks that must prove the owner sees a non-empty owned result. |
| `scope` | Optional `object`, `caller`, or `shared`; default `object`. | Selects the evidence model. `object` is the existing object-isolation contract. `caller` means the endpoint returns data selected by the requesting identity. `shared` means a catalogue/feed intentionally common to authenticated identities. |
| `require_owner_canary_in_baseline` | Optional boolean, default `false`; required `true` for `scope: caller`. | Prevents a caller-scoped PASS from being vacuous: the owner baseline must actually contain one of the declared canaries. A caller rule must also declare at least one canary. |
| `spec_check` | Optional `strict` or `warn`; CLI default is `strict`. | Per-rule override of `--spec-check`. `strict` skips an endpoint absent from the loaded spec; `warn` executes a synthetic endpoint record and attaches `spec_drift` to the result/report. |

The runner resolves canaries before any selected-target HTTP. Both named
`primary` and `forbidden` contexts are required and must have different names.
A primary 2xx baseline is mandatory; non-2xx, baseline timeout, resolution,
configuration, and non-timeout transport failures are ERROR, not findings.
The comparison ignores shared/static values using the nonexistent control.
If that control is unavailable/disabled/non-JSON, overlap alone is insufficient:
only an explicit qualifying canary can establish a leak, at reduced confidence.

A JSON nonexistent-object control is **invalid** when it returns 2xx and either
shares at least `min_unique_leaf_values` distinct scalar values with the primary
baseline or contains any configured canary, after `ignore_fields` exclusions.
It must not subtract values from owner/forbidden overlap or establish a soft deny. An initial forbidden status in
`acceptable_status` still yields PASS. For forbidden 2xx, invalid control yields
INCONCLUSIVE with reason `invalid_control`, except that an explicit owner canary
present in the baseline and forbidden response but **absent from the control**
can independently establish FAIL, with reduced confidence and the usual
confirmation requirement. A canary also exposed by the control is not
owner-specific evidence. Identical public data may establish `public_endpoint`
only without owner-specific evidence or a canary in the invalid control;
an invalid owner-like control otherwise remains `invalid_control`.

### Controls, read-only operation, and confirmation

Every baseline, dependency, forbidden, control, and confirmation request uses
the same `GuardedClient`, rate bucket, cooldown, and read-only policy. Use
`--read-only` for non-mutating scans: mutations are blocked unless their exact
method/resolved path is allowlisted. Without it, differential policies may
repeat mutations, so select only authorized test endpoints. A state-changing
GET remains unsafe despite its method. Confirmations reuse exact original
path/query/body inputs; neither forbidden nor control responses update state.

| Control | Behavior |
| --- | --- |
| `nonexistent_object` | Replays the forbidden identity with a generated candidate ID. Supports one unambiguous path/query `id` or `*_id` parameter (otherwise a single path parameter), schema-declared UUID/string/integer types, bounds, and supported string patterns. Multiple IDs, unknown/unsupported types, enums, or unsatisfied constraints skip the control and reduce confidence. UUIDs/integers are randomized; string candidates preserve existing length/separators or known prefixes and are checked against the pattern. Candidates cannot be proven absent; only values from a valid control are treated as shared. Owner-like 2xx controls produce `invalid_control` as described above. Non-JSON control bodies are not usable subtraction evidence. |
| `unauthenticated` | Replays the original request with no context headers, `auth=None`, and an empty Cookie header to prevent cookie-jar reuse. A 2xx containing an owner canary, or sufficient baseline overlap with a valid nonexistent control, is FAIL `unauthenticated_leak` even if the authenticated forbidden request was denied. `public_endpoint` PASS requires identical unauthenticated/forbidden data **and no owner-specific evidence**. |

### Control precedence

A nonexistent-object control that returns `5xx`, `429`, or times out is
**unusable**, not a verdict-level server error. With an unusable control:

- a reproducible explicit owner canary in the forbidden `2xx` response is a
  reduced-confidence `FAIL` / `leak_detected` with note `control_unusable`;
- without that canary the result is `INCONCLUSIVE` / `control_unusable`.

A server error on the forbidden request or on a confirmation remains
`INCONCLUSIVE` / `server_error`. Generic overlap is never used when the control
could not establish what is generic.

### Rule-declared scope

`scope: caller` evaluates only the owner/other responses. A non-empty other
response is `PASS` with note `caller_scoped` when it has no owner canary and no
unique overlap at the configured threshold; a reproduced canary/overlap is
`FAIL` / `leak_detected`. An empty or unparseable response is
`INCONCLUSIVE` / `ambiguous_2xx`. The owner baseline must contain a declared
canary, enforced by `require_owner_canary_in_baseline: true`.

`scope: shared` is for catalogues and feeds. It is `PASS` with note
`shared_data` when the other response and the owner baseline contain no owner
canary. A canary in the other response is a reproduced `FAIL` /
`leak_detected`; a baseline canary that is absent from the other response is
`INCONCLUSIVE` / `ambiguous_2xx`.

### Spec drift

`--spec-check strict` (default) skips a selected path absent from the loaded
inventory with `endpoint_absent` and tells the operator to use
`--spec-check warn`. In `warn` mode the rule executes against a synthetic
endpoint record, and the result carries `spec_drift: <path>`. JUnit exposes it
as a `ledgerprobe.spec_drift` property and SARIF emits a warning notification.

A would-be FAIL requires `confirm` additional observations. Every repeat must
retain a qualifying original canary or all original overlap values (with at
least the configured minimum). Missing/changed evidence or denial on a repeat yields
INCONCLUSIVE `not_reproducible`. A 429/5xx/timeout on a control or confirmation
yields its specific inconclusive reason; repeats stop on overload/timeouts
rather than hammering the target. GuardedClient still applies Retry-After.

### Differential verdicts and reason codes

Results retain lowercase `status` for compatibility. Differential results also
carry uppercase `verdict`, `confidence` (`high` or `reduced`), and privacy-safe
`evidence`. Every non-PASS, including legacy failures/errors and safety skips,
has a machine-readable `reason`. PASS annotations use `note`, not `reason`.

| Verdict | Reason code | Exact outcome |
| --- | --- | --- |
| `PASS` | — | Forbidden response is in `acceptable_status` and controls show no anonymous owner-data leak. |
| `PASS` | note: `public_endpoint` | Unauthenticated 2xx has identical JSON data to the forbidden response, without owner-specific evidence. |
| `PASS` | note: `soft_deny` | Forbidden 2xx has the same JSON paths/types as the nonexistent response, without leak evidence (values may differ). |
| `FAIL` | `leak_detected` | Forbidden 2xx has a unique owner canary or sufficient unique overlap, and all configured repeats reproduce stable evidence. |
| `FAIL` | `unauthenticated_leak` | The unauthenticated control exposes an owner canary or enough owner-specific baseline overlap with a valid nonexistent control. |
| `INCONCLUSIVE` | `rate_limited` | Forbidden/control/confirmation response is 429. |
| `INCONCLUSIVE` | `server_error` | Forbidden or confirmation response is 5xx. |
| `INCONCLUSIVE` | `control_unusable` | Nonexistent-object control is 5xx/429/timeout without a reproducible owner canary. |
| `INCONCLUSIVE` | `timeout` | Forbidden/control/confirmation request times out. |
| `INCONCLUSIVE` | `not_reproducible` | Candidate evidence does not reproduce on every required confirmation. |
| `INCONCLUSIVE` | `ambiguous_2xx` | Successful response is neither public nor a soft deny and has insufficient unique leak evidence. |
| `INCONCLUSIVE` | `invalid_control` | Nonexistent-object control returns owner-like 2xx data or a canary; no independent, reproducible owner canary can prove a leak. No soft-deny PASS is permitted; public classification requires no owner-specific evidence or control canary. |
| `PASS` | note: `caller_scoped` | Other identity received a non-empty 2xx caller-scoped response with no owner evidence. |
| `PASS` | note: `shared_data` | Other identity received shared non-owner data with no owner canary in either baseline or response. |
| `INCONCLUSIVE` | `unexpected_status` | Forbidden response is neither 2xx nor an accepted denial/overload status (e.g. redirect). |
| `ERROR` | `baseline_not_2xx` / `baseline_timeout` / `baseline_missing_canary` | Primary baseline failed, timed out, or lacked required owner evidence. |
| `ERROR` | `execution_error` / `invalid_canary` | Resolution/context/transport problem, or canary resolves to a non-scalar. |
| legacy `FAIL` | `assertion_failed` | Legacy assertions did not all match; no differential traffic is added. |
| existing `SKIPPED` | `safety_blocked` / `endpoint_absent` | Guard blocked a request, or strict spec check found the selected endpoint absent. |

A 429/5xx/timeout/non-reproducible candidate is never a vulnerability finding.
INCONCLUSIVE exits **0** by default (even when every executed check is
inconclusive); `--fail-on-inconclusive` makes it exit **1**. FAIL exits **1**;
ERROR, configuration failure, or all-skipped scans exit **2**, taking priority.
JUnit represents INCONCLUSIVE as skipped with a message/reason. SARIF emits a
`level: note`, `kind: review` result without security-rule severity metadata,
not a security alert. HIGH/CRITICAL webhooks still send only FAIL findings.

### CWE classification and exports

Results, SARIF properties/taxa, and DefectDojo Generic Findings Import records carry
one deterministic CWE: object/BOLA access, state change by another identity, and
caller/shared-scope leaks map to CWE-639; unauthenticated access maps to CWE-306;
and race checks map to CWE-362. DefectDojo exports only FAIL or suppressed findings.
A suppressed finding is emitted as `active: false, false_p: true`; PASS,
INCONCLUSIVE, and ERROR are deliberately not DefectDojo findings. The exporter uses
only path templates, fingerprints, rule metadata, CVSS, CWE, and remediation; it
never includes evidence values or expanded object IDs.

### Evidence privacy and compatibility

Differential evidence contains only counts, hashes, HTTP statuses, and boolean
control/reproduction flags. It never contains raw canary values, resolved input
values, request or response bodies, headers, URLs, exception text, or raw field
paths. Hashes fingerprint JSON paths/types only, not scalar values or
low-entropy object IDs. Reporters allowlist evidence fields before exporting
SARIF/JUnit properties; raw observations remain local to verdict evaluation.

`rulesets/legacy_status_only.yaml` preserves the original policy exactly: the
same metadata, contexts, path input, target, and one `403` status assertion.
Use it for the legacy assertion schema. `rulesets/abac_isolation.yaml` is the
differential read-only example: it has no assertions, resolves `{{teen_id}}` as
a scalar canary, and uses two confirmation repeats. A legacy-only runner must
reject differential fields rather than silently downgrade the policy.

## Race-condition extension

Mutating rules may add a strict `race:` block (documented in `docs/RACE.md`).
Race rules still require `mutating: true`, a non-safe target method, `restore:`,
and the normal `--allow-mutations` / `--allow-host` / non-`--read-only` gates.
The block supports bounded `requests` (default 10, max 50), `rounds` (default 5,
max 20), `sync` (`last_byte`, `burst`, or optional `h2_single_packet`),
`identity`, required `reset:`, `success_status`, optional `idempotency`, and a
required `invariant` with `max_successes` and/or a signed `ledger` check.

`h2_single_packet` is **experimental and unverified against a real HTTP/2
server**. It requires the optional `h2` package and ALPN `h2`; when unavailable
it falls back to `last_byte` with `h2_unavailable`, and that fallback must not
be reported as an h2 result. The h2 coalescing limit is 1200 bytes.

Every reset, snapshot, race request, and restore request uses the same
`GuardedClient`; `GuardedClient.send_synchronized()` applies the read-only path
policy, host allowlist, rate bucket, and cooldown. Reset failure is
`INCONCLUSIVE reset_failed`; snapshot failure is `verify_unavailable`; an
invariant violation is `FAIL race_invariant_violated`; fewer than five strong
rounds (or fewer than half) is `INCONCLUSIVE weak_synchronization`; restore
failure is `ERROR restore_failed`. A PASS is reported as
`no_violation_observed`, never as proof of absence.
