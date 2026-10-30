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
`target_endpoints` and `assertions` are nonempty lists. Methods are
uppercase HTTP methods. Paths/methods match inventory entries exactly; there
are no wildcards or automatic discovery attacks.

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
 "status": "passed", "message": "All assertions passed.",
 "assertions": [{"index": 0, "type": "status_code", "passed": True}]}
```

`passed` means every assertion matched; `failed` means an assertion did not
match. Missing selected endpoints and safety blocks are `skipped`. Resolution,
context, baseline, transport and other execution problems are `error`, never
vulnerability findings. Results contain no expanded URLs, request headers,
input values, exception text or response bodies. Rules' own metadata is returned
unchanged, so do not place secrets in metadata.

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
| `acceptable_status` | Optional nonempty list of unique integer `400..499` statuses, excluding `429`. Default: `[401, 403, 404]`. | An initial forbidden response in this deny set is **PASS**, without control or confirmation requests. `404` is a valid hide-existence pattern. Overload/success statuses cannot be configured as denials. |
| `leak_detection` | Mapping; its presence opts into differential evaluation. | May contain only `canaries`, `min_unique_leaf_values`, and `ignore_fields`. Cannot be combined with legacy `assertions`. Other differential fields without this block are rejected. |
| `leak_detection.canaries` | Optional list of unique nonempty strings/templates. Default: `[]`. | Templates resolve from input `variables` using normal placeholder resolution and may yield any scalar JSON value, never an object/array. These are comparison **values**, not response-field paths. Supply values known to occur only in the owner's object. A canary counts only if found in the baseline, not ignored, and absent from the nonexistent response. |
| `leak_detection.min_unique_leaf_values` | Optional positive integer. Default: `2`. | Minimum distinct scalar values shared by primary and forbidden JSON responses **after subtracting** every value also seen in the nonexistent response. Repeated leaves count once; boolean/number types remain distinct. Any single qualifying canary independently satisfies the leak criterion. |
| `leak_detection.ignore_fields` | Optional list of unique nonempty dot paths. Default: `[]`. | Excludes matching subtrees from **all** comparisons, including overlap, canaries, public equality, and soft-deny shape. Paths use object keys and zero-based array indexes, e.g. `metadata.request_id`, `rows.0.timestamp`. No wildcard/JSONPath syntax. |
| `controls` | Optional mapping containing only booleans `nonexistent_object` and `unauthenticated`. | When `leak_detection` is present, both controls default to `true`; omitted keys also default to `true`. |
| `confirm` | Optional integer in `[0, 100]` (booleans rejected). Default: `2`. | Additional identical forbidden requests for a would-be FAIL only. Every repeat must reproduce stable owner-specific evidence. `0` disables repeats; the upper bound prevents accidental unbounded traffic. PASS and ambiguous outcomes are not repeated. |

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
It must not subtract values from owner/forbidden overlap, establish a soft deny,
or permit a public-endpoint PASS. An initial forbidden status in
`acceptable_status` still yields PASS. For forbidden 2xx, invalid control yields
INCONCLUSIVE with reason `invalid_control`, except that an explicit owner canary
present in the baseline and forbidden response but **absent from the control**
can independently establish FAIL, with reduced confidence and the usual
confirmation requirement. A canary also exposed by the control is not
owner-specific evidence; identical unauthenticated data cannot establish an
authorization leak. `invalid_control` deliberately takes precedence over
`public_endpoint` and `soft_deny` classification, not merely over overlap scoring.

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
| `unauthenticated` | Replays the original request with no context headers, `auth=None`, and an empty Cookie header to prevent cookie-jar reuse. An unauthenticated 2xx with identical JSON paths/typed values (after ignoring fields) yields PASS with note `public_endpoint`. This classifies public exposure, not whether public access itself is desirable. |

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
| `PASS` | — | Forbidden response is in `acceptable_status`; no body-leak analysis on an accepted denial. |
| `PASS` | note: `public_endpoint` | Unauthenticated 2xx has identical JSON data to the forbidden response. |
| `PASS` | note: `soft_deny` | Forbidden 2xx has the same JSON paths/types as the nonexistent response, without leak evidence (values may differ). |
| `FAIL` | `leak_detected` | Forbidden 2xx has a unique owner canary or sufficient unique overlap, and all configured repeats reproduce stable evidence. |
| `INCONCLUSIVE` | `rate_limited` | Forbidden/control/confirmation response is 429. |
| `INCONCLUSIVE` | `server_error` | Forbidden/control/confirmation response is 5xx. |
| `INCONCLUSIVE` | `timeout` | Forbidden/control/confirmation request times out. |
| `INCONCLUSIVE` | `not_reproducible` | Candidate evidence does not reproduce on every required confirmation. |
| `INCONCLUSIVE` | `ambiguous_2xx` | Successful response is neither public nor a soft deny and has insufficient unique leak evidence. |
| `INCONCLUSIVE` | `invalid_control` | Nonexistent-object control returns owner-like 2xx data or a canary; no independent, reproducible owner canary can prove a leak. No soft-deny/public PASS is permitted. |
| `INCONCLUSIVE` | `unexpected_status` | Forbidden response is neither 2xx nor an accepted denial/overload status (e.g. redirect). |
| `ERROR` | `baseline_not_2xx` / `baseline_timeout` | Primary baseline failed; no forbidden request is sent. |
| `ERROR` | `execution_error` / `invalid_canary` | Resolution/context/transport problem, or canary resolves to a non-scalar. |
| legacy `FAIL` | `assertion_failed` | Legacy assertions did not all match; no differential traffic is added. |
| existing `SKIPPED` | `safety_blocked` / `endpoint_absent` | Guard blocked a request, or selected endpoint is absent. |

A 429/5xx/timeout/non-reproducible candidate is never a vulnerability finding.
INCONCLUSIVE exits **0** by default (even when every executed check is
inconclusive); `--fail-on-inconclusive` makes it exit **1**. FAIL exits **1**;
ERROR, configuration failure, or all-skipped scans exit **2**, taking priority.
JUnit represents INCONCLUSIVE as skipped with a message/reason. SARIF emits a
`level: note`, `kind: review` result without security-rule severity metadata,
not a security alert. HIGH/CRITICAL webhooks still send only FAIL findings.

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
