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
