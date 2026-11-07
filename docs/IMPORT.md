# Importing observed traffic

`ledgerprobe import` turns two labelled staging captures into an endpoint
inventory, reviewable rule candidates, local inputs, and a drift report. It is
an offline parser: it does not call the target, the tracker, or any other
network service.

The importer is deliberately conservative. A generated rule is a **candidate**,
not an approved policy. Every generated rule carries `review_required: true`.
LedgerProbe refuses to load it unless the operator passes `--accept-generated`;
that explicit flag is the acceptance record. The flag remains in the file until
a reviewer removes it intentionally.

## Workflow

1. Capture two sessions in a staging environment, one with the owner identity
   and one with a second identity. Browser DevTools can export HAR 1.2; do not
   capture production traffic or production credentials.
2. Label each capture at import time. The importer never infers identity from
   tokens or bodies.

   ```bash
   ledgerprobe import har \
     --role owner=owner.har \
     --role other=other.har \
     --include-host staging-api.example.test \
     --spec openapi.json \
     --out traffic-review
   ```

   Postman collection v2.1 uses the same workflow with `postman` in place of
   `har`. Only request paths, methods, query names, and JSON body key names are
   retained; Postman auth, variables, examples, and values are ignored.

3. Review `traffic-review/inventory.json`, `traffic-review/drift.json`, and
   `traffic-review/rules.generated.yaml`. Check inferred path parameters and
   endpoint scope before running anything. Mutation candidates are emitted
   `disabled: true` with `mutating: true` and require `restore:` and `verify:`.
4. Keep `traffic-review/inputs.generated.json` local. It contains owner object
   IDs and candidate canaries from the captures, plus `REPLACE_ME` token
   placeholders. It is written mode `0600` and is refused unless the path is
   git-ignored. `--allow-tracked-output` is a warned last resort for unusual
   throwaway workspaces; never use it in a shared repository.
5. Replace the token placeholders in a private copy of the inputs file. Never
   commit the inputs file or paste raw capture tokens into a command.
6. Accept the reviewed candidates explicitly and run against staging with the
   normal guarded scan path:

   ```bash
   ledgerprobe --spec openapi.json --base-url https://staging-api.example.test \
     --rules traffic-review/rules.generated.yaml \
     --inputs private-inputs.json \
     --accept-generated --read-only --tickets off
   ```

   `--read-only` is appropriate for GET-only candidates. Remove it only for a
   reviewed mutation rule that has a real restore and verify contract.

## What is kept and what is discarded

The inventory retains method, path template, query parameter names, request and
response content types, observed status codes, JSON schema key names/types, the
observing roles, and optional GraphQL operation metadata. It also records
`template_confidence` and warnings such as `single_observation_literal`.

The importer discards Authorization, cookie, API-key, and other auth headers;
all query values; all request and response body values; and token, cookie,
email, phone, card-like, JWT, and similar secrets. Schema keys can still reveal
domain vocabulary, so inventory files remain internal review artifacts.

Path parameters are inferred from UUIDs, integers, 24-hex ObjectIds, long hex
values, base64url values of at least 16 characters, and variation at the same
position across observations. Known words and version segments stay literal.
Trailing slashes are removed, repeated observations are merged, and query order
is ignored.

Generated BOLA candidates use `scope: object` only when an owner observation
contains a path ID. Endpoints without an ID observed for both roles get a
low-confidence `scope: caller` proposal. `shared` is never emitted. Canaries
are owner-only JSON leaves, capped at five per template, and are written only to
the local inputs file. Non-GET candidates are never enabled automatically.

GraphQL POST requests are inventoried with operation name/type under
`graphql_operations`, but the importer does not generate GraphQL rules. Add
those manually after reviewing the operation and its authorization model.

## Drift

Report drift directly:

```bash
ledgerprobe drift --spec openapi.json --inventory traffic-review/inventory.json
ledgerprobe drift --spec openapi.json --inventory traffic-review/inventory.json --fail-on-drift
```

The report lists traffic routes absent from the spec (undocumented), spec routes
not observed (unobserved), and method/parameter mismatches. Exit status is zero
by default; `--fail-on-drift` returns 1 when undocumented routes exist.

For scans, `--inventory traffic-review/inventory.json` with
`--spec-check warn` adds traffic-only routes to endpoint lookup. A rule that
targets such a route is not skipped as `endpoint_absent`; its `spec_drift`
warning says the route came from the traffic inventory. The optional `drift`
section in results JSON contains counts and template lists, not captured values.

## Worked example

Suppose the owner capture contains `GET /api/v1/objects/obj-owner-1` and the
second capture contains `GET /api/v1/objects/obj-other-1`. The shared literal
skeleton and the two distinct values produce this inventory route:

```json
{
  "method": "GET",
  "path": "/api/v1/objects/{id}",
  "parameters": [{"name": "id", "in": "path", "required": true}],
  "template_confidence": "medium"
}
```

The generated rule targets `/api/v1/objects/{id}`, uses the owner and second
identity contexts, and reads the owner ID and any owner-only canary from
`inputs.generated.json`. On a vulnerable staging profile the differential check
fails; on a correctly isolated profile the second identity receives an
acceptable 401/403/404 and the check passes. If only one literal observation
exists, the importer leaves the segment literal, warns, and does not invent a
BOLA candidate.

## Limitations

- A single observation cannot safely distinguish an ID from a literal word;
  such routes stay literal with a warning.
- `scope: caller` proposals are intentionally low-confidence and should be
  reviewed against the application's ownership model.
- GraphQL rules, pagination discovery, stateful workflows, and multi-tenant
  role models are not inferred.
- mitmproxy flow import is experimental and untested: it is coded behind an
  optional dependency, but this workspace does not install `mitmproxy` and has
  no test for that path; use HAR or Postman here.
- Generated artifacts are not a substitute for a reviewed OpenAPI contract or
  an authorization design review.