# BFLA, mass assignment, and business limits

| Check | Fingerprint `check_type` | CWE | Default CVSS | Rationale |
| --- | --- | --- | --- | --- |
| BFLA | `bfla` | 285 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | A low-privilege identity can read or invoke a function reserved for another role. |
| Mass assignment | `mass_assignment` | 915 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | An authenticated user can persist privileged fields through an otherwise legitimate request. |
| Business limit | `business_limit` | 840 | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` | Integrity of a declared financial/business invariant is lost without confidentiality impact. |

BFLA is **validated on fixtures only; not yet benchmarked on real targets**.

`check: mass_assignment` and `check: business_limit` are **experimental, untested; require --experimental**. Their loader gates are tested; their execution paths are not.

## BFLA

```yaml
check: bfla
privileged: admin
unprivileged: customer
target_endpoints: [{path: /admin/export, method: GET}]
leak_detection: {canaries: [admin-only-value]}
controls: {nonexistent_object: true, unauthenticated: true}
```

The privileged identity is normalized to `auth_contexts.primary`; the
unprivileged identity is `forbidden`. Read checks reuse BOLA controls and
confirmation. A mutating BFLA rule sets `mutating: true`, provides `verify`, and
requires `restore`.

`access_matrix` expands one BFLA check for every endpoint/role pair not listed in
`allowed_roles`; the expanded rule ID is `<matrix_id>#<METHOD path>#<role>`.

## Mass assignment

```yaml
check: mass_assignment
request: {method: PATCH, path: /me, body: {name: Test}}
readback: {request: {method: GET, path: /me}, paths: [role, nested.plan]}
inject: [role, {name: nested.plan, type: string}]
restore: [{method: PATCH, path: /me, body: {name: Test}}]
```

Default candidates are `role`, `roles`, `is_admin`, `admin`, `is_staff`,
`balance`, `limit`, `status`, `verified`, `kyc_status`, `plan`, `owner_id`,
`user_id`, and `account_id`. Evidence contains field names and counts only.

## Business limits

```yaml
check: business_limit
request: {method: POST, path: /payments, body: {amount: "{{amount}}"}}
ledger: {snapshot: {method: GET, path: /account}, path: balance}
limits: {per_txn_max: 100, min: 0, precision: 2}
cases: [negative, zero, sub_precision, over_balance, over_per_txn_limit]
restore: [{method: POST, path: /account/restore}]
```

Each case becomes `<rule_id>#<case>`. `over_per_txn_limit` is rejected during
loading unless the author declares `per_txn_max`; the engine never guesses a
business boundary. There are no boundary-accept cases.

BFLA honors `mutating`, `--allow-mutations`, `--allow-host`, `restore`,
`--read-only`, `--kill-file`, and the production hard block. The two
experimental checks share the loader-level mutation, restore, and
`--experimental` gates; their execution paths are not tested.
