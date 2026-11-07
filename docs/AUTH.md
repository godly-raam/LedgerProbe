# Authentication and secrets

LedgerProbe keeps credentials in memory and resolves them only while building a
request. `ledgerprobe-auth.yaml` is strict: unknown fields, inline credentials,
and secret references without a provider are rejected before any scan traffic.

```yaml
schema_version: ledgerprobe-auth/1
identities:
  owner:
    provider: static_header
    environment: lab
    params:
      header: Authorization
      value_ref: env:OWNER_TOKEN
  other:
    provider: login_request
    environment: staging
    refresh_on_401: true
    params:
      method: POST
      path: /users/v1/login
      body:
        username: "{{other_username}}"
        password_ref: file:/run/secrets/staging.env#OTHER_PASSWORD
      token_json_path: auth_token
      expiry_json_path: expires_in
      header_format: "Bearer {token}"
setup:
  argv: ["/usr/local/bin/seed-canaries"]
  timeout: 30
  env: ["PATH", "STAGING_BASE_URL"]
teardown:
  argv: ["/usr/local/bin/remove-canaries"]
  timeout: 30
  env: ["PATH"]
```

The quick start uses `--auth ledgerprobe-auth.yaml`. Legacy `inputs.json`
contexts remain available for migration only and are documented here, not in
the quick start; they print `legacy_static_credentials`, and `--strict-auth`
turns that into a configuration error.

## Providers

### Static header

```yaml
provider: static_header
params:
  header: X-Api-Key
  value_ref: env:STAGING_API_KEY
```

### OAuth 2.0 client credentials

```yaml
provider: oauth2_client_credentials
environment: staging
params:
  token_url: https://idp.example.test/oauth/token
  client_id_ref: env:STAGING_CLIENT_ID
  client_secret_ref: vault:secret/data/ledgerprobe#client_secret
  scope: ledger.read
```

The bearer token is cached in memory until 30 seconds before expiry. A refresh
is proactive; reactive refresh is opt-in per identity with
`refresh_on_401: true`. A `403` is never retried: it is the authorization signal
under test.

### Login request

```yaml
provider: login_request
environment: staging
params:
  method: POST
  path: /identity/api/auth/login
  body:
    username: "{{owner_username}}"
    password_ref: file:/run/secrets/staging.env#OWNER_PASSWORD
  token_json_path: token
  # or token_header: X-Auth-Token
  # or token_cookie: session
  expiry_json_path: expiresIn
  header_format: "Bearer {token}"
```

This covers VAmPI/crAPI-style login responses. A 400, 401, or 403 from the
login endpoint fails fast with `auth_failed`; there is no retry loop and no
finding is emitted. At most three login/token attempts are made per identity
per run. Login/token requests can have side effects such as OTP/SMS cost, user
notifications, account lockout, and session creation: point them only at
dedicated test identities in staging.

### Script escape hatch for OTP and device-bound flows

```yaml
provider: script
environment: staging
params:
  argv:
    - /usr/local/bin/fetch-test-sms-otp
    - "--identity"
    - "owner"
  timeout: 30
  env: ["PATH", "SMS_SINK_URL", "SMS_SINK_TOKEN"]
```

The script must print:

```json
{"headers": {"Authorization": "Bearer ..."}, "expires_in": 300}
```

`argv` is always a list and never a shell string. stdout is capped at 64 KB.
stderr is discarded; only the exit code is reported. Use a test SMS sink, never
a real customer's phone.

### Secret references

| Reference | Meaning |
| --- | --- |
| `env:NAME` | Environment variable |
| `file:/path#key` | JSON object key or dotenv key; POSIX files readable by group/other are refused |
| `vault:<path>#<field>` | HashiCorp Vault KV v2; requires `VAULT_ADDR` and `VAULT_TOKEN` |
| `aws:<secret-id>#<json-key>` | AWS Secrets Manager; optional `ledgerprobe[aws]` extra (boto3), implemented but unverified against AWS |

`Secret` objects render as `***` for `repr`, `str`, f-strings, formatting, and
JSON serialization. Raw values are reachable only through `.reveal()` at the
request boundary. A global redactor replaces resolved values in log records and
exception text with `[REDACTED]`.

## CI patterns

- GitHub Actions: put `STAGING_*` values in repository/environment secrets and
  expose them to the scan step as environment variables. Never echo them or
  write them into `inputs.json`.
- Prefer short-lived OIDC federation to Vault/AWS roles where the CI provider
  supports it. This repository does not implement that federation; the
  `vault:` and `aws:` providers consume credentials supplied by the runner.
- Keep auth configuration in the repository only when it contains references,
  never literal credentials.
- Set a low `--max-rps`, use `--strict-auth`, and run the unauthenticated control
  on every differential rule.

## Threat model

LedgerProbe never persists tokens, cookies, authorization headers, resolved
secret values, login bodies, or provider stderr. Tokens are held only in
process memory. Reports, SARIF, JUnit, results JSON, tickets, and logs contain
no credential values. The tool does not protect a compromised host, a malicious
Python process, or a target that deliberately returns secrets in response
bodies; those are outside its control. Use dedicated staging identities and a
test SMS sink.

## Failure semantics

- `auth_failed`: login/token credential failure or attempt cap; scan stops with
  `ERROR`, not a security finding.
- `baseline_unauthorized`: the primary baseline returned 401 after the configured
  flow; check the auth identity, environment, and secret reference.
- `auth_host_not_allowed`: an IdP host outside the target and allowed-hosts
  list. Loopback hosts are allowed by default.
- `secret_file_permissions`: a file reference is readable by group/other.
- `auth_refreshed`: recorded as a value-free result note after a successful
  reactive refresh.
