# LedgerProbe real-world benchmark

This benchmark measures whether LedgerProbe's differential authorization engine
finds documented BOLA/IDOR on projects the engine's authors did not write. It
compares the current engine with the legacy status-only rule mode on identical
endpoints. It is deliberately small and fully local; it is not a product
security assessment.

## Safety model

`benchmark/run.py` refuses to start unless every target URL is loopback
(`127.0.0.1`, `localhost`, `::1`) or, only with an explicit opt-in, an RFC1918
Docker address or a named Compose service. Public IPs, public hostnames,
link-local/metadata addresses, credentials in URLs, non-HTTP schemes and invalid
ports raise `UnsafeTarget` before a request is opened. `benchmark/tests`
contains the hard-fail tests for that guard, including `8.8.8.8`,
`169.254.169.254`, `127.0.0.1.evil.test` and `0.0.0.0`.

Both Compose files publish only on `127.0.0.1`. The only target mutation in the
VAmPI rule set is the documented password-change endpoint; all other rules are
GETs. crAPI rules are read-only.

## Targets and versions

| Target | Upstream revision | Runtime | Modes |
| --- | --- | --- | --- |
| VAmPI | `erev0s/VAmPI@f16052dce83f05847133ec98f01c5193a41de7d8` | `erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12` | `vulnerable=1`, `vulnerable=0` |
| crAPI | OWASP/crAPI source `1.1.5` (`benchmark/.out/crapi-source`) | `crapi/*:1.1.6` images, `postgres:14.15`, `mongo:4.4.29` | single mode |

Docker Engine 28.5.2 and Compose v2 are the expected runtime. VAmPI's only
published tag is mutable, so its manifest digest is pinned. crAPI has no
published 1.1.5 image; the image/source skew is a recorded limitation.

## Ground truth provenance

Ground truth was committed as `6eabf48` **before** any LedgerProbe run against
these targets. Labels come only from the targets' README/docs/OpenAPI/service
source; no LedgerProbe output influenced them. Files:

- `benchmark/ground_truth/vampi.yaml` — 13 cases: **8 vulnerable, 5 safe**.
  Sources include `api_views/books.py:50-58` (book BOLA),
  `api_views/users.py:186-192` (password BOLA), and `api_views/users.py:19-26,45-49`
  (unauthenticated user directory/debug/read-by-name exposure). The secure
  toggle is represented by `api_views/books.py:61-73` and
  `api_views/users.py:193-196`; the README's warning that secure mode does not
  fix every endpoint is reflected by keeping the directory/debug cases
  vulnerable in both modes.
- `benchmark/ground_truth/crapi.yaml` — 10 cases: **5 vulnerable, 5 safe**.
  Sources include `docs/challenges.md:17-33` and
  `VehicleServiceImpl.java:145-164` / `mechanic/views.py:223-244` for the two
  documented BOLA challenges; `shop/views.py:109-165` and
  `merchant/views.py:157-180` for source-derived order/VIN IDOR; the official
  solution's vehicle-id leak (`docs/challengeSolutions.md:22-23`,
  `community/api/models/post.go:114-130`) for the feed exposure. Safe cases cite
  token-scoped queries (`UserServiceImpl.java:199-229`,
  `VehicleServiceImpl.java:115-133`, `shop/views.py:267-294`,
  `ProfileServiceImpl.java:122-133`) and the public product catalogue.

The crAPI labels were frozen but **not executed** in this environment; they are
reported as blocked, not as measured results.

## Method

1. `benchmark/targets/<target>/setup.py` creates two identities, obtains tokens
   and seeds an owner object with a unique canary. Auth/setup lives in the
   target adapter, never in the engine. Inputs are written under
   `benchmark/.out/<target>/<instance>/inputs.json` with mode `0600` and are
   gitignored.
2. Both modes run through `ledgerprobe.py` with the same OpenAPI snapshot,
   base URL, inputs and rate limit:
   - **legacy**: status-only assertion `403` on the cross-tenant request. This
     is the naive baseline: it has no canary, control, confirmation or soft-deny
     logic.
   - **differential**: owner/other comparison, nonexistent-object and
     unauthenticated controls, canaries/unique-overlap, two confirmations, and
     bounded pagination where applicable.
3. `benchmark/run.py` starts/stops Compose (unless `--no-docker`), runs setup,
   parses JUnit (which contains every check, unlike SARIF which contains only
   non-passing checks), and scores each endpoint against the frozen label.
4. `INCONCLUSIVE` is reported separately. A vulnerable endpoint that is not
   `FAIL` is counted as `FN`; a safe endpoint that is neither `PASS` nor `FAIL`
   is `INCONCLUSIVE`, not `TN`. Precision is `TP/(TP+FP)`; recall is
   `TP/(TP+FN)`.

## Results

Generated in `benchmark/RESULTS.md`:

| Target | Mode | TP | FP | TN | FN | INCONCLUSIVE | Precision | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VAmPI | legacy status-only | 8 | 5 | 0 | 0 | 0 | 61.5% | 100.0% |
| VAmPI | differential | 7 | 0 | 3 | 1 | 3 | 100.0% | 87.5% |
| crAPI | legacy status-only | — | — | — | — | — | n/a | n/a |
| crAPI | differential | — | — | — | — | — | n/a | n/a |

The differential engine removed all five legacy false positives while retaining
seven of eight vulnerable findings. The cost is one missed state-changing
authorization bug and two conservative INCONCLUSIVE results.

### Every false positive (legacy)

All five are the same naive-baseline defect: a status-only rule demands exactly
403, so any other correct behavior is a finding.

1. `vampi-home` `GET /` — 200 public banner, expected 403 → `FAIL`, reason
   `assertion_failed`. The endpoint is documented as a public service banner.
2. `vampi-book-list` `GET /books/v1` — 200 public catalogue without secrets,
   expected 403 → `FAIL`. `Book.json` omits `secret_content`.
3. `vampi-me` `GET /me` — 200 caller-scoped profile, expected 403 → `FAIL`.
4. `vampi-books-object` `GET /books/v1/{book_title}` in `vulnerable=0` — 404
   hide-existence, expected 403 → `FAIL`.
5. `vampi-users-password` `PUT /users/v1/{username}/password` in
   `vulnerable=0` — 204 self-scoped update, expected 403 → `FAIL`.

### Every false negative and inconclusive (differential)

1. **FN** `vampi-users-password` `PUT /users/v1/{username}/password`
   (`vulnerable=1`) — `INCONCLUSIVE`, reason `ambiguous_2xx`. Diagnosis: VAmPI
   returns a generic 204/`{"status":"success","Password":"Updated."}` body; no
   owner canary or owner-specific JSON is exposed. The engine compares response
   data, so it cannot prove that the state change targeted the owner. This is a
   real coverage gap for state-changing BOLA and is recorded rather than tuned
   away in the benchmark commit.
2. **INCONCLUSIVE (safe)** `vampi-me` `GET /me` — both identities receive their
   own 200 profile; there is no denial and no owner-data overlap. The engine
   refuses to call that PASS and reports `ambiguous_2xx`. It is not counted as
   TN.
3. **INCONCLUSIVE (safe)** `vampi-users-password` secure mode — 204 with no body;
   no denial/soft-deny shape, so the engine reports `ambiguous_2xx` instead of
   inventing a PASS.

The remaining two safe INCONCLUSIVE rows in the table are these two; the FN is
the third INCONCLUSIVE count.

## Before and after

No engine change was made in the benchmark commits. The engine baseline is
commit `15ae40a`; the benchmark adds targets, ground truth, scoring and reports
only. Therefore before and after numbers are identical:

| Mode | Before | After |
| --- | --- | --- |
| legacy | 8 TP / 5 FP / 0 TN / 0 FN | 8 TP / 5 FP / 0 TN / 0 FN |
| differential | 7 TP / 0 FP / 3 TN / 1 FN / 3 INC | 7 TP / 0 FP / 3 TN / 1 FN / 3 INC |

If a later commit fixes the state-changing-BOLA gap, it must not touch
`benchmark/ground_truth/`; update this section with the new numbers and keep the
old row visible.

## What could not run, and why

- **crAPI (required target): not executed.** The Docker daemon socket is
  `root:docker` mode `0660`; this user is not in group `docker`. The
  `request_elevation` path failed because `pkexec` is not setuid root on this
  host, and the environment forbids direct `sudo`. Rootless Docker is also not
  viable for crAPI here: `newuidmap`/`newgidmap` are absent, so the multi-UID
  Postgres/Mongo containers cannot start. The Compose/setup/rules are committed
  but unverified. No crAPI numbers are claimed.
- **OWASP ZAP API scan: not run.** It is a Docker image, so the same blocker
  applies. Even when available, a generic API scan is not a BOLA oracle; we did
  not fabricate alerts or scores.
- **Docker for VAmPI: not used in the recorded run.** VAmPI was executed
  natively with Python 3.11.15 and the pinned `requirements.txt` from the same
  commit. The runtime copies changed only the hardcoded `0.0.0.0:5000/debug=True`
  bind to `127.0.0.1:$PORT/debug=False`; the application source and rules were
  unchanged. This is a forced deviation from the Docker method of record.

## Limitations

- One of two required targets is missing; the overall benchmark is a VAmPI-only
  measurement. No claim can be made about crAPI precision/recall.
- The sample is 13 executed endpoint cases, not a population. There are no
  confidence intervals, repeated trials or inter-rater checks.
- VAmPI's ground truth deliberately includes unauthenticated directory/debug
  exposure (IDOR/excessive data exposure) as well as classic object BOLA; it is
  not a pure BOLA benchmark. Public and self-scoped controls are labelled safe
  because the target documents them that way, even though they are not
  object-level denial checks.
- The engine and rules were written by the same project that wrote the
  benchmark. Ground truth was frozen first, but endpoint selection and canary
  choice still reflect knowledge of the target.
- crAPI's source snapshot is 1.1.5 while the only published images are 1.1.6;
  endpoints may differ. Its Compose stack is also untested here.
- `postgres:14.15`, `mongo:4.4.29` and the crAPI tags are mutable tags, not
  digests. VAmPI is digest-pinned.
- The legacy baseline is intentionally strict (exact 403). A more lenient
  status policy would produce fewer false positives and is not measured.
- The password endpoint is a mutation. The benchmark does not verify the
  resulting state, only response evidence; this is exactly why the differential
  engine reports INCONCLUSIVE.
- No secrets, tokens or databases are committed. Runtime artifacts live under
  `benchmark/.out/` and are gitignored.

## Reproduce

With Docker and Compose v2 available:

```bash
python benchmark/run.py --target all
```

This starts the pinned stacks, runs setup, scans legacy and differential modes,
scores against `benchmark/ground_truth/`, writes `benchmark/RESULTS.md` and
`benchmark/.out/results.json`, then removes the benchmark Compose projects.
Use `--keep` to inspect a running stack. The run exits 2 if a required target
cannot be executed or a scan has execution errors.

Constrained fallback used for the recorded VAmPI numbers:

```bash
# VAmPI checkout at the pinned commit, Python 3.11, requirements installed.
PORT=5002 vulnerable=1 tokentimetolive=3600 python app.py   # loopback only
PORT=5001 vulnerable=0 tokentimetolive=3600 python app.py
python benchmark/run.py --target vampi --no-docker \
  --base-url-vulnerable http://127.0.0.1:5002 \
  --base-url-secure http://127.0.0.1:5001
```

Run the guard/scorer tests with:

```bash
python -m pytest benchmark/tests -q
```
