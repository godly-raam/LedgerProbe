# Roadmap

## Planned, not implemented

None of the items below exist in the current code on `main`. There is no code
path, rule, CLI flag, or test for any of them, and none of them changes a number
in `README.md`, `docs/BENCHMARK.md`, or `docs/VALIDATION.md`. Each would
need its own fixtures and preregistered evaluation before any recorded result
could cite it.

### (a) Ledger conservation invariant across accounts

Check that a transfer moves value between accounts without creating or
destroying it: a declared tolerance per currency, a settle-wait before the
after-snapshot, and declared velocity caps so the invariant can tell a correct
system from a throttled one. Fixture-validated first; no live ledger target.

### (b) Webhook and state-machine probes

Probe state machines for out-of-order transitions, replayed events, and
signature handling, with staging-only execution and new mutation gates. Not
implemented; the current engine has no event, queue, or signature checks.

### (c) Optional, opt-in LLM-assisted rule drafting

Draft candidate rules from the sanitized traffic inventory only: no response
content is ever sent to a model, every draft is human-reviewed, and nothing is
executed until `--accept-generated` is passed. Not implemented; there is no
model client, prompt, or provider configuration in the current code.

### (d) Nullable `anyOf` handling in the OpenAPI parser

The parser flattens request-body compositions, but nullable `anyOf` fields
collapse to `type: null`, which keeps `dvr-bola-profile-update` an
`execution_error`. Not implemented.

### (e) One-command reproduction of the extension evaluation

The extension run currently needs a hand-driven CLI sequence per target. A
single committed command that resets, seeds, scans, and scores the extension
would make the after-Amendments row reproducible without manual steps. Not
implemented; `benchmark/run.py` covers the 23-case benchmark only.
