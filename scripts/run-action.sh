#!/usr/bin/env bash
set -uo pipefail

args=(--spec "$INPUT_SPEC" --rules $INPUT_RULES --environment "$INPUT_ENVIRONMENT"
      --tickets "$INPUT_TICKETS" --fail-on "$INPUT_FAIL_ON"
      --json ledgerprobe-results.json --sarif ledgerprobe-results.sarif
      --junit ledgerprobe-results.xml)
if [ -n "${INPUT_AUTH:-}" ]; then args+=(--auth "$INPUT_AUTH"); fi
if [ -n "${INPUT_BASELINE:-}" ]; then args+=(--baseline "$INPUT_BASELINE"); fi

printf 'sarif=%s\n' "ledgerprobe-results.sarif" >> "${GITHUB_OUTPUT:?}"
printf 'junit=%s\n' "ledgerprobe-results.xml" >> "$GITHUB_OUTPUT"
printf 'results=%s\n' "ledgerprobe-results.json" >> "$GITHUB_OUTPUT"

code=0
ledgerprobe "${args[@]}" || code=$?
exit "$code"