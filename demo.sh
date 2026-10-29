#!/usr/bin/env bash
# FinShield-Core demo entry point.
# Boots the mock bank, runs both audit harnesses, then serves the production console.
# If the API/dashboard are already running on the chosen ports, they are reused.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_PORT="${API_PORT:-8000}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3001}"
REPORTS_DIR="${ROOT_DIR}/logic-fuzzer/reports"
MOBILE_REPORTS_DIR="${ROOT_DIR}/mobile-harness/reports"
LOG_DIR="${ROOT_DIR}/.demo"
API_LOG="${LOG_DIR}/api.log"
DASHBOARD_LOG="${LOG_DIR}/dashboard.log"

API_PID=""
DASHBOARD_PID=""
STARTED_API=0
STARTED_DASHBOARD=0

mkdir -p "$REPORTS_DIR" "$MOBILE_REPORTS_DIR" "$LOG_DIR"

cleanup() {
  local status=$?
  trap - EXIT INT TERM

  echo
  if (( STARTED_DASHBOARD )); then
    echo "[-] Stopping dashboard (pid ${DASHBOARD_PID})"
    kill "$DASHBOARD_PID" 2>/dev/null || true
    wait "$DASHBOARD_PID" 2>/dev/null || true
  fi
  if (( STARTED_API )); then
    echo "[-] Stopping mock API (pid ${API_PID})"
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
  echo "[+] Demo stopped. Logs: ${LOG_DIR}"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- Prerequisites -----------------------------------------------------------
if [[ -z "${PYTHON:-}" ]]; then
  if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    PYTHON="${ROOT_DIR}/.venv/bin/python"
  else
    PYTHON="$(command -v python3)"
  fi
fi

command -v curl >/dev/null || {
  echo "[!] curl is required." >&2
  exit 1
}

if ! "$PYTHON" -c "import fastapi, httpx, jwt, sqlalchemy, uvicorn, yaml, openapi_spec_validator" >/dev/null 2>&1; then
  echo "[!] Python dependencies are missing for ${PYTHON}." >&2
  echo "    Install: ${PYTHON} -m pip install -r mock-bank-api/requirements-dev.txt -r requirements.txt" >&2
  exit 1
fi

if [[ ! -d "${ROOT_DIR}/dashboard/node_modules" ]]; then
  echo "[!] dashboard/node_modules is missing." >&2
  echo "    Install: (cd ${ROOT_DIR}/dashboard && npm install)" >&2
  exit 1
fi

api_ready() {
  curl -fsS --max-time 2 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1
}

dashboard_ready() {
  curl -fsS --max-time 2 "http://127.0.0.1:${DASHBOARD_PORT}/" 2>/dev/null | grep -q "FinShield Core"
}

wait_until() {
  local check="$1"
  local pid="$2"
  local attempt

  for attempt in $(seq 1 40); do
    if "$check"; then
      return 0
    fi
    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.5
  done
  return 1
}

echo "=========================================================="
echo "          FINSHIELD-CORE AUTOMATED DEMO RUNNER            "
echo "=========================================================="

# --- 1. Mock bank API --------------------------------------------------------
echo "[1/4] Mock neobank API on http://127.0.0.1:${API_PORT}"
if api_ready; then
  echo "[=] Reusing the healthy API already listening on port ${API_PORT}."
else
  (
    cd "${ROOT_DIR}/mock-bank-api"
    exec "$PYTHON" -m uvicorn app.asgi:app --host 127.0.0.1 --port "$API_PORT" --log-level warning
  ) >>"$API_LOG" 2>&1 &
  API_PID=$!
  STARTED_API=1

  if ! wait_until api_ready "$API_PID"; then
    echo "[!] API failed to become healthy. Last log lines:" >&2
    tail -n 20 "$API_LOG" >&2 || true
    exit 1
  fi
  echo "[+] API healthy (pid ${API_PID})."
fi

# --- 2. Logic fuzzer and spec-driven LedgerProbe -----------------------------
echo "[2/4] Running logic fuzzer against http://127.0.0.1:${API_PORT}..."
(
  cd "${ROOT_DIR}/logic-fuzzer"
  "$PYTHON" main.py --base-url "http://127.0.0.1:${API_PORT}" --out "$REPORTS_DIR"
)

echo "[*] LedgerProbe: local OpenAPI input, read-only policies, SARIF + JUnit..."
(
  cd "$ROOT_DIR"
  "$PYTHON" -m examples.prepare_demo --base-url "http://127.0.0.1:${API_PORT}" --out "$LOG_DIR"
  scan_status=0
  "$PYTHON" ledgerprobe.py \
    --spec "${LOG_DIR}/openapi.json" \
    --base-url "http://127.0.0.1:${API_PORT}" \
    --rules rulesets/abac_isolation.yaml \
    --inputs "${LOG_DIR}/inputs.json" \
    --read-only --max-rps 5 \
    --sarif "${REPORTS_DIR}/results.sarif" \
    --junit "${REPORTS_DIR}/results.xml" || scan_status=$?
  # A vulnerability is expected in this lab; execution/config errors are not.
  if (( scan_status > 1 )); then
    exit "$scan_status"
  fi
)

# --- 3. Mobile attestation harness ------------------------------------------
echo "[3/4] Running mobile attestation harness (simulated profile)..."
(
  cd "${ROOT_DIR}/mobile-harness"
  "$PYTHON" runner.py --simulate --profile vulnerable --out "$MOBILE_REPORTS_DIR"
)

# --- 4. Production dashboard -------------------------------------------------
echo "[4/4] Dashboard on http://127.0.0.1:${DASHBOARD_PORT}"
if dashboard_ready; then
  echo "[=] Reusing the healthy dashboard already listening on port ${DASHBOARD_PORT}."
else
  if [[ ! -f "${ROOT_DIR}/dashboard/.next/BUILD_ID" ]]; then
    echo "[*] Building the production dashboard..."
    (cd "${ROOT_DIR}/dashboard" && npm run build)
  fi

  (
    cd "${ROOT_DIR}/dashboard"
    REPORTS_DIR="$REPORTS_DIR" exec ./node_modules/.bin/next start -H 127.0.0.1 -p "$DASHBOARD_PORT"
  ) >>"$DASHBOARD_LOG" 2>&1 &
  DASHBOARD_PID=$!
  STARTED_DASHBOARD=1

  if ! wait_until dashboard_ready "$DASHBOARD_PID"; then
    echo "[!] Dashboard failed to become ready. Last log lines:" >&2
    tail -n 20 "$DASHBOARD_LOG" >&2 || true
    exit 1
  fi
  echo "[+] Dashboard ready (pid ${DASHBOARD_PID})."
fi

echo "=========================================================="
echo "[+] FINSHIELD-CORE DEMO READY"
echo "  • Mock API:      http://127.0.0.1:${API_PORT}"
echo "  • API docs:     http://127.0.0.1:${API_PORT}/docs"
echo "  • Dashboard UI: http://127.0.0.1:${DASHBOARD_PORT}"
echo "  • Reports:      ${REPORTS_DIR}"
echo "  • SARIF:        ${REPORTS_DIR}/results.sarif"
echo "=========================================================="

if (( ! STARTED_API && ! STARTED_DASHBOARD )); then
  echo "[+] Both services were already running; the fresh audit is live on refresh."
  exit 0
fi

echo "Press Ctrl+C to stop the services started by this demo."
wait
