#!/usr/bin/env bash
#
# tests/integration/run_integration_test.sh
#
# Real, end-to-end integration test: builds the actual wheel, installs
# it into a clean venv, and drives the REAL installed `sipsiege`
# command via real subprocess calls against a live mock SBC - not
# CliRunner, not mocked sipp. This exists because the two real bugs
# that shipped past 45+ passing unit tests (the Call-ID prefix
# breaking SIPp's transaction matching, and SIPp hanging forever
# without -nostdin/-recv_timeout when run without a TTY) were both
# invisible to unit tests that mock run_sipp() out entirely. Only a
# real sipp process talking to a real socket surfaces them.
#
# Exit code 0 = all assertions passed. Non-zero = something regressed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
VENV="${WORKDIR}/venv"
MOCK_PORT=15070
MOCK_LOG="${WORKDIR}/mock_sbc.log"

cleanup() {
  [[ -n "${MOCK_PID:-}" ]] && kill "${MOCK_PID}" 2>/dev/null || true
  wait "${MOCK_PID:-0}" 2>/dev/null || true
}
trap cleanup EXIT

echo "== 1. Build the real wheel =="
cd "${REPO_ROOT}"
rm -rf dist build ./*.egg-info
python3 -m build --wheel

echo "== 2. Install it into a clean venv =="
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install -q dist/sipsiege-*.whl

echo "== 3. Confirm sipp is available =="
command -v sipp >/dev/null || { echo "FAIL: sipp not installed"; exit 1; }

echo "== 4. Start the mock SBC (threshold=15 reqs / 10s window) =="
python3 "${REPO_ROOT}/tests/fixtures/mock_sbc.py" \
  --host 127.0.0.1 --port "${MOCK_PORT}" --threshold 15 --window 10 --log "${MOCK_LOG}" &
MOCK_PID=$!
sleep 1

cd "${WORKDIR}"
SIPSIEGE="${VENV}/bin/sipsiege"

echo "== 5. init + edit authorization.yml =="
"${SIPSIEGE}" init >/dev/null
python3 - <<PYEOF
content = open("authorization.yml").read()
content = content.replace(
    '- "CHANGE ME - your TEST SBC IP, e.g. 10.10.10.50"', '- "127.0.0.1"'
)
content = content.replace(
    'authorized_by: "CHANGE ME - your name / role"', 'authorized_by: "CI"'
)
content = content.replace(
    'authorized_contact_email: "CHANGE ME"', 'authorized_contact_email: "ci@test.local"'
)
# excluded_targets ships empty by default (see cli.py's TEMPLATE) - add
# one here explicitly so step 8 below can exercise real exclusion
# refusal, the same way a user would populate their own production
# infrastructure before a real run.
content = content.replace(
    'excluded_targets: []', 'excluded_targets: ["192.0.2.57"]'
)
open("authorization.yml", "w").write(content)
PYEOF
ENGAGEMENT_ID=$(grep '^engagement_id:' authorization.yml | head -1 | sed -E 's/engagement_id: "(.*)"/\1/')

echo "== 6. validate-scope must succeed =="
"${SIPSIEGE}" validate-scope

echo "== 7. status must report a clean, verified audit log =="
"${SIPSIEGE}" status | grep -q "Audit log: OK" || { echo "FAIL: audit log not OK at start"; exit 1; }

echo "== 8. scope refusal: production-style excluded target must be refused =="
OUT=$("${SIPSIEGE}" baseline 192.0.2.57 --port "${MOCK_PORT}" || true)
echo "${OUT}" | grep -q "allowed:  False" || { echo "FAIL: excluded target was not refused"; exit 1; }
echo "${OUT}" | grep -q "exclusion" || { echo "FAIL: refusal reason missing exclusion mention"; exit 1; }

echo "== 9. active tier without --confirm must be refused =="
OUT=$("${SIPSIEGE}" run register_flood 127.0.0.1 --port "${MOCK_PORT}" --rate 10 --duration 2 || true)
echo "${OUT}" | grep -q "allowed:  False" || { echo "FAIL: unconfirmed active scenario was not refused"; exit 1; }

echo "== 10. baseline BEFORE flood must be reachable =="
OUT=$("${SIPSIEGE}" baseline 127.0.0.1 --port "${MOCK_PORT}")
echo "${OUT}" | grep -q '"reachable": true' || { echo "FAIL: baseline before flood was not reachable - $OUT"; exit 1; }

echo "== 11. run register_flood for real, well over the mock's threshold =="
OUT=$("${SIPSIEGE}" run register_flood 127.0.0.1 --port "${MOCK_PORT}" \
      --rate 50 --duration 5 --confirm "${ENGAGEMENT_ID}")
echo "${OUT}" | grep -q "allowed:  True" || { echo "FAIL: authorized flood was refused - $OUT"; exit 1; }
echo "${OUT}" | grep -q '"total_calls_attempted": 250' || { echo "FAIL: unexpected call count - $OUT"; exit 1; }

echo "== 12. baseline IMMEDIATELY after flood must now be blocked =="
OUT=$("${SIPSIEGE}" baseline 127.0.0.1 --port "${MOCK_PORT}")
echo "${OUT}" | grep -q '"reachable": false' || { echo "FAIL: source was not blocked after flood - $OUT"; exit 1; }

echo "== 13. wait for the mock's window to clear, confirm recovery =="
sleep 11
OUT=$("${SIPSIEGE}" baseline 127.0.0.1 --port "${MOCK_PORT}")
echo "${OUT}" | grep -q '"reachable": true' || { echo "FAIL: source did not recover after window cleared - $OUT"; exit 1; }

echo "== 14. run invite_flood for real, under threshold - full INVITE/ACK/BYE teardown =="
OUT=$("${SIPSIEGE}" run invite_flood 127.0.0.1 --port "${MOCK_PORT}" \
      --rate 5 --duration 2 --confirm "${ENGAGEMENT_ID}")
echo "${OUT}" | grep -q "allowed:  True" || { echo "FAIL: authorized invite_flood was refused - $OUT"; exit 1; }
echo "${OUT}" | grep -q '"total_calls_attempted": 10' || { echo "FAIL: unexpected invite_flood call count - $OUT"; exit 1; }
# Every call must have been INVITE-accepted by the mock AND torn down
# with a BYE - if either count is short of 10, either the mock's new
# INVITE/ACK/BYE handling or invite_flood.xml's call flow regressed.
INVITE_ALLOWED=$(grep -c "INVITE ALLOWED" "${MOCK_LOG}")
BYE_COUNT=$(grep -c " BYE$" "${MOCK_LOG}")
[[ "${INVITE_ALLOWED}" -eq 10 ]] || { echo "FAIL: expected 10 allowed INVITEs, mock log shows ${INVITE_ALLOWED}"; exit 1; }
[[ "${BYE_COUNT}" -eq 10 ]] || { echo "FAIL: expected 10 BYEs (full call teardown), mock log shows ${BYE_COUNT}"; exit 1; }

echo "== 15. wait for the mock's window to clear again before invite_no_ack =="
sleep 11

echo "== 16. run invite_no_ack for real, under threshold - INVITEs answered, NEVER torn down =="
OUT=$("${SIPSIEGE}" run invite_no_ack 127.0.0.1 --port "${MOCK_PORT}" \
      --rate 5 --duration 2 --confirm "${ENGAGEMENT_ID}")
echo "${OUT}" | grep -q "allowed:  True" || { echo "FAIL: authorized invite_no_ack was refused - $OUT"; exit 1; }
echo "${OUT}" | grep -q '"total_calls_attempted": 10' || { echo "FAIL: unexpected invite_no_ack call count - $OUT"; exit 1; }
# The whole point of this scenario is that it never ACKs or BYEs a
# successfully-answered call - the mock must show 10 MORE allowed
# INVITEs (20 cumulative) but the BYE count must be UNCHANGED from
# step 14's 10, proving no teardown ever happened for these calls.
INVITE_ALLOWED=$(grep -c "INVITE ALLOWED" "${MOCK_LOG}")
BYE_COUNT=$(grep -c " BYE$" "${MOCK_LOG}")
[[ "${INVITE_ALLOWED}" -eq 20 ]] || { echo "FAIL: expected 20 cumulative allowed INVITEs, mock log shows ${INVITE_ALLOWED}"; exit 1; }
[[ "${BYE_COUNT}" -eq 10 ]] || { echo "FAIL: BYE count changed (expected still 10, half-open calls must never be torn down) - mock log shows ${BYE_COUNT}"; exit 1; }

echo "== 17. wait for the mock's window to clear again before digest_bruteforce =="
sleep 11

echo "== 18. run digest_bruteforce for real - real MD5 digest crypto, both outcomes =="
OUT=$("${SIPSIEGE}" run digest_bruteforce 127.0.0.1 --port "${MOCK_PORT}" \
      --rate 5 --duration 1 --confirm "${ENGAGEMENT_ID}")
echo "${OUT}" | grep -q "allowed:  True" || { echo "FAIL: authorized digest_bruteforce was refused - $OUT"; exit 1; }
echo "${OUT}" | grep -q '"credential_pairs_attempted": 5' || { echo "FAIL: unexpected digest_bruteforce pair count - $OUT"; exit 1; }
# The bundled default wordlist has exactly 2 credential pairs that match
# the mock's known-good accounts (1000/changeme, 1234/password123) and 3
# that don't - if this doesn't read exactly 2 successes / 3 failures,
# either sipsiege's or the mock's MD5 digest computation regressed (a
# stubbed/fake success count would not reproduce this exact split).
echo "${OUT}" | grep -q '"successful_logins": 2' || { echo "FAIL: expected exactly 2 real successful logins - $OUT"; exit 1; }
echo "${OUT}" | grep -q '"failed_attempts": 3' || { echo "FAIL: expected exactly 3 real failed attempts - $OUT"; exit 1; }
AUTH_OK=$(grep -c "REGISTER AUTH_OK" "${MOCK_LOG}")
AUTH_FAIL=$(grep -c "REGISTER AUTH_FAIL" "${MOCK_LOG}")
[[ "${AUTH_OK}" -eq 2 ]] || { echo "FAIL: expected 2 AUTH_OK in mock log, got ${AUTH_OK}"; exit 1; }
[[ "${AUTH_FAIL}" -eq 3 ]] || { echo "FAIL: expected 3 AUTH_FAIL in mock log, got ${AUTH_FAIL}"; exit 1; }

echo "== 19. audit log must still verify clean after all of the above =="
"${SIPSIEGE}" status | grep -q "Audit log: OK" || { echo "FAIL: audit log not OK at end"; exit 1; }

echo "== 20. tamper the audit log and confirm status catches it =="
AUDIT_FILE="${ENGAGEMENT_ID}.audit.jsonl"
python3 - "${AUDIT_FILE}" <<'PYEOF'
import json, sys
path = sys.argv[1]
lines = open(path).readlines()
entry = json.loads(lines[0])
entry["target"] = "TAMPERED"
lines[0] = json.dumps(entry, sort_keys=True) + "\n"
open(path, "w").writelines(lines)
PYEOF
"${SIPSIEGE}" status | grep -q "TAMPERED" || { echo "FAIL: tampering was not detected"; exit 1; }

echo
echo "ALL INTEGRATION CHECKS PASSED"
