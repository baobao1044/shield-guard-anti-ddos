#!/usr/bin/env bash
# ============================================================================
# Shield Guard — Test Suite & Benchmark
# Usage: bash test.sh [--benchmark]
# ============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

PASS=0; FAIL=0; SKIP=0
PORT=19901
BACKEND_PORT=19900
BASE="http://localhost:$PORT"

pass() { ((PASS++)); echo -e "  ${GREEN}✓${NC} $1"; }
fail() { ((FAIL++)); echo -e "  ${RED}✗${NC} $1 ${DIM}(expected $2, got $3)${NC}"; }
skip() { ((SKIP++)); echo -e "  ${YELLOW}○${NC} $1 ${DIM}(skipped)${NC}"; }

check_status() {
  local desc="$1" url="$2" expected="$3" extra_args="${4:-}"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" $extra_args "$url" 2>/dev/null || echo "000")
  if [[ "$status" == "$expected" ]]; then
    pass "$desc → $status"
  else
    fail "$desc" "$expected" "$status"
  fi
}

check_contains() {
  local desc="$1" url="$2" pattern="$3" extra_args="${4:-}"
  local body
  body=$(curl -s $extra_args "$url" 2>/dev/null || echo "")
  if echo "$body" | grep -qi "$pattern"; then
    pass "$desc"
  else
    fail "$desc" "contains '$pattern'" "not found"
  fi
}

# ── Cleanup ──
cleanup() {
  kill $BACKEND_PID 2>/dev/null || true
  kill $SHIELD_PID 2>/dev/null || true
}
trap cleanup EXIT

echo -e "\n${BOLD}${CYAN}🛡️  Shield Guard — Test Suite${NC}\n"

# ── Build ──
echo -e "${BOLD}Build${NC}"
if npm run build --prefix "$(dirname "$0")" > /dev/null 2>&1; then
  SIZE=$(wc -c < "$(dirname "$0")/shield.js" | tr -d ' ')
  pass "Build successful ($(( SIZE / 1024 ))KB)"
else
  fail "Build" "success" "failed"
  exit 1
fi

# ── Start backend ──
echo -e "\n${BOLD}Setup${NC}"
node -e "require('http').createServer((q,s)=>{s.writeHead(200,{'Content-Type':'text/plain'});s.end('OK from backend')}).listen($BACKEND_PORT)" &
BACKEND_PID=$!
sleep 1

if curl -s "http://localhost:$BACKEND_PORT" | grep -q "OK from backend"; then
  pass "Backend started on :$BACKEND_PORT"
else
  fail "Backend start" "OK" "failed"
  exit 1
fi

# ── Start shield ──
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
node "$SCRIPT_DIR/shield.js" --target "http://localhost:$BACKEND_PORT" --port $PORT &
SHIELD_PID=$!
sleep 2

if curl -s "$BASE/shield-health" | grep -q '"status":"ok"'; then
  pass "Shield started on :$PORT"
else
  fail "Shield start" "ok" "failed"
  exit 1
fi

# ════════════════════════════════════════════════════════════════════════
# TESTS
# ════════════════════════════════════════════════════════════════════════

echo -e "\n${BOLD}Proxy${NC}"
check_status   "Normal GET request"                  "$BASE/"                         200
check_contains "Proxied response body"               "$BASE/"                         "OK from backend"
check_status   "Non-existent path"                   "$BASE/nonexistent"              200

echo -e "\n${BOLD}Health & Dashboard${NC}"
check_status   "Health endpoint"                     "$BASE/shield-health"            200
check_contains "Health JSON body"                    "$BASE/shield-health"            '"status":"ok"'
check_status   "Dashboard page"                      "$BASE/shield-dashboard"         200
check_contains "Dashboard HTML"                      "$BASE/shield-dashboard"         "Shield Guard"
check_status   "Metrics API"                         "$BASE/shield-api/metrics"       200
check_contains "Metrics has totalPackets"             "$BASE/shield-api/metrics"       "totalPackets"
check_status   "Stats API"                           "$BASE/shield-api/stats"         200
check_status   "Events API"                          "$BASE/shield-api/events"        200
check_status   "Unknown API route"                   "$BASE/shield-api/nonexistent"   404

echo -e "\n${BOLD}Demo Page${NC}"
check_status   "Demo page loads"                     "$BASE/shield-demo"              200
check_contains "Demo page HTML"                      "$BASE/shield-demo"              "Attack Playground"

echo -e "\n${BOLD}WAF — SQL Injection${NC}"
check_status   "SQLi: UNION SELECT"                  "$BASE/?id=1+UNION+SELECT+*+FROM+users"  403
check_status   "SQLi: OR 1=1"                        "$BASE/?id=1'+OR+1=1--"                    403
check_status   "SQLi: DROP TABLE"                    "$BASE/?q=1;DROP+TABLE+users"              403
check_status   "SQLi: WAITFOR DELAY"                 "$BASE/?q=waitfor+delay+'0:0:5'"           403
check_status   "SQLi: safe query passes"             "$BASE/?q=hello+world"                     200

echo -e "\n${BOLD}WAF — XSS${NC}"
check_status   "XSS: <script> tag"                   "$BASE/?q=<script>alert(1)</script>"       403
check_status   "XSS: onerror handler"                "$BASE/?q=<img+src=x+onerror=alert(1)>"   403
check_status   "XSS: javascript: URI"                "$BASE/?q=javascript:alert(1)"             403
check_status   "XSS: safe HTML passes"               "$BASE/?q=hello+<b>world</b>"              200

echo -e "\n${BOLD}WAF — Path Traversal${NC}"
check_status   "Path traversal: ../etc/passwd"       "$BASE/../../../etc/passwd"                403
check_status   "Path traversal: encoded"             "$BASE/%2e%2e%2fetc%2fpasswd"              403
check_status   "Path traversal: .env"                "$BASE/.env"                               403
check_status   "Path traversal: .git"                "$BASE/.git"                               403
check_status   "Path traversal: safe path"           "$BASE/api/users"                          200

echo -e "\n${BOLD}WAF — Command Injection${NC}"
check_status   "CMDi: ;cat /etc/passwd"              "$BASE/?cmd=;cat+/etc/passwd"              403
check_status   "CMDi: | whoami"                      "$BASE/?cmd=|whoami"                       403
check_status   "CMDi: \$(command)"                   "$BASE/?cmd=\$(id)"                        403

echo -e "\n${BOLD}Bot Detection${NC}"
check_status   "Bot: empty user-agent"               "$BASE/"  200  "-H 'User-Agent:'"
check_status   "Bot: python-requests"                "$BASE/"  200  "-H 'User-Agent: python-requests/2.28'"
check_status   "Bot: sqlmap"                         "$BASE/"  200  "-H 'User-Agent: sqlmap/1.7'"

echo -e "\n${BOLD}UAM Control${NC}"
check_status   "UAM: activate"                       "$BASE/shield-api/uam/on"                 200
check_contains "UAM: activate response"              "$BASE/shield-api/uam/on"                 '"uamActive":true'
# When UAM is on, normal request should get challenge page (200 with JS challenge)
check_status   "UAM: request gets challenge"         "$BASE/"                                  200
check_contains "UAM: challenge page content"         "$BASE/"                                  "Checking your browser"
check_status   "UAM: deactivate"                     "$BASE/shield-api/uam/off"                200
check_contains "UAM: deactivate response"            "$BASE/shield-api/uam/off"                '"uamActive":false'
check_status   "UAM: normal request after deactivate" "$BASE/"                                 200

echo -e "\n${BOLD}Metrics Tracking${NC}"
METRICS=$(curl -s "$BASE/shield-api/metrics")
TOTAL=$(echo "$METRICS" | grep -o '"totalPackets":[0-9]*' | head -1 | cut -d: -f2)
DROPPED=$(echo "$METRICS" | grep -o '"totalDropped":[0-9]*' | head -1 | cut -d: -f2)
if [[ "$TOTAL" -gt 0 ]]; then
  pass "Total packets tracked: $TOTAL"
else
  fail "Total packets tracked" ">0" "$TOTAL"
fi
if [[ "$DROPPED" -gt 0 ]]; then
  pass "Dropped requests tracked: $DROPPED"
else
  fail "Dropped requests tracked" ">0" "$DROPPED"
fi
L7=$(echo "$METRICS" | grep -o '"l7":[0-9]*' | head -1 | cut -d: -f2)
if [[ "$L7" -gt 0 ]]; then
  pass "L7 threats tracked: $L7"
else
  fail "L7 threats tracked" ">0" "$L7"
fi

# ════════════════════════════════════════════════════════════════════════
# BENCHMARK (optional)
# ════════════════════════════════════════════════════════════════════════

if [[ "$1" == "--benchmark" ]]; then
  echo -e "\n${BOLD}${CYAN}Benchmark${NC}"

  if command -v ab &>/dev/null; then
    echo -e "  ${DIM}Running Apache Bench: 5000 requests, 50 concurrent${NC}"
    AB_OUT=$(ab -n 5000 -c 50 -q "$BASE/" 2>&1)
    RPS=$(echo "$AB_OUT" | grep "Requests per second" | awk '{print $4}')
    P50=$(echo "$AB_OUT" | grep "50%" | awk '{print $2}')
    P99=$(echo "$AB_OUT" | grep "99%" | awk '{print $2}')
    FAILED=$(echo "$AB_OUT" | grep "Failed requests" | awk '{print $3}')
    echo -e "  ${GREEN}→${NC} RPS:     ${BOLD}$RPS${NC} req/s"
    echo -e "  ${GREEN}→${NC} P50:     ${P50}ms"
    echo -e "  ${GREEN}→${NC} P99:     ${P99}ms"
    echo -e "  ${GREEN}→${NC} Failed:  $FAILED"
  else
    echo -e "  ${DIM}Running curl-based benchmark: 1000 requests, 20 concurrent${NC}"
    START_TIME=$(date +%s%N)
    for i in $(seq 1 50); do
      for j in $(seq 1 20); do
        curl -s -o /dev/null "$BASE/" &
      done
      wait
    done
    END_TIME=$(date +%s%N)
    ELAPSED=$(( (END_TIME - START_TIME) / 1000000 ))
    RPS=$(( 1000 * 1000 / ELAPSED ))
    echo -e "  ${GREEN}→${NC} 1000 requests in ${ELAPSED}ms"
    echo -e "  ${GREEN}→${NC} ~${BOLD}${RPS}${NC} req/s"
  fi

  echo -e "\n  ${DIM}Attack benchmark: 500 mixed malicious requests${NC}"
  ATTACK_START=$(date +%s%N)
  for i in $(seq 1 25); do
    for j in $(seq 1 20); do
      case $((j % 4)) in
        0) curl -s -o /dev/null "$BASE/?id=1'+OR+1=1--" ;;
        1) curl -s -o /dev/null "$BASE/?q=<script>alert(1)</script>" ;;
        2) curl -s -o /dev/null "$BASE/../../../etc/passwd" ;;
        3) curl -s -o /dev/null "$BASE/?cmd=;cat+/etc/passwd" ;;
      esac &
    done
    wait
  done
  ATTACK_END=$(date +%s%N)
  ATTACK_ELAPSED=$(( (ATTACK_END - ATTACK_START) / 1000000 ))
  ATTACK_RPS=$(( 500 * 1000 / ATTACK_ELAPSED ))
  echo -e "  ${GREEN}→${NC} 500 attacks blocked in ${ATTACK_ELAPSED}ms"
  echo -e "  ${GREEN}→${NC} ~${BOLD}${ATTACK_RPS}${NC} blocks/s"

  FINAL_METRICS=$(curl -s "$BASE/shield-api/metrics")
  AVG_TIME=$(echo "$FINAL_METRICS" | grep -o '"avgProcessingTimeUs":[0-9.]*' | cut -d: -f2)
  echo -e "  ${GREEN}→${NC} Avg processing: ${BOLD}${AVG_TIME}µs${NC}/req"
fi

# ════════════════════════════════════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════════════════════════════════════

echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${RED}Failed:${NC}  $FAIL"
echo -e "  ${YELLOW}Skipped:${NC} $SKIP"
echo -e "  ${BOLD}Total:${NC}   $(( PASS + FAIL + SKIP ))"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ $FAIL -gt 0 ]]; then
  echo -e "\n  ${RED}${BOLD}SOME TESTS FAILED${NC}\n"
  exit 1
else
  echo -e "\n  ${GREEN}${BOLD}ALL TESTS PASSED ✓${NC}\n"
  exit 0
fi
