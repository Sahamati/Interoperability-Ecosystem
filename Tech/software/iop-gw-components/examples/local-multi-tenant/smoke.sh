#!/usr/bin/env bash
# Calls through the multi-tenant example, both FIUs, both directions:
#  1. each FIU's core sends a Consent request to aa-test-004 (Customer-AA) through
#     aa-test-002 (Connected-AA), naming its FIU with Core-Entity-Id;
#  2. a call without Core-Entity-Id is refused (two FIUs are loaded);
#  3. aa-test-004's core sends a Consent Notification to each FIU; gw-fiu finds the
#     FIU from the JWE kid and calls that FIU's core.
# Exits non-zero on the first unexpected answer.
set -euo pipefail
cd "$(dirname "$0")"
. ./.env
FIU_GW=http://127.0.0.1:18181
AA_GW=http://127.0.0.1:18184
fail() { echo "FAIL: $*"; exit 1; }
uuid() { cat /proc/sys/kernel/random/uuid; }

call() { # url, then curl arguments; prints "status body"
  local url=$1; shift
  local out; out=$(mktemp)
  local status; status=$(curl -sS -o "$out" -w '%{http_code}' "$url" "$@")
  echo "$status $(cat "$out")"; rm -f "$out"
}

for fiu in fiu-test-001 fiu-test-005; do
  var="IOPGW_GWAPI_TOKEN_$(echo "$fiu" | tr 'a-z-' 'A-Z_')"
  r=$(call "$FIU_GW/fiu-dgw/Consent" -X POST \
    -H "Authorization: Bearer ${!var}" -H "Core-Entity-Id: $fiu" \
    -H 'Target-Entity: {"type":"AA","id":"aa-test-004"}' -H "Correlation-Id: $(uuid)" \
    --data "{\"ver\":\"2.0.0\",\"txnid\":\"$(uuid)\",\"ConsentDetail\":{}}")
  [[ $r == 200* ]] || fail "$fiu -> aa-test-004: $r"
  echo "ok   $fiu -> aa-test-004 (via aa-test-002): $r"
done

r=$(call "$FIU_GW/fiu-dgw/Consent" -X POST -H "Authorization: Bearer $IOPGW_GWAPI_TOKEN_FIU_TEST_001" \
  -H 'Target-Entity: {"type":"AA","id":"aa-test-004"}' -H "Correlation-Id: $(uuid)" \
  --data "{\"ver\":\"2.0.0\",\"txnid\":\"$(uuid)\"}")
[[ $r == 400*"Core-Entity-Id header is required"* ]] || fail "no Core-Entity-Id: $r"
echo "ok   no Core-Entity-Id with two FIUs loaded: $r"

for fiu in fiu-test-001 fiu-test-005; do
  r=$(call "$AA_GW/aa-dgw/Consent/Notification" -X POST -H "Authorization: Bearer $IOPGW_API_TOKEN" \
    -H "Target-Entity: {\"type\":\"FIU\",\"id\":\"$fiu\"}" -H "Correlation-Id: $(uuid)" \
    --data "{\"ver\":\"2.0.0\",\"txnid\":\"$(uuid)\",\"ConsentStatusNotification\":{\"consentStatus\":\"ACTIVE\"}}")
  [[ $r == 200*"core-$fiu"* ]] || fail "aa-test-004 -> $fiu: $r"
  echo "ok   aa-test-004 -> $fiu (via aa-test-002), answered by core-$fiu"
done
echo "PASS"
