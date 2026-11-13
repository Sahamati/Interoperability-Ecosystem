#!/usr/bin/env bash
# One call through the local example: fiu-test-001's core asks its gateway for a
# Heartbeat at aa-test-004 (Customer-AA), through aa-test-002 (Connected-AA).
# On the way: IopTokens from the mock token service, checked against its JWKS at
# both AAs; keys and addresses from the mock CR; the route from the mock AIG.
set -euo pipefail
cd "$(dirname "$0")"
. ./.env
corr=$(cat /proc/sys/kernel/random/uuid)
curl -sS -D - -o /tmp/iop-gw-smoke.body "http://127.0.0.1:18081/fiu-dgw/Heartbeat" \
  -H "Authorization: Bearer $IOPGW_API_TOKEN" \
  -H 'Target-Entity: {"type":"AA","id":"aa-test-004"}' \
  -H "Correlation-Id: $corr" | tr -d '\r' | grep -iE "^HTTP/|^forwarding-hop|^correlation-id|^iop-gw-error|^x-jws-signature" | sed 's/^\(x-jws-signature: .\{30\}\).*/\1…/'
echo "body: $(cat /tmp/iop-gw-smoke.body)"
