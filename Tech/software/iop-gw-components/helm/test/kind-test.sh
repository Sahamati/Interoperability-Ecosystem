#!/usr/bin/env bash
# Installs the iop-gw chart into a local kind cluster with iop-gw-mocks, and
# makes one call: fiu-test-001 -> aa-test-002 (hop) -> aa-test-004's core.
# Testing only: synthetic keys from examples/local (run its setup.sh first).
#
#   kind create cluster --name iop-gw-test
#   kind load docker-image iop-gw:0.0.0.0 iop-gw-mocks:0.0.0.0 python:3.13-alpine --name iop-gw-test
#   ./kind-test.sh              # install and test (small: memory-only cache, internal HTTP and HTTPS)
#   ./kind-test.sh production   # production settings: RocksDB cache on a PersistentVolumeClaim
#                               # (StatefulSet), internal APIs over HTTPS only, the chart's default
#                               # resources; then restarts a gateway and checks it comes back from its cache
#   ./kind-test.sh clean        # delete the namespace
#   kind delete cluster --name iop-gw-test
set -euo pipefail
cd "$(dirname "$0")"
CTX=${CTX:-kind-iop-gw-test}
NS=iop-gw-test
case "$CTX" in kind-*) ;; *) echo "refusing: $CTX is not a kind cluster" >&2; exit 1;; esac
k() { kubectl --context "$CTX" -n "$NS" "$@"; }
GEN=../../examples/local/generated
CHART=../iop-gw

if [ "${1:-}" = clean ]; then kubectl --context "$CTX" delete namespace "$NS" --ignore-not-found; exit 0; fi
PROD=false; [ "${1:-}" = production ] && PROD=true
KIND=deploy; $PROD && KIND=statefulset
[ -d "$GEN" ] || { echo "run ../../examples/local/setup.sh first" >&2; exit 1; }
. ../../examples/local/.env

kubectl --context "$CTX" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null
IDS="fiu-test-001 aa-test-002 aa-test-004 fip-test-003"

# --- iop-gw-mocks: token service, Central Registry, AIG ---
args=()
for id in $IDS; do
  args+=(--from-file="$id-sig.pub.pem=$GEN/$id/sig.pub.pem" --from-file="$id-enc.pub.pem=$GEN/$id/enc.pub.pem"
         --from-file="$id-credentials.json=$GEN/$id/credentials.json")
done
k create secret generic mocks-input "${args[@]}" --dry-run=client -o yaml | k apply -f - >/dev/null
{
  echo 'listenAddr: "0.0.0.0:9443"'
  echo 'outDir: /var/lib/iop-gw-mocks/out'
  echo "tlsHosts: [mocks, mocks.$NS.svc, localhost]"
  echo 'tokenService:'
  echo '  issuer: "https://mock-token-service.local/realms/sahamati"'
  echo '  credentialsFiles:'
  for id in $IDS; do echo "    - /etc/iop-gw-mocks/input/$id-credentials.json"; done
  echo 'entities:'
  for id in $IDS; do
    type=$(echo "${id%%-*}" | tr a-z A-Z)
    echo "  - id: $id"
    echo "    type: $type"
    echo "    baseUrl: \"http://gw-$id-iop-gw.$NS.svc:8080\""
    echo "    signingPublicKeys: [{kid: $id-sig, file: /etc/iop-gw-mocks/input/$id-sig.pub.pem}]"
    echo "    encryptionPublicKeys: [{kid: $id-enc, file: /etc/iop-gw-mocks/input/$id-enc.pub.pem}]"
  done
  echo 'aig:'
  echo '  fiu: [{fiu-test-001: [aa-test-002]}]'
  echo '  fip: [{fip-test-003: [aa-test-002]}]'
  echo '  aa:  [{aa-test-002: [aa-test-004]}]'
} > /tmp/iop-gw-kind-mocks.yaml
k create configmap mocks-config --from-file=mocks.yaml=/tmp/iop-gw-kind-mocks.yaml --dry-run=client -o yaml | k apply -f - >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: mocks}
spec:
  selector: {matchLabels: {app: mocks}}
  template:
    metadata: {labels: {app: mocks}}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 10002, runAsGroup: 10002, fsGroup: 10002}
      containers:
        - name: mocks
          image: iop-gw-mocks:0.0.0.0
          imagePullPolicy: Never
          args: ["/etc/iop-gw-mocks/mocks.yaml"]
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          ports: [{containerPort: 9443}]
          readinessProbe: {httpGet: {path: /healthz, port: 9443, scheme: HTTPS}, periodSeconds: 2}
          volumeMounts:
            - {name: config, mountPath: /etc/iop-gw-mocks/mocks.yaml, subPath: mocks.yaml}
            - {name: input, mountPath: /etc/iop-gw-mocks/input}
            - {name: out, mountPath: /var/lib/iop-gw-mocks/out}
            - {name: tmp, mountPath: /tmp}
      volumes:
        - {name: config, configMap: {name: mocks-config}}
        - {name: input, secret: {secretName: mocks-input, defaultMode: 0440}}
        - {name: out, emptyDir: {}}
        - {name: tmp, emptyDir: {medium: Memory}}
---
apiVersion: v1
kind: Service
metadata: {name: mocks}
spec: {selector: {app: mocks}, ports: [{port: 9443, targetPort: 9443}]}
YAML
k rollout status deploy/mocks --timeout=120s
k exec deploy/mocks -- cat /var/lib/iop-gw-mocks/out/truststore.p12 > /tmp/iop-gw-kind-truststore.p12
k create secret generic iop-gw-truststore --from-file=truststore.p12=/tmp/iop-gw-kind-truststore.p12 --dry-run=client -o yaml | k apply -f - >/dev/null

# --- a stand-in core for aa-test-004 ---
k create configmap core-stub --from-file=core-stub.py=../../examples/local/core-stub.py --dry-run=client -o yaml | k apply -f - >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: core-aa-test-004}
spec:
  selector: {matchLabels: {app: core-aa-test-004}}
  template:
    metadata: {labels: {app: core-aa-test-004}}
    spec:
      containers:
        - name: core
          image: python:3.13-alpine
          imagePullPolicy: IfNotPresent
          command: ["python", "/core/core-stub.py"]
          volumeMounts: [{name: code, mountPath: /core}]
      volumes: [{name: code, configMap: {name: core-stub}}]
---
apiVersion: v1
kind: Service
metadata: {name: core-aa-test-004}
spec: {selector: {app: core-aa-test-004}, ports: [{port: 8090, targetPort: 8090}]}
YAML

# --- three gateways, installed with the chart, Secrets as a client would create them ---
k create secret generic iop-gw-env --from-literal=IOPGW_API_TOKEN="$IOPGW_API_TOKEN" --dry-run=client -o yaml | k apply -f - >/dev/null
gateway() { # id mode linked-aa
  local id=$1 mode=$2 linked=$3
  k create secret generic "gw-$id-files" \
    --from-file=signing.pem="$GEN/$id/sig.pem" --from-file=decryption.pem="$GEN/$id/enc.pem" \
    --from-file=credentials.json="$GEN/$id/credentials.json" \
    --from-file=gw-tls.crt="$GEN/gw-tls.crt" --from-file=gw-tls.key="$GEN/gw-tls.key" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  cat > "/tmp/iop-gw-kind-values-$id.yaml" <<VALUES
image: {repository: iop-gw, tag: "0.0.0.0", pullPolicy: Never}
secretEnv: {existingSecret: iop-gw-env}
files: {existingSecret: gw-$id-files}
truststore: {existingSecret: iop-gw-truststore}
$($PROD || echo 'resources: {requests: {cpu: 100m, memory: 256Mi}, limits: {memory: 768Mi}}')
config:
  mode: $mode
  self:
    id: $id
    signingKey: {source: file, kid: $id-sig, file: /etc/iop-gw/secrets/signing.pem}
    decryptionKeys: {source: file, keys: [{kid: $id-enc, file: /etc/iop-gw/secrets/decryption.pem}]}
  core: {baseUrl: "http://core-$id:8090", timeoutSeconds: 10}
  tokenService: {baseUrl: "https://mocks:9443", credentialsFile: /etc/iop-gw/secrets/credentials.json}
  apiKey: {mode: jwt, issuerKeysUrl: "https://mocks:9443/tokenservice/jwks", issuer: "https://mock-token-service.local/realms/sahamati"}
  cr: {source: api, baseUrl: "https://mocks:9443"}
  aigBaseUrl: "https://mocks:9443"
  linkedAAs: {source: config, aas: [$linked]}
VALUES
  # production: the chart's values-production.yaml, with only test values on top
  # (local image, Secret names, the mocks' URLs and truststore)
  local base=(); $PROD && base=(-f "$CHART/values-production.yaml")
  helm --kube-context "$CTX" -n "$NS" upgrade --install "gw-$id" "$CHART" "${base[@]}" -f "/tmp/iop-gw-kind-values-$id.yaml" >/dev/null
}
gateway fiu-test-001 FIU aa-test-002
gateway aa-test-002 AA aa-test-004
gateway aa-test-004 AA aa-test-002
for id in fiu-test-001 aa-test-002 aa-test-004; do k rollout status "$KIND/gw-$id-iop-gw" --timeout=300s; done

# --- one call, from inside fiu-test-001's pod (as its core would) ---
call() {
  local url="http://localhost:8081/fiu-dgw/Heartbeat" tls=""
  if $PROD; then url="https://localhost:8443/fiu-dgw/Heartbeat"; tls="-k"; fi  # -k: the test's self-signed internal certificate
  echo "== GET $url -> aa-test-004 via aa-test-002"
  k exec "$KIND/gw-fiu-test-001-iop-gw" -- curl -sS $tls -D - -o /tmp/body "$url" \
    -H "Authorization: Bearer $IOPGW_API_TOKEN" -H 'Target-Entity: {"type":"AA","id":"aa-test-004"}' \
    -H "Correlation-Id: $(cat /proc/sys/kernel/random/uuid)" | tr -d '\r' | grep -iE "^HTTP/|^forwarding-hop|^iop-gw-error"
  k exec "$KIND/gw-fiu-test-001-iop-gw" -- cat /tmp/body; echo
}
call

if $PROD; then
  echo "== volumes:"; k get pvc -o 'custom-columns=CLAIM:.metadata.name,STATUS:.status.phase,SIZE:.status.capacity.storage'
  echo "== restart aa-test-002 (the hop): its pod is deleted, a new one mounts the same volume"
  k delete pod gw-aa-test-002-iop-gw-0 --wait=true >/dev/null
  k rollout status statefulset/gw-aa-test-002-iop-gw --timeout=300s
  echo "== what the new pod restored from its RocksDB cache:"
  k logs gw-aa-test-002-iop-gw-0 | grep -o '"msg":"[^"]*restored[^"]*"[^}]*' | cut -c1-120
  call
fi
