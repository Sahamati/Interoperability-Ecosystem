#!/usr/bin/env bash
#
# IOP Gateway mock setup on Kubernetes, with iop-gw-mocks in place of the Sahamati
# services. For testing and evaluation only: every identity and key it creates
# is synthetic.
#
# It installs, in one namespace of the cluster you name:
#   - iop-gw-mocks (token service, Central Registry and AIG), with a stable TLS
#     certificate and token-signing key, so a restart changes nothing;
#   - four IOP Gateways, wired to the mocks and to each other:
#       fiu-test-001 (FIU) -> aa-test-002 (AA, the FIU's Connected-AA) -> aa-test-004 (AA)
#       aa-test-004 (AA)   -> aa-test-002 (AA, the FIP's Inter-AA)     -> fip-test-003 (FIP);
#   - a stand-in core, for any gateway whose core URL is not configured.
#
# Settings are in mock-setup.yaml, next to this script. See MOCK_SETUP.md,
# section 8, for details.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HELM_DIR="$(cd "$HERE/../.." && pwd)"
COMPONENTS_DIR="$(cd "$HELM_DIR/.." && pwd)"
GEN="$HERE/generated"

CONFIG="$HERE/mock-setup.yaml"
TRUSTSTORE_PASSWORD="changeit"

FIU=fiu-test-001
HOP=aa-test-002
TARGET=aa-test-004
FIP=fip-test-003
ENTITIES="$FIU $HOP $TARGET $FIP"

usage() {
  cat <<EOF
Usage: $(basename "$0") <install|test|uninstall>

Commands:
  install     Create the keys and Secrets (once) and install the mocks, four
              gateways and, for any core not configured, a stand-in core.
              Run it again after changing mock-setup.yaml.
  test        Make two calls: $FIU -> $HOP -> $TARGET's core, and
              $TARGET -> $HOP -> $FIP's core.
  uninstall   Remove everything this script installed (the namespace) and the
              generated files.

Settings (kube context, namespace, images, core URLs) are read from
mock-setup.yaml next to this script.
EOF
}

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# Reads "key" or "section.key" from mock-setup.yaml (a flat, two-level file).
setting() {
  awk -v want="$1" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    /^[^[:space:]]/ { split($0, a, ":"); section = a[1]; key = section; sub(/^[^:]*:[[:space:]]*/, ""); if (key == want) val = $0; next }
    { line = $0; sub(/^[[:space:]]+/, "", line); split(line, a, ":"); key = section "." a[1];
      sub(/^[^:]*:[[:space:]]*/, "", line); if (key == want) val = line }
    END { sub(/[[:space:]]+#.*$/, "", val); gsub(/^"|"$/, "", val); print val }
  ' "$CONFIG"
}

[ $# -eq 1 ] || { usage; exit 1; }
COMMAND="$1"
case "$COMMAND" in install|test|uninstall) ;; -h|--help) usage; exit 0 ;; *) die "unknown command: $COMMAND (see --help)" ;; esac
[ -f "$CONFIG" ] || die "configuration not found: $CONFIG"

CONTEXT="$(setting context)"
NAMESPACE="$(setting namespace)"
GW_IMAGE="$(setting images.gateway)"
MOCKS_IMAGE="$(setting images.mocks)"
CORE_IMAGE="$(setting images.coreStub)"
[ -n "$CONTEXT" ] || die "set 'context' in $CONFIG (list your contexts with: kubectl config get-contexts)"
[ -n "$NAMESPACE" ] || die "set 'namespace' in $CONFIG"
[ -n "$GW_IMAGE" ] && [ -n "$MOCKS_IMAGE" ] || die "set images.gateway and images.mocks in $CONFIG"

for tool in kubectl helm openssl; do
  command -v "$tool" >/dev/null || die "$tool is required but was not found"
done
kubectl config get-contexts -o name | grep -qx "$CONTEXT" || die "kube context '$CONTEXT' (from $CONFIG) not found"

# The URL of each gateway's core: the configured one, or the stand-in core.
core_url() {
  local u; u="$(setting "cores.$1")"
  if [ -n "$u" ]; then echo "$u"; else echo "http://core-stub.$NAMESPACE.svc:8090"; fi
}
stub_needed() {
  local id
  for id in $ENTITIES; do [ -z "$(setting "cores.$id")" ] && return 0; done
  return 1
}

k() { kubectl --context "$CONTEXT" -n "$NAMESPACE" "$@"; }
h() { helm --kube-context "$CONTEXT" -n "$NAMESPACE" "$@"; }
repo() { echo "${1%:*}"; }
tag() { echo "${1##*:}"; }
type_of() { case "$1" in fiu-*) echo FIU ;; aa-*) echo AA ;; fip-*) echo FIP ;; esac; }
apply_secret() { # name, then kubectl create secret generic arguments
  local name="$1"; shift
  k create secret generic "$name" "$@" --dry-run=client -o yaml | k apply -f - >/dev/null
}

# ---------------------------------------------------------------------------

generate() {
  if [ -f "$GEN/.complete" ]; then
    info "Using the keys already generated in $GEN"
    return
  fi
  info "Generating synthetic keys and credentials in $GEN"
  rm -rf "$GEN"
  mkdir -p "$GEN"
  chmod 700 "$GEN"
  umask 077

  for id in $ENTITIES; do
    mkdir -p "$GEN/$id"
    for use in signing decryption; do
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$GEN/$id/$use.pem" 2>/dev/null
      openssl pkey -in "$GEN/$id/$use.pem" -pubout -out "$GEN/$id/$use.pub.pem"
    done
    printf '{"entityId":"%s","entitySecret":"%s"}\n' "$id" "$(openssl rand -hex 24)" > "$GEN/$id/credentials.json"
  done

  # The internal API certificate the gateways serve to their cores.
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=iop-gw internal API (mock setup)" \
    -keyout "$GEN/gw-tls.key" -out "$GEN/gw-tls.crt" 2>/dev/null

  # The mocks' TLS certificate (valid for their Service name) and token-signing key.
  mkdir -p "$GEN/mocks"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=iop-gw-mocks (mock setup)" \
    -addext "subjectAltName=DNS:mocks,DNS:mocks.$NAMESPACE.svc,DNS:mocks.$NAMESPACE.svc.cluster.local" \
    -keyout "$GEN/mocks/tls.key" -out "$GEN/mocks/tls.crt" 2>/dev/null
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$GEN/mocks/signing.pem" 2>/dev/null

  # A truststore holding the mocks' certificate, for the gateways' JVMs.
  if command -v keytool >/dev/null; then
    keytool -importcert -noprompt -alias iop-gw-mocks -file "$GEN/mocks/tls.crt" \
      -keystore "$GEN/mocks/truststore.p12" -storetype PKCS12 -storepass "$TRUSTSTORE_PASSWORD" >/dev/null
  elif command -v docker >/dev/null; then
    docker run --rm --user "$(id -u):$(id -g)" -v "$GEN/mocks:/work" --entrypoint keytool "eclipse-temurin:21.0.13_9-jre-noble" \
      -importcert -noprompt -alias iop-gw-mocks -file /work/tls.crt \
      -keystore /work/truststore.p12 -storetype PKCS12 -storepass "$TRUSTSTORE_PASSWORD" >/dev/null
  else
    die "keytool (from a JDK or JRE) or docker is required to create the truststore"
  fi

  openssl rand -hex 24 > "$GEN/internal-api-token"
  touch "$GEN/.complete"
}

write_values() {
  local f="$GEN/mocks-values.yaml"
  {
    echo "image: {repository: \"$(repo "$MOCKS_IMAGE")\", tag: \"$(tag "$MOCKS_IMAGE")\"}"
    echo "keysSecret: mocks-keys"
    echo "inputSecret: mocks-input"
    echo "config:"
    echo "  tokenService:"
    echo "    issuer: \"https://mock-token-service.local/realms/sahamati\""
    echo "    credentialsFiles:"
    for id in $ENTITIES; do echo "      - /etc/iop-gw-mocks/input/$id-credentials.json"; done
    echo "  entities:"
    for id in $ENTITIES; do
      echo "    - id: $id"
      echo "      type: $(type_of "$id")"
      echo "      baseUrl: \"http://gw-$id-iop-gw.$NAMESPACE.svc:8080\""
      echo "      signingPublicKeys: [{kid: $id-sig, file: /etc/iop-gw-mocks/input/$id-signing.pub.pem}]"
      echo "      encryptionPublicKeys: [{kid: $id-enc, file: /etc/iop-gw-mocks/input/$id-decryption.pub.pem}]"
    done
    echo "  aig:"
    echo "    fiu: [{$FIU: [$HOP]}]           # $HOP is $FIU's Connected-AA"
    echo "    fip: [{$FIP: [$HOP]}]           # $HOP is $FIP's Inter-AA"
    echo "    aa:  [{$HOP: [$TARGET]}]        # the two AAs peer with each other"
  } > "$f"

  gw_values "$FIU" FIU "$HOP" "$(core_url "$FIU")"
  gw_values "$HOP" AA "$TARGET" "$(core_url "$HOP")"
  gw_values "$TARGET" AA "$HOP" "$(core_url "$TARGET")"
  gw_values "$FIP" FIP "$HOP" "$(core_url "$FIP")"
}

gw_values() { # id mode linked-aa core-url
  cat > "$GEN/gw-$1-values.yaml" <<EOF
image: {repository: "$(repo "$GW_IMAGE")", tag: "$(tag "$GW_IMAGE")"}
secretEnv: {existingSecret: iop-gw-env}
files: {existingSecret: gw-$1-files}
config:
  mode: $2
  self:
    id: $1
    signingKey: {source: file, kid: $1-sig, file: /etc/iop-gw/secrets/signing.pem}
    decryptionKeys: {source: file, keys: [{kid: $1-enc, file: /etc/iop-gw/secrets/decryption.pem}]}
  core: {baseUrl: "$4", timeoutSeconds: 10}
  linkedAAs: {source: config, aas: [$3]}
EOF
}

install() {
  generate
  write_values

  info "Preparing namespace $NAMESPACE (context $CONTEXT)"
  kubectl --context "$CONTEXT" create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f - >/dev/null

  info "Creating Secrets"
  apply_secret mocks-keys --from-file=tls.crt="$GEN/mocks/tls.crt" --from-file=tls.key="$GEN/mocks/tls.key" \
    --from-file=signing.pem="$GEN/mocks/signing.pem"
  local input=()
  for id in $ENTITIES; do
    input+=(--from-file="$id-credentials.json=$GEN/$id/credentials.json"
            --from-file="$id-signing.pub.pem=$GEN/$id/signing.pub.pem"
            --from-file="$id-decryption.pub.pem=$GEN/$id/decryption.pub.pem")
  done
  apply_secret mocks-input "${input[@]}"
  apply_secret mocks-truststore --from-file=truststore.p12="$GEN/mocks/truststore.p12"
  apply_secret iop-gw-env --from-literal=IOPGW_API_TOKEN="$(cat "$GEN/internal-api-token")"
  for id in $ENTITIES; do
    apply_secret "gw-$id-files" --from-file=signing.pem="$GEN/$id/signing.pem" \
      --from-file=decryption.pem="$GEN/$id/decryption.pem" --from-file=credentials.json="$GEN/$id/credentials.json" \
      --from-file=gw-tls.crt="$GEN/gw-tls.crt" --from-file=gw-tls.key="$GEN/gw-tls.key"
  done

  info "Installing iop-gw-mocks"
  h upgrade --install mocks "$HELM_DIR/iop-gw-mocks" -f "$GEN/mocks-values.yaml" --wait --timeout 3m >/dev/null

  if stub_needed; then
    info "Installing the stand-in core (for the cores not set in mock-setup.yaml)"
    k create configmap core-stub --from-file=core-stub.py="$COMPONENTS_DIR/examples/local/core-stub.py" \
      --dry-run=client -o yaml | k apply -f - >/dev/null
    k apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: core-stub, labels: {app: core-stub}}
spec:
  selector: {matchLabels: {app: core-stub}}
  template:
    metadata: {labels: {app: core-stub}}
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 10003, runAsGroup: 10003, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: core
          image: $CORE_IMAGE
          command: ["python", "/core/core-stub.py"]
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          ports: [{containerPort: 8090}]
          volumeMounts: [{name: code, mountPath: /core}]
      volumes: [{name: code, configMap: {name: core-stub}}]
---
apiVersion: v1
kind: Service
metadata: {name: core-stub}
spec: {selector: {app: core-stub}, ports: [{port: 8090, targetPort: 8090}]}
EOF
  else
    k delete deploy/core-stub svc/core-stub configmap/core-stub --ignore-not-found >/dev/null
  fi

  for id in $ENTITIES; do
    info "Installing the IOP Gateway for $id"
    h upgrade --install "gw-$id" "$HELM_DIR/iop-gw" -f "$GEN/gw-$id-values.yaml" >/dev/null
  done
  for id in $ENTITIES; do
    k rollout status "deploy/gw-$id-iop-gw" --timeout=5m >/dev/null
  done
  if stub_needed; then k rollout status deploy/core-stub --timeout=3m >/dev/null; fi

  for id in $ENTITIES; do
    if [ -z "$(setting "cores.$id")" ]; then echo "    $id: stand-in core"; else echo "    $id: $(core_url "$id")"; fi
  done
  info "Installed. Make a test call with: $0 test"
}

call() { # from-entity internal-api-path target-type target-id
  local out
  out="$(k exec "deploy/gw-$1-iop-gw" -- curl -sk -D - -o /dev/null "https://localhost:8443$2" \
    -H "Authorization: Bearer $(cat "$GEN/internal-api-token")" \
    -H "Target-Entity: {\"type\":\"$3\",\"id\":\"$4\"}" \
    -H "Correlation-Id: $(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)" | tr -d '\r')"
  echo "$out" | grep -iE "^HTTP/|^forwarding-hop|^iop-gw-error" | sed 's/^/    /'
  echo "$out" | head -1 | grep -q " 200"
}

run_test() {
  [ -f "$GEN/internal-api-token" ] || die "nothing installed from this folder yet (run install first)"
  local failed=0
  info "Calling $TARGET through $HOP, from $FIU's internal API"
  if call "$FIU" /fiu-dgw/Heartbeat AA "$TARGET"; then echo "    reached $TARGET's core"; else failed=1; fi
  info "Calling $FIP through $HOP, from $TARGET's internal API"
  if call "$TARGET" /aa-sgw/Heartbeat FIP "$FIP"; then echo "    reached $FIP's core"; else failed=1; fi
  [ "$failed" = 0 ] || die "a call did not succeed; see the gateways' logs, e.g. kubectl --context $CONTEXT -n $NAMESPACE logs deploy/gw-$FIU-iop-gw"
  info "Success: both calls reached their target's core"
}

uninstall() {
  info "Removing namespace $NAMESPACE (context $CONTEXT)"
  kubectl --context "$CONTEXT" delete namespace "$NAMESPACE" --ignore-not-found --wait=true >/dev/null
  rm -rf "$GEN"
  info "Removed"
}

case "$COMMAND" in
  install) install ;;
  test) run_test ;;
  uninstall) uninstall ;;
esac
