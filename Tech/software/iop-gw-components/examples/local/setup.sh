#!/usr/bin/env bash
# Generates throwaway, synthetic material for the local example into ./generated:
# for each entity a signing and an encryption RSA key pair and a token-service
# credentials file; a TLS certificate for the gateways' internal HTTPS listener;
# and .env with the internal API token. Testing only: never reuse these.
#
# The files are made readable by the containers' non-root users (mode 0644),
# which is acceptable only because everything here is synthetic.
set -euo pipefail
cd "$(dirname "$0")"
umask 022
G=generated
rm -rf "$G"; mkdir -p "$G"
for id in fiu-test-001 aa-test-002 fip-test-003 aa-test-004; do
  mkdir -p "$G/$id"
  for use in sig enc; do
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$G/$id/$use.pem" 2>/dev/null
    openssl pkey -in "$G/$id/$use.pem" -pubout -out "$G/$id/$use.pub.pem"
  done
  printf '{"entityId":"%s","entitySecret":"%s"}\n' "$id" "$(openssl rand -hex 24)" > "$G/$id/credentials.json"
done
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=iop-gw local example (testing only)" \
  -keyout "$G/gw-tls.key" -out "$G/gw-tls.crt" 2>/dev/null
chmod -R a+rX "$G"
printf 'IOPGW_API_TOKEN=%s\n' "$(openssl rand -hex 24)" > .env
echo "generated synthetic keys, credentials and .env in $(pwd)"
