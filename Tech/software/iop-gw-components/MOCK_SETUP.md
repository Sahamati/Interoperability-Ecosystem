# iop-gw-mocks: setup guide

`iop-gw-mocks` is a small local stand-in for the three Sahamati services the IOP Gateway depends
on: the **token service**, the **Central Registry (CR)** and the **AA Interoperability Graph
(AIG)**. With it, you can run one or more gateways on their production settings (`cr.source: api`,
`aigSource: api`, tokens from a token service, token signatures checked against a JWKS) on your own
machine, without credentials or a network connection to Sahamati.

> **Testing only.** The mocks are not the real services. Every key they use is generated on your
> machine, every identifier is synthetic, and they keep nothing between restarts. Never point a
> production gateway at them, and never load real keys, secrets or customer data into them.

For installing and configuring the gateway itself, see [SETUP.md](SETUP.md).

---

## Contents

1. [What the mocks do](#1-what-the-mocks-do)
2. [Quick start: the local example](#2-quick-start-the-local-example)
3. [Build and run](#3-build-and-run)
4. [Configuration reference](#4-configuration-reference)
5. [Endpoints](#5-endpoints)
6. [Files the mocks write](#6-files-the-mocks-write)
7. [Point a gateway at the mocks](#7-point-a-gateway-at-the-mocks)
8. [On Kubernetes](#8-on-kubernetes)
9. [Moving to the real services](#9-moving-to-the-real-services)
10. [How the mocks differ from the real services](#10-how-the-mocks-differ-from-the-real-services)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. What the mocks do

One process serves all three services on **one HTTPS port**:

| Service | What it serves |
|---|---|
| Token service | Access tokens and IopTokens for the entities you list, from the same credentials files the gateways use. Tokens are RS256 JWTs signed by a key the mocks generate, and published as a JWKS. |
| Central Registry | `/v2/entityInfo/{AA,FIU,FIP}`: each entity's id, base URL, `interop` flag and public keys (with optional validity windows). |
| AIG | The FIU, FIP and AA graphs, read by the gateways, and the update call AAs use to publish their links. |

The mocks use a TLS certificate and a token-signing key that you give them (section 4), or, if you
give none, generate new ones at every start. Either way, they write the certificate (with a
truststore) and the public signing key to an output folder for the gateways (section 6).

---

## 2. Quick start: the local example

`examples/local` runs the mocks, four gateways (an FIU, two AAs and a FIP) and a stand-in core with
Docker Compose. It is the quickest way to see everything working.

```bash
# 1. Build the two images (only Docker is needed; the first build takes a few minutes)
cd iop-gw-components/iop-gw       && docker build -t iop-gw:0.0.0.0 .
cd ../iop-gw-mocks                && docker build -t iop-gw-mocks:0.0.0.0 .

# 2. Generate synthetic keys, credentials and .env (all git-ignored)
cd ../examples/local
./setup.sh

# 3. Start everything and wait until it is healthy
docker compose up -d --wait

# 4. One call: fiu-test-001 → aa-test-002 (hop) → aa-test-004's core
./smoke.sh

# 5. Stop and remove everything, volumes included
docker compose down -v
```

`smoke.sh` should print `HTTP/1.1 200` and `Forwarding-Hop: aa-test-002`.

What the example contains:

| File | Purpose |
|---|---|
| `setup.sh` | Generates, under `generated/`: a signing and an encryption key pair and a credentials file per entity, the internal API TLS certificate, and `.env` with the internal API token. Running it again replaces them. |
| `mocks.yaml` | The mocks' configuration: the four entities, their keys and the AIG graph. |
| `gateways/*.yaml` | One gateway configuration per entity, all on production sources pointed at `https://mocks:9443`. |
| `compose.yaml` | The services, read-only containers, health checks, and the mocks' truststore given to every gateway. |
| `core-stub.py` | A stand-in core: answers every call `200` and echoes `Correlation-Id`. |
| `smoke.sh` | One Heartbeat call through the FIU's internal API (published on `127.0.0.1:18081`). |

---

## 3. Build and run

### 3.1 Docker

```bash
cd iop-gw-components/iop-gw-mocks
docker build -t iop-gw-mocks:0.0.0.0 .
```

The build compiles the mocks from source inside Docker. Add `--build-arg MVN_ARGS=` to run the tests
during the build.

Run it with the configuration, the public keys and credentials files it names, and a writable output
folder:

```bash
docker run -d --name mocks -p 9443:9443 \
  -v "$PWD/mocks.yaml:/etc/iop-gw-mocks/mocks.yaml:ro" \
  -v "$PWD/generated:/etc/iop-gw-mocks/generated:ro" \
  -v mocks-out:/var/lib/iop-gw-mocks/out \
  --read-only --tmpfs /tmp \
  iop-gw-mocks:0.0.0.0
```

The image runs as a non-root user (uid 10002). Mounted files must be readable by it. The output
folder must be writable by it: a named volume, as above, is.

### 3.2 Plain Java

Requires JDK 21 and Maven 3.6 or later.

```bash
cd iop-gw-components/iop-gw-mocks
mvn package
java -jar target/iop-gw-mocks-0.0.0.0.jar /path/to/mocks.yaml
```

The only argument is the configuration file (default `mocks.yaml` in the working directory).

### 3.3 Check it is up

```bash
curl -k https://localhost:9443/healthz        # ok
```

The start-up log line is `"msg":"iop-gw-mocks started (testing only)"`, with the listen address,
the output folder and the number of entities. Every request is logged on one JSON line (method,
path, status and the calling entity); tokens and secrets are never logged.

---

## 4. Configuration reference

The configuration is one YAML file. Unknown keys are refused, and the process exits with code `2`
on an invalid configuration. Secrets are never in this file: the mocks read them from the
credentials files.

### 4.1 Top level

| Key | Default | Meaning |
|---|---|---|
| `listenAddr` | `127.0.0.1:9443` | The one HTTPS listener, `host:port`. Use `0.0.0.0:9443` in a container. |
| `tlsHosts` | `[localhost, 127.0.0.1]` | Host names and IP addresses the generated TLS certificate is valid for. **Include the name the gateways use** to reach the mocks (for example `mocks` in Compose, or `mocks.<namespace>.svc` on Kubernetes); otherwise their TLS check fails. |
| `tls.certFile`, `tls.keyFile` | – | A TLS certificate and its private key (PEM; the key in PKCS#8, `BEGIN PRIVATE KEY`) to serve. With them, the certificate stays the same across restarts, so the gateways keep trusting it; `tlsHosts` is then not used. Without them, a new certificate is generated at every start. Use them wherever the mocks may restart on their own (Kubernetes). |
| `outDir` | `./mock-out` | Where the certificate, truststore and token-signing key are written at start-up (section 6). Must be writable. |
| `tokenService` | – | Token service settings (4.2). |
| `entities` | `[]` | The participants the Central Registry lists (4.3). |
| `aig` | empty | The starting AIG graph (4.4). |

### 4.2 `tokenService`

| Key | Default | Meaning |
|---|---|---|
| `path` | `/entity/token/generate` | Where access tokens are generated. |
| `iopPath` | `/entity/iopToken/generate` | Where IopTokens are generated. |
| `issuer` | `https://mock-token-service.local/realms/sahamati` | The `iss` claim of every token. Set the gateways' `apiKey.issuer` to the same value. |
| `ttlSeconds` | `86400` | Token lifetime (24 hours, as the Sahamati token service). Shorten it to see the gateways renew tokens. |
| `signingKeyFile` | – | The token-signing private key (PEM, RSA, PKCS#8). With it, tokens and the published JWKS stay valid across restarts. Without it, a new key is generated at every start. |
| `signingKeyId` | `iop-gw-mocks-ts-1` | The key id of the token-signing key, in the JWKS and in every token's header. |
| `credentialsFiles` | `[]` | The credentials files (`{"entityId": "...", "entitySecret": "..."}`) of the entities that may get a token: the same files the gateways mount. A file is read again on every token request, so a changed secret is picked up at once. |

### 4.3 `entities`

One entry per participant the Central Registry lists.

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | The entity id. |
| `type` | yes | `AA`, `FIU` or `FIP`. |
| `baseUrl` | no | Where that entity's gateway listens for `/iop` (for example `http://gw-aa-test-002:8080`). |
| `interop` | no (default `true`) | Whether the entity is ready for interoperability. Gateways never route to one marked `false`. |
| `signingPublicKeys` | no | A list of `{kid, file, validFrom, validTo}`: the PEM public keys others use to check this entity's signatures. |
| `encryptionPublicKeys` | no | The same, for the keys others encrypt to. |

`validFrom` and `validTo` are optional RFC 3339 timestamps with a time zone (for example
`2026-11-10T17:25:16Z`). Gateways use a key only inside its window, which lets you rehearse a key
rotation (see [SETUP.md](SETUP.md), section 7.5).

### 4.4 `aig`

The starting graph, in the same form as a gateway's configured graph: lists of single-entry maps
`id: [AA ids]`.

```yaml
aig:
  fiu:
    - fiu-test-001: [aa-test-002]     # aa-test-002 is fiu-test-001's Connected-AA
  fip:
    - fip-test-003: [aa-test-002]     # aa-test-002 is fip-test-003's Inter-AA
  aa:
    - aa-test-002: [aa-test-004]      # the two AAs peer with each other
```

AAs can change the graph while the mocks run (`PUT /v1/aig/update`, section 5); changes are lost on
restart.

---

## 5. Endpoints

All on the one HTTPS listener.

### Token service (no authorization)

| Method and path | Request | Response |
|---|---|---|
| `POST /entity/token/generate` | Form (`application/x-www-form-urlencoded`): `id`, `secret` | `200 {ver, timestamp, txnId, accessToken, expiresIn, refreshExpiresIn, tokenType, notBeforePolicy, scope}` |
| `POST /entity/iopToken/generate` | The same | The same; the token is an IopToken |
| `GET /tokenservice/jwks`, `GET /auth/realms/sahamati/protocol/openid-connect/certs`, `GET /.well-known/jwks.json` | – | The token-signing key as a JWKS (three paths, one key) |

Token errors use the Sahamati token service's format, `{ver, timestamp, txnId, errorCode,
errorMsg}`:

| Status | `errorCode` | `errorMsg` | When |
|---|---|---|---|
| `400` | `TKN_2014` | `id is missing in the request` / `secret is missing in the request` | A form field is missing |
| `401` | `TKN_2025` | `Invalid id/secret` | Unknown entity (not in `credentialsFiles`) or wrong secret |

The token is an RS256 JWT. Its claims: `iss` (the configured issuer), `aud` `"account"`,
`typ` `"Bearer"`, `azp`, `clientId` and `client_id` (the entity id), `roles` (the entity's type,
when it is listed in `entities`), `scope`, `sub`, `iat`, `exp`, `jti`, and `tokenUse` (`access`
or `iop`, this mock's own marker).

### Central Registry (bearer token from the mocks)

| Method and path | Response |
|---|---|
| `GET /v2/entityInfo/AA`, `/FIU`, `/FIP` | A top-level array of `{ver, timestamp, txnid, entityinfo}`. `entityinfo` carries `id`, `name`, `baseurl`, `interop` (a boolean), `keys.signature` and `keys.encryption` (lists of `{key: <JWK>, validFrom, validTo}`), and `certificate` (a bare JWK). |

### AIG (bearer token from the mocks)

| Method and path | Who may call | Response |
|---|---|---|
| `GET /v1/aig/fiu` | AAs | Every FIU with its Connected-AAs |
| `GET /v1/aig/fip` | AAs | Every FIP with its Inter-AAs |
| `GET /v1/aig/aa` | FIUs and FIPs | Every AA with its peer AAs |
| `PUT /v1/aig/update` | AAs | Body `{"fiu": [...], "fip": [...], "aa": [...]}`: the FIUs, FIPs and peer AAs the calling AA is linked to; each list given replaces that AA's previous links of that kind. Answers `{..., "responseText": "Uploaded"}`. |

Without a valid token: `401`. A caller of the wrong type: `403 Forbidden`.

### Other

| Method and path | Response |
|---|---|
| `GET /healthz` | `200 ok` |
| anything else | `404` |

---

## 6. Files the mocks write

At every start, into `outDir`:

| File | What it is | Used by |
|---|---|---|
| `tls.crt` | The mocks' self-signed TLS certificate (valid for `tlsHosts`) | Reference |
| `truststore.p12` | A PKCS12 truststore holding that certificate, password `changeit` | Each gateway's JVM, so it trusts the mocks (section 7) |
| `issuer-public.pem` | The token-signing public key, in PEM | A gateway's `apiKey.issuerPublicKeys`, if you use files instead of the JWKS URL |
| `jwks.json` | The same key as a JWKS | Reference |

**Unless you give the mocks a certificate and signing key (`tls`, `tokenService.signingKeyFile`),
both are new at every start.** In that case, after restarting the mocks, give the gateways the new
truststore and restart them (section 11). The Helm chart always uses given keys (section 8).

---

## 7. Point a gateway at the mocks

Use the gateway's production sources, with the mocks' address everywhere. In this example the
mocks are reachable as `mocks:9443`:

```yaml
tokenService:
  baseUrl: "https://mocks:9443"
  credentialsFile: /etc/iop-gw/secrets/credentials.json    # also listed in the mocks' credentialsFiles
apiKey:
  mode: jwt
  issuerKeysUrl: "https://mocks:9443/tokenservice/jwks"
  issuer: "https://mock-token-service.local/realms/sahamati" # the mocks' tokenService.issuer
cr: {source: api, baseUrl: "https://mocks:9443"}
aigSource: api
aigBaseUrl: "https://mocks:9443"
```

Then make the gateway trust the mocks' certificate:

- **Docker:** mount the mocks' output folder (or just `truststore.p12`) and set:

  ```
  JAVA_TOOL_OPTIONS=-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -XX:-HeapDumpOnOutOfMemoryError
    -Djavax.net.ssl.trustStore=/mocks-out/truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit
    -Djavax.net.ssl.trustStoreType=PKCS12
  ```

  Setting `JAVA_TOOL_OPTIONS` replaces the image's own options, so repeat them as above.
  `examples/local/compose.yaml` does exactly this.
- **Helm:** put `truststore.p12` in a Secret and set `truststore.existingSecret` (see
  [SETUP.md](SETUP.md), section 4.1).
- **Plain Java:** pass the same `-Djavax.net.ssl.trustStore…` options to `java`.

For every gateway, the mocks must know the entity:

1. its credentials file is in `tokenService.credentialsFiles`;
2. it is in `entities`, with its public keys and the base URL of its gateway;
3. its links are in the `aig` graph (or published with `PUT /v1/aig/update`).

---

## 8. On Kubernetes

Two pieces, in `helm/`:

| Piece | What it is |
|---|---|
| `iop-gw-mocks` chart | The mocks as a Deployment and a Service named after the release. It always uses a TLS certificate and token-signing key from a Secret, so a restart changes nothing for the gateways. |
| `iop-gw` chart defaults | By default, the gateway chart points at the mocks (release `mocks`, same namespace) and trusts their certificate (Secret `mocks-truststore`). Adding `values-production.yaml` replaces all of that with the Sahamati services. |

### 8.1 The mock setup

`helm/examples/mock-setup/` installs everything in one namespace and wires it together:

- the mocks;
- four gateways: `fiu-test-001` (FIU), `aa-test-002` (AA), `aa-test-004` (AA) and `fip-test-003`
  (FIP). `aa-test-002` is the FIU's Connected-AA and the FIP's Inter-AA, so messages go
  `fiu-test-001` → `aa-test-002` → `aa-test-004`, and `aa-test-004` → `aa-test-002` →
  `fip-test-003`;
- a stand-in core, for any gateway whose core you have not connected yet.

It works on any Kubernetes cluster you can reach with `kubectl` and `helm`.

**Before you start:**

- `kubectl`, `helm` and `openssl`; and `keytool` (from any JDK or JRE) or Docker, to create the
  truststore.
- The two images (`iop-gw`, `iop-gw-mocks`) where your cluster can pull them: push them to a
  registry it can reach, or, on a local cluster, load them with that tool's own command.

**Steps:**

1. Edit `helm/examples/mock-setup/mock-setup.yaml`:

   | Setting | Meaning |
   |---|---|
   | `context` | The kube context to install into. **Required**: the script never uses your current context by default. |
   | `namespace` | The namespace everything goes into (default `iop-gw-mock-setup`). Uninstalling removes it. |
   | `images.gateway`, `images.mocks` | The two images, as your cluster pulls them (for example `registry.your-domain.example/iop-gw:0.0.0.0`). |
   | `images.coreStub` | The image the stand-in core runs on (default `python:3.13-alpine`). |
   | `cores.<entity id>` | Where that gateway delivers messages to its core. Empty: the stand-in core. |

2. Install:

   ```bash
   helm/examples/mock-setup/mock-setup.sh install
   ```

   On the first run, the script creates synthetic keys, credentials and certificates in
   `helm/examples/mock-setup/generated/` (git-ignored, readable only by you) and keeps them for
   later runs. It then creates the Secrets and installs the mocks, the stand-in core and the four
   gateways, and waits until they are ready.

3. Make the test calls:

   ```bash
   helm/examples/mock-setup/mock-setup.sh test
   ```

   It makes two calls: from `fiu-test-001`'s internal API to `aa-test-004`, and from
   `aa-test-004`'s internal API to `fip-test-003`. Expect `HTTP/1.1 200` and
   `Forwarding-Hop: aa-test-002` for each.

4. Remove everything when you are done:

   ```bash
   helm/examples/mock-setup/mock-setup.sh uninstall
   ```

   This deletes the namespace and the generated files.

### 8.2 Connecting your own core

Set the gateway's entry under `cores` to your core's URL, as the gateway reaches it from the
cluster, and run `install` again:

```yaml
cores:
  aa-test-004: "http://aa-core.your-namespace.svc:8090"
```

The gateway then delivers to your core instead of the stand-in core (see [SETUP.md](SETUP.md),
section 6.2, for what the core receives and must answer). The stand-in core is removed once no
gateway uses it. In the test calls, `aa-test-004`'s core receives the call from `fiu-test-001`,
and `fip-test-003`'s core the call from `aa-test-004`; `aa-test-002` only forwards.
`fiu-test-001`'s core receives notifications sent to the FIU.

### 8.3 What the script creates

| Kind | Name | Holds |
|---|---|---|
| Secret | `mocks-keys` | The mocks' TLS certificate and key, and their token-signing key |
| Secret | `mocks-input` | Each entity's public keys and credentials file, for the mocks |
| Secret | `mocks-truststore` | `truststore.p12` with the mocks' certificate, for the gateways |
| Secret | `iop-gw-env` | The internal API token the gateways share |
| Secret | `gw-<entity id>-files` | Each gateway's private keys, credentials file and internal API certificate |
| Helm release | `mocks` | The mocks (`iop-gw-mocks` chart) |
| Helm release | `gw-<entity id>` | Each gateway (`iop-gw` chart, with its defaults: the mocks) |
| Deployment, Service | `core-stub` | The stand-in core (only while a core is not connected) |

The values files the script passes to Helm are in `generated/` (`mocks-values.yaml`,
`gw-<entity id>-values.yaml`): read them to see exactly how a gateway is configured to use the mocks.

### 8.4 Using the charts yourself

To set up other entities, install the charts directly:

1. Create a TLS certificate for the mocks, valid for the name the gateways use (for example
   `mocks.<namespace>.svc`), and a token-signing RSA key, both PEM with the keys in PKCS#8. Put
   them in a Secret with the keys `tls.crt`, `tls.key` and `signing.pem`.
2. Put each entity's public keys and credentials file in a second Secret.
3. Create a PKCS12 truststore holding the mocks' certificate, and put it in a Secret
   (`truststore.p12`).
4. Install the mocks with your entities and AIG graph (section 4), for example:

   ```bash
   helm install mocks helm/iop-gw-mocks --set keysSecret=mocks-keys --set inputSecret=mocks-input -f my-mocks.yaml
   ```

5. Install each gateway with a values file of its own (entity id, key ids, core, linked AAs,
   image and Secret names). The chart's defaults already point at the mocks:

   ```bash
   helm install gw-aa-test-002 helm/iop-gw -f gw-aa-test-002.yaml
   ```

Every entity must be known to the mocks: its credentials file listed, its public keys and gateway
URL (`http://gw-<entity id>-iop-gw.<namespace>.svc:8080`) in `entities`, and its links in `aig`.

## 9. Moving to the real services

Change only the gateway's configuration:

| Setting | Mocks | Sahamati |
|---|---|---|
| `tokenService.baseUrl` | `https://mocks:9443` | The token service base URL from Sahamati. Its paths are under a version prefix, so the base URL includes it (for dev: `https://api.dev.sahamati.org.in/iam/v1`). |
| `tokenService.credentialsFile` | A synthetic credentials file | Your entity's credentials from Sahamati |
| `apiKey.issuerKeysUrl` | `https://mocks:9443/tokenservice/jwks` | The token service's JWKS (for dev: `https://api.dev.sahamati.org.in/auth/realms/sahamati/protocol/openid-connect/certs`) |
| `apiKey.issuer` | The mocks' issuer | The token service's issuer (for dev: `https://api.dev.sahamati.org.in/auth/realms/sahamati`) |
| `cr.baseUrl`, `aigBaseUrl` | `https://mocks:9443` | The Central Registry and AIG URLs from Sahamati |
| Truststore | The mocks' `truststore.p12` | Remove it: the Sahamati services have publicly trusted certificates |

The keys you register in the Central Registry are your own; nothing from the mocks carries over.

---

## 10. How the mocks differ from the real services

| Topic | Mocks | Sahamati services |
|---|---|---|
| IopToken | Issued at `/entity/iopToken/generate` | **Not yet available** in the token service (the path answers `404`). Until it is, a gateway can only be tested against the real token service by using the access token in its place (`tokenService.iopPath: /entity/token/generate`). That is for testing only: the two tokens are separate on purpose. |
| Telling an IopToken apart | The `tokenUse` claim (`access` or `iop`), this mock's own marker | Not yet specified. The gateway does not check it yet. |
| Token service paths | No version prefix (`/entity/token/generate`) | Under a version prefix (`/v1/entity/token/generate`), covered by the base URL |
| Failed logins | Never locks an entity | Locks an entity out after repeated failed attempts |
| Token claims | The claims the gateway uses, plus a few of the real ones (section 5) | Many more (Keycloak claims, roles, secret expiry) |
| Secrets | Plain values in local credentials files | Managed, rotated and expired by the token service |
| Central Registry | Only the fields the gateway reads | The full entity record |
| State | Nothing kept: keys, certificate and AIG changes are new at every start | Persistent |
| Availability | Never fails unless stopped | Real outages and latency: test the gateway's retries and cache against the real services too |

---

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Gateway log: `CR load failed`, `AIG load failed` or `issuer JWKS fetch failed`, with a TLS or certificate error | The gateway does not trust the mocks' certificate, or the certificate is not valid for the host name it uses. Check the truststore options (section 7), and that `tlsHosts` includes that host name. |
| Everything worked, then failed after restarting the mocks (Docker or plain Java, without `tls` and `signingKeyFile` set) | The mocks generated a new certificate and token-signing key. Copy the new `truststore.p12` to the gateways and restart them (with a persistent cache, delete the gateways' caches too: they hold tokens signed with the old key). |
| `token service refused`, `TKN_2025` `Invalid id/secret` | The entity's credentials file is not in the mocks' `tokenService.credentialsFiles`, or the gateway and the mocks read different files. |
| `token service refused`, `TKN_2014` | The request is missing `id` or `secret`. The gateway always sends both: this points at another client. |
| `/iop` calls answered `401 InvalidSecurity` `sender not registered` | The sender is missing from the mocks' `entities`, or the receiving gateway has not loaded the CR yet. |
| A call answered `400 InvalidRoute` or `503 AllRoutesUnavailable` | The AIG graph does not link the participants: check `aig` (section 4.4) and the gateways' `linkedAAs`. |
| A gateway never routes to an AA | That AA is marked `interop: false`, or has no `baseUrl`, in `entities`. |
| Mocks exit with code `2` at start-up | Invalid configuration: an unknown key, or an entity without `id` or with a type other than `AA`, `FIU` or `FIP`. The log line `invalid mock configuration` says which. |
| Mocks stop at start-up with a Java exception (exit code `1`) | A file the configuration names cannot be read: a public key, a credentials file (or one without `entityId`), or an `outDir` that is not writable. The exception names the file. |
| Compose: the mocks are unhealthy | Check `docker compose logs mocks`: usually a file in `generated/` is missing because `setup.sh` was not run. |
