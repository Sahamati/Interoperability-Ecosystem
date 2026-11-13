# IOP Gateway: setup guide

The IOP Gateway lets your Account Aggregator (AA), Financial Information User (FIU) or Financial
Information Provider (FIP) exchange messages with participants you are **not directly connected
to**, through other AAs. It runs next to your existing system (your **core**) and takes care of
the interoperability work: signing and checking signatures, end-to-end encryption, choosing a route
through another AA, retries, and the Sahamati services it depends on.

This guide covers what to prepare, how to install the gateway (Kubernetes, Docker or plain Java),
every configuration setting, what your core needs to do, and how to check that it works.

All identifiers in examples (`aa-test-002`, `fiu-test-001`, …) are illustrative.

---

## Contents

1. [How it works](#1-how-it-works)
2. [Before you start](#2-before-you-start)
3. [Choose your mode](#3-choose-your-mode)
4. [Install](#4-install)
5. [Configuration reference](#5-configuration-reference)
6. [What your core needs to do](#6-what-your-core-needs-to-do)
7. [Keys, secrets and certificates](#7-keys-secrets-and-certificates)
8. [Security checklist](#8-security-checklist)
9. [Check that it works](#9-check-that-it-works)
10. [Troubleshooting](#10-troubleshooting)
11. [Try it locally](#11-try-it-locally)
12. [Not yet available](#12-not-yet-available)

---

## 1. How it works

Every participant that uses interoperability runs its own gateway. Your core talks only to **your
own gateway**; gateways talk to **each other**. A message to a participant you are not connected
to goes through an AA that is connected to both of you: the **hop**.

Example: an FIU sends a consent request to an AA it is not connected to, through its Connected-AA.

```
       fiu-test-001                    aa-test-002                     aa-test-003
     you: the sender              hop: your Connected-AA           target: Customer-AA
┌────────────────────────┐      ┌────────────────────────┐      ┌────────────────────────┐
│        FIU core        │      │                        │      │        AA core         │
│           │            │      │                        │      │           ▲            │
│       (1) │            │      │                        │      │           │ (4)        │
│           ▼            │ (2)  │                        │ (3)  │           │            │
│       IOP Gateway ─────┼─────►│       IOP Gateway ─────┼─────►│       IOP Gateway      │
└────────────────────────┘      └────────────────────────┘      └────────────────────────┘
```

1. **Your core calls your gateway**: `POST /fiu-dgw/Consent`, with the usual Direct API payload and
   a `Target-Entity` header naming `aa-test-003`.
2. **Your gateway sends it to the hop**: it signs the message, encrypts the payload so that only
   `aa-test-003` can read it, chooses a hop among the AAs you are linked to, and calls the hop's
   `POST /iop/Consent` with your IopToken.
3. **The hop's gateway forwards it**: it checks your token and signature, checks that it can reach
   `aa-test-003`, and passes the message on unchanged. It cannot read the payload. The hop's core
   is not involved.
4. **The target's gateway delivers it**: it checks the signatures, decrypts the payload and calls
   its core's `POST /aa-core/Consent` with the plain payload, exactly as a Direct API call.

The target's answer travels back the same way, encrypted for you, and your core receives it as the
response to step 1. Other directions work alike:

| Sender → target | Hop |
|---|---|
| FIU → AA | an AA linked to the FIU (its Connected-AA) |
| AA → FIU | an AA linked to the FIU |
| AA → FIP | an AA linked to the FIP (an Inter-AA) |
| FIP → AA | an AA linked to the FIP |

An AA's gateway plays every part: sender, hop (for other participants, with no work for its core)
and target.

The three kinds of endpoint:

- **Internal APIs** (`/fiu-dgw`, `/aa-dgw`, `/aa-sgw`, `/fip-sgw`): what your core calls to send a
  message to a participant it is not directly connected to. They are served on separate, internal
  listeners and must never be reachable from outside your network.
- **`/iop`**: the public listener other participants' gateways call. Every message on it is signed
  by the sender, and the business payload is encrypted for the final recipient only: an AA in
  between (a **hop**) forwards it without being able to read it.
- **Core paths** (`/aa-core`, `/fiu-core`, `/fip-core`): where your gateway delivers messages
  addressed to you, with the same payloads as the Direct APIs.

Participants you are **directly connected to** are still reached through the Direct APIs, as today.
The gateway is only for the others.

The gateway uses three Sahamati services:

| Service | Used for |
|---|---|
| **Token service** | Two tokens for your entity: an **access token** (Direct API calls the gateway makes, and the Central Registry and AIG) and an **IopToken** (sent on every `/iop` call). It also publishes the keys that verify other participants' tokens (JWKS). |
| **Central Registry (CR)** | Every participant's id, base URL, public keys (with validity windows) and whether it is ready for interoperability. |
| **AA Interoperability Graph (AIG)** | Which AAs can reach which FIUs, FIPs and AAs: used to choose a route. |

---

## 2. Before you start

### From Sahamati

- [ ] Your **entity id**, as registered in the Central Registry.
- [ ] Your **token-service credentials** (entity id and secret).
- [ ] The URLs of the **token service**, its **JWKS**, the **Central Registry** and the **AIG**.

### On your side

- [ ] A **signing key pair** and an **encryption key pair** (RSA, at least 2048 bits). The public
  keys are registered in the Central Registry under your entity, with a key id (`kid`) each; the
  private keys go to the gateway (section 7).
- [ ] Your entry in the Central Registry marked **interop ready**, with the **base URL** at which
  your gateway's `/iop` listener is reachable.
- [ ] The list of **AAs you are linked to** (your Connected-AAs, Inter-AAs or peer AAs): the only
  AAs the gateway will use as hops.
- [ ] A **TLS certificate** for the gateway's internal HTTPS listener (it can be issued by your
  internal CA; your core must trust it).
- [ ] A random **internal API token**, shared between your core and your gateway.
- [ ] The **core changes** in section 6.
- [ ] Somewhere to run it: a Kubernetes cluster (recommended), Docker, or a host with Java 21.

---

## 3. Choose your mode

Set `mode` to your participant type. The mode decides which internal APIs your core can call and
which `/iop` messages the gateway accepts.

| Mode | Your core calls | Your gateway delivers to your core | The gateway also forwards (as a hop) |
|---|---|---|---|
| `AA` | `/aa-dgw/*` (to FIUs, through their Connected-AA), `/aa-sgw/*` (to FIPs, through an Inter-AA) | `/aa-core/*` | yes: as Connected-AA or Inter-AA for other participants |
| `FIU` | `/fiu-dgw/*` (to AAs, through your Connected-AA) | `/fiu-core/*` (notifications) | no |
| `FIP` | `/fip-sgw/*` (to AAs, through an Inter-AA) | `/fip-core/*` | no |

---

## 4. Install

Whichever way you install, the steps are the same:

1. Prepare the keys, credentials file and TLS certificate (section 7).
2. Write the configuration file (section 5), starting from the example for your platform.
3. Provide the secrets as environment variables and the files as read-only mounts.
4. Start the gateway and check it (section 9).

### 4.1 Kubernetes (Helm), recommended

The chart is in `helm/iop-gw`. **By default it uses `iop-gw-mocks` in place of the Sahamati
services**, for testing ([MOCK_SETUP.md](MOCK_SETUP.md), section 8), and its install notes say so.
For the Sahamati services, you install it with two values files:

- `helm/iop-gw/values-production.yaml`: the production settings and the Sahamati services (it
  replaces every mock default);
- a small file of your own (here `my-entity.yaml`) with what only you know: your entity id, key
  ids, core address, linked AAs and image location. An example is at the end of
  `values-production.yaml`.

The chart refuses to install until every value it needs is set, and lists each missing one.

To try the chart without the Sahamati services first, see [MOCK_SETUP.md](MOCK_SETUP.md),
section 8: it installs mock services and four gateways wired together.

1. **Create the two Secrets** the gateway reads (or let Vault or your cloud secret store create them
   with these keys):

   ```bash
   kubectl create secret generic iop-gw-env \
     --from-literal=IOPGW_API_TOKEN=<random internal API token>

   kubectl create secret generic iop-gw-files \
     --from-file=signing.pem=<signing private key> \
     --from-file=decryption.pem=<decryption private key> \
     --from-file=credentials.json=<token-service credentials file> \
     --from-file=gw-tls.crt=<internal API certificate> \
     --from-file=gw-tls.key=<its private key>
   ```

   Each key of `iop-gw-env` becomes an environment variable (the configuration refers to it as
   `${IOPGW_API_TOKEN}`); each key of `iop-gw-files` becomes a file under `/etc/iop-gw/secrets/`.

2. **Write `my-entity.yaml`** with your values. Its `config:` section is the gateway configuration
   (section 5), in the same format as the file, and only needs the keys you set: Helm merges it
   with `values-production.yaml`.

   ```yaml
   image:
     repository: registry.your-domain.example/iop-gw
   config:
     mode: AA                                   # AA, FIU or FIP
     self:
       id: aa-test-002                          # your Central Registry id
       signingKey: {source: file, kid: aa-test-002-sig-2026-11, file: /etc/iop-gw/secrets/signing.pem}
       decryptionKeys: {source: file, keys: [{kid: aa-test-002-enc-2026-11, file: /etc/iop-gw/secrets/decryption.pem}]}
     core: {baseUrl: "http://aa-core.your-namespace.svc:8090"}
     linkedAAs: {source: config, aas: [aa-test-003, aa-test-004]}
   ```

3. **Install:**

   ```bash
   helm install iop-gw ./helm/iop-gw -f helm/iop-gw/values-production.yaml -f my-entity.yaml
   ```

   If a value is missing, nothing is installed and the error lists what to set, for example:

   ```
   These values must be set (see SETUP.md, section 5):
     - config.self.id: your Central Registry id
     - config.core.baseUrl: where your core is reached
   ```

4. **Expose the public `/iop` listener** to other participants (an Ingress or a load balancer, with
   TLS). The chart creates two Services (named here for a release called `iop-gw`): `iop-gw` for
   `/iop`, and `iop-gw-internal` for the internal APIs. Expose only `iop-gw`. Point your core at
   `https://iop-gw-internal.<namespace>.svc:8443`.

#### Chart settings

Your values file only needs what differs from the chart's defaults (`helm/iop-gw/values.yaml`).
`values-production.yaml` already sets the production choices: persistent cache on, no plain-HTTP
internal listener, larger resources, and existing Secrets named `iop-gw-env` and `iop-gw-files`.

**Image**

| Value | Default | What it does |
|---|---|---|
| `image.repository` | – (required) | Registry and name of the gateway image. Set it to where Sahamati publishes the image, or to your own registry if you mirror it. |
| `image.tag` | the chart's `appVersion` (`0.0.0.0`) | Image version. Pin an exact version; upgrade it together with the chart. |
| `image.pullPolicy` | `IfNotPresent` | Standard Kubernetes pull policy. |
| `imagePullSecrets` | `[]` | `[{name: <secret>}]` when your registry needs credentials. |

**Gateway configuration**

| Value | Default | What it does |
|---|---|---|
| `config` | the structure, with every entity-specific value empty (required) | The whole gateway configuration (section 5), written as YAML under this key. The chart renders it into a ConfigMap mounted at `/etc/iop-gw/config.yaml`. |

Helm **merges** your `config` with the chart's default key by key: a key you leave out keeps the
chart's value, and a list you set replaces the chart's list. To remove a default key, set it to
`null` (for example `gwApi.httpListenAddr: null` removes the plain-HTTP internal listener). Run
`helm template` and read the rendered ConfigMap to see the exact file the gateway will get.

When `cache.persistent` is `true`, the chart adds `cache.dir` itself; do not set it in `config`.
A change to `config` applied with `helm upgrade` restarts the pods automatically.

**Ports.** These must agree with the listen addresses in `config`.

| Value | Default | What it does |
|---|---|---|
| `ports.iop` | `8080` | Container port of the public `/iop` listener: the port in `config.listenAddr`. The probes and the public Service use it. |
| `ports.gwApiHttps` | `8443` | Container port of the internal HTTPS listener: the port in `config.gwApi.listenAddr`. |
| `ports.gwApiHttp` | `8081` | Container port of the optional plain-HTTP internal listener: the port in `config.gwApi.httpListenAddr`. Set it to `0` when that listener is not configured, and the port is then left out of the pod and the internal Service. |

**Secrets.** The chart never holds your secrets: it mounts Secrets you create.

| Value | Default | What it does |
|---|---|---|
| `secretEnv.existingSecret` | – (**required**) | Name of a Secret whose keys become environment variables in the gateway container. These are the values the configuration refers to as `${NAME}` (for example `IOPGW_API_TOKEN` for `gwApi.token`, or a `core.token`). The chart refuses to render without it. |
| `files.existingSecret` | – (**required**) | Name of a Secret whose keys become files in `/etc/iop-gw/secrets/` (read-only, mode `0440`): private keys, the token-service credentials file, and the internal API certificate and key. The file names are the Secret's key names, and the paths in `config` must use them. |
| `createSecrets.enabled` | `false` | **Testing only.** The chart creates both Secrets from `createSecrets.env` (`NAME: value`) and `createSecrets.files` (`filename: content`). Never use it with real keys: they would sit in your values file and in Helm's release history. |

**Trust**

| Value | Default | What it does |
|---|---|---|
| `truststore.existingSecret` | `mocks-truststore` (`values-production.yaml`: none) | Name of a Secret holding a PKCS12 truststore. The default trusts `iop-gw-mocks`; `values-production.yaml` removes it. Only needed when the gateway calls a service whose TLS certificate is signed by a CA the JVM does not already trust, for example a core served over HTTPS with your internal CA (`core.keysBaseUrl`, key and linkedAAs URLs). The Sahamati services use publicly trusted certificates and need none. The truststore **replaces** the JVM's default trust store, so it must also contain the public CAs of any public service the gateway calls. |
| `truststore.key` | `truststore.p12` | The key in that Secret that holds the truststore file. |
| `truststore.password` | `changeit` | The truststore password. It appears in the pod's environment; a truststore holds only public certificates. |
| `javaOpts` | – | Extra JVM options, added after the image's own: memory sized from the container limit, exit on out-of-memory, no heap dumps. Do not enable debug or JMX ports here. |

**Cache and storage**

| Value | Default | What it does |
|---|---|---|
| `cache.persistent` | `false` | `false`: the chart creates a **Deployment**, and everything the gateway fetches (tokens, Central Registry lists, AIG, token-service keys) is held in memory. After a restart, the gateway has none of it until the fetches succeed: while a Sahamati service is unreachable, it answers calls with `503`, although `/healthz` already reports it ready. `true`: the chart creates a **StatefulSet** with one volume per pod, mounted at `/var/lib/iop-gw/cache`, and the cache directory is set to its `store` subdirectory. A restarted pod serves at once from the last good copy. Recommended for production. Private keys and secrets are never written to it. |
| `cache.size` | `1Gi` | Size of each pod's volume. The cache holds a few megabytes; 1Gi is ample. |
| `cache.storageClassName` | – (cluster default) | Storage class of the volumes. Any `ReadWriteOnce` class works. Each pod needs its own volume, because a cache directory cannot be shared between gateway processes. |

**Replicas and resources**

| Value | Default | What it does |
|---|---|---|
| `replicaCount` | `1` | Number of gateway pods. The pods are independent: each fetches its own tokens and data and, with `cache.persistent`, has its own volume, so you can scale out without changing anything else. With one replica, a restart or upgrade briefly interrupts the gateway (a StatefulSet replaces the pod; a Deployment starts the new pod first). Use 2 or more where that matters. |
| `resources.requests` | `cpu: 250m`, `memory: 512Mi` (`values-production.yaml`: `500m`, `768Mi`) | What the scheduler reserves for each pod. |
| `resources.limits.memory` | `1Gi` (`values-production.yaml`: `1536Mi`) | The pod's memory limit. The JVM sizes its heap at 75% of it. If the gateway runs out of memory, it exits and Kubernetes restarts it. No CPU limit is set by default, to avoid throttling during TLS and crypto bursts; add one if your cluster policy requires it. |

**Services and Ingress.** The Service names below assume the release is named `iop-gw`.

| Value | Default | What it does |
|---|---|---|
| `service.type` | `ClusterIP` | Type of the **public** Service, `iop-gw`, which carries `/iop` only. Keep `ClusterIP` behind an Ingress, or use `LoadBalancer` to expose it directly (then terminate TLS at the load balancer or set `config.tls`). |
| `service.port` | `8080` | Port of the public Service. |
| `service.annotations` | `{}` | Annotations for your cloud's load balancer (internal or external, TLS certificate, and so on). |
| `internalService.type` | `ClusterIP` | Type of the **internal** Service, `iop-gw-internal`, which your core calls. Keep it `ClusterIP` (or an internal-only load balancer if your core runs outside the cluster). It must never be reachable from the internet. |
| `internalService.httpsPort`, `internalService.httpPort` | `8443`, `8081` | Ports of the internal Service. The HTTP port exists only when `ports.gwApiHttp` is not `0`. |
| `ingress.enabled` | `false` | Create an Ingress routing the path prefix `/iop` to the public Service. The internal APIs are never routed. |
| `ingress.className` | – | Your Ingress controller's class. |
| `ingress.host` | – | The host name other participants use, as registered in your Central Registry base URL. |
| `ingress.tls` | `[]` | TLS for that host: `[{secretName: <tls secret>, hosts: [<host>]}]`. |
| `ingress.annotations` | `{}` | Controller-specific settings, for example a request body limit of at least `config.limits.maxBodyBytes` (2 MiB by default), and timeouts above `forwarding.timeoutSeconds`. |

**Pod security.** The defaults already meet the checklist in section 8. Change them only if your
cluster policy demands it, and never loosen them.

| Value | Default | What it does |
|---|---|---|
| `podSecurityContext.runAsNonRoot`, `runAsUser`, `runAsGroup` | `true`, `10001`, `10001` | The gateway runs as an unprivileged user. 10001 is the user built into the image, so file permissions in the image match. |
| `podSecurityContext.fsGroup` | `10001` | The group that owns mounted volumes, so the gateway can write its cache volume and read the Secret files (mode `0440`). |
| `podSecurityContext.seccompProfile` | `RuntimeDefault` | Limits the system calls the container may make to the runtime's safe default set. |
| `securityContext.allowPrivilegeEscalation` | `false` | No process in the container can gain more privileges than it started with. |
| `securityContext.readOnlyRootFilesystem` | `true` | The container's filesystem is read-only. The gateway writes only to `/tmp` (an in-memory volume of 64 MiB the chart always mounts) and to the cache volume. |
| `securityContext.capabilities.drop` | `[ALL]` | All Linux capabilities are removed. The gateway listens on unprivileged ports and needs none. |

The pod also runs with no Kubernetes service-account token mounted: the gateway never calls the
Kubernetes API.

**Scheduling**

| Value | Default | What it does |
|---|---|---|
| `podAnnotations` | `{}` | Extra pod annotations, for example for your log collector or service mesh. |
| `nodeSelector`, `tolerations`, `affinity` | – | Standard Kubernetes scheduling. With more than one replica, a pod anti-affinity rule spreads the pods across nodes or zones. |

**Probes (fixed).** All three probe `GET /healthz` on the `/iop` port:

- the **startup** probe allows up to 3 minutes for the gateway to start;
- the **readiness** probe keeps the pod out of the Services until it answers;
- the **liveness** probe restarts a pod that stops answering for a minute.

`/healthz` answers `200` as soon as the listeners are up. It does **not** check that tokens, the
Central Registry and the AIG have loaded: the gateway tries each once at start-up and keeps
retrying a failed one in the background. Check the start-up log (section 9) to see what loaded.

### 4.2 Docker

Build the image (or pull it from where it is published). The build compiles the gateway from
source inside Docker, so only Docker is needed; the first build takes a few minutes while Maven
downloads its dependencies:

```bash
cd iop-gw && docker build -t iop-gw:0.0.0.0 .
```

Run it with the configuration, the secret files mounted read-only, the secrets as environment
variables, and a volume for the cache:

```bash
docker run -d --name iop-gw \
  -p 8080:8080 -p 8443:8443 \
  -v "$PWD/config.yaml:/etc/iop-gw/config.yaml:ro" \
  -v "$PWD/secrets:/etc/iop-gw/secrets:ro" \
  -v iop-gw-cache:/var/lib/iop-gw/cache \
  --read-only --tmpfs /tmp \
  -e IOPGW_API_TOKEN=<random internal API token> \
  iop-gw:0.0.0.0
```

The files in the secrets folder must be readable by the gateway's user, uid 10001 (for example
`chown -R 10001 secrets` with mode `0400`, or group-readable with `--group-add`). Otherwise it stops
at start-up with `AccessDeniedException`. Mount the **folder**, not single files, so that files
replaced later are seen (section 7.4).

If a service the gateway calls uses a certificate from a private CA, mount a PKCS12 truststore and
set `JAVA_TOOL_OPTIONS`. Repeat the image's own options in it, because setting the variable replaces
them:

```bash
  -v "$PWD/truststore.p12:/etc/iop-gw/truststore.p12:ro" \
  -e JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -XX:-HeapDumpOnOutOfMemoryError \
    -Djavax.net.ssl.trustStore=/etc/iop-gw/truststore.p12 -Djavax.net.ssl.trustStorePassword=<password> \
    -Djavax.net.ssl.trustStoreType=PKCS12" \
```

The image runs as a non-root user (uid 10001). It works with a read-only root filesystem and a
`noexec` `/tmp`. Memory follows the container limit, and the process exits on out-of-memory (so
your orchestrator restarts it) without writing heap dumps.

### 4.3 Plain Java

Requires Java 21.

```bash
cd iop-gw && mvn package
IOPGW_API_TOKEN=<…> java -jar target/iop-gw-0.0.0.0.jar /path/to/config.yaml
```

The only argument is the configuration file (default `config.yaml` in the working directory).

---

## 5. Configuration reference

The configuration is one YAML file. It is checked strictly at start-up. An **unknown key** (usually
a typo), an empty file or more than one YAML document stops the gateway at the first such problem.
Once the file's structure is right, **every** remaining error (missing values, wrong URLs, missing
files, literal secrets) is reported at once, and the gateway exits with code 2. Secrets are never written in the file: you write `${NAME}`, and the gateway reads the
environment variable `NAME`. A literal value where a secret is expected is refused.

Below, "required" means the gateway does not start without it. Times are in seconds.

### 5.1 Mode, listeners, logging

| Key | Default | Meaning |
|---|---|---|
| `mode` | `AA` | `AA`, `FIU` or `FIP` (section 3). |
| `listenAddr` | – (required) | Public `/iop` listener, `host:port` (e.g. `0.0.0.0:8080`). Also serves `GET /healthz`. |
| `tls.certFile`, `tls.keyFile` | – | Serve `/iop` over HTTPS with this certificate. Leave out when TLS is terminated in front of the gateway (Ingress, load balancer). |
| `logging.level` | `INFO` | `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR` or `CRITICAL`. Logs are JSON lines on standard output. |
| `logging.audit` | `true` | Write one audit record per request and response on every leg (section 9). |
| `logging.statsIntervalSeconds` | `60` | How often a stats line with counters is written; `0` turns it off. |

### 5.2 Your entity: `self`

| Key | Default | Meaning |
|---|---|---|
| `self.id` | – (required) | Your entity id in the Central Registry. |
| `self.signingKey.source` | `file` | `file`: one private key from a file. `api`: a set of keys fetched from your core (section 7). |
| `self.signingKey.kid`, `.file` | – (required with `file`) | The key id registered in the CR, and the PEM file of the private key (RSA, at least 2048 bits). |
| `self.signingKey.active`, `.applied`, `.expiry` | active, always, never | Optional validity of a file key: in use while `active`, from `applied` until `expiry` (RFC 3339 or `YYYY-MM-DD`). |
| `self.signingKey.url`, `.token`, `.refreshSeconds` | (see 7.2), –, `3600` | With `api`: where the keys are fetched (HTTPS only), the bearer token (`${NAME}`, required), and how often. |
| `self.decryptionKeys.source` | `file` | `file` or `api`, as for signing. |
| `self.decryptionKeys.keys` | – (required with `file`) | A list of `{kid, file, active, applied, expiry}`. Several keys are allowed: messages are decrypted by the key id they name, so old and new keys can overlap during a rotation. |
| `self.decryptionKeys.url`, `.token`, `.refreshSeconds` | (see 7.2), –, `3600` | With `api`, as for signing. |
| `self.outboundApiKey` | – | **Testing only**: a fixed api-key sent to other gateways instead of tokens from the token service. Not allowed together with `tokenService`. |

### 5.3 Your core: `core`

| Key | Default | Meaning |
|---|---|---|
| `core.baseUrl` | – (required) | Where your core is reached (`http` or `https`), e.g. `http://aa-core.internal:8090`. |
| `core.pathPrefix` | `/aa-core`, `/fiu-core` or `/fip-core` | The path under which the gateway calls your core. |
| `core.timeoutSeconds` | `30` | Timeout for each call to your core. |
| `core.token` | – | Optional bearer token (`${NAME}`) the gateway sends to your core on every call, so your core can check that the caller is your gateway. |
| `core.keysBaseUrl` | `core.baseUrl` | Base URL for fetching private keys from your core (section 7.2). **Must be HTTPS.** |

### 5.4 Checking incoming api-keys: `apiKey`

Every `/iop` request carries the sender's token in a role header. The gateway checks it before
anything else.

| Key | Default | Meaning |
|---|---|---|
| `apiKey.mode` | `jwt` | `jwt` (production): verify the token's signature with the token service's keys. `static`: fixed keys (testing only). |
| `apiKey.issuerKeysUrl` | – | The token service's JWKS URL (HTTPS). Fetched at start-up, every `issuerKeysRefreshSeconds`, and again (at most once a minute) when a token names a key id the gateway does not hold, so key rotation is picked up. |
| `apiKey.issuerPublicKeys` | – | Alternative to `issuerKeysUrl`: a list of PEM files with the token service's public keys. Use one of the two. |
| `apiKey.issuerKeysRefreshSeconds` | `3600` | How often the JWKS is fetched (only with `issuerKeysUrl`). |
| `apiKey.issuer`, `apiKey.audience` | – | When set, a token's `iss` / `aud` must match. |
| `apiKey.senderIdClaim` | `azp` | The token claim that holds the sender's entity id. |
| `apiKey.clockSkewSeconds` | `60` | Tolerance when checking `exp` and `nbf`. |
| `apiKey.static` | – | Testing only, with `mode: static`: `"${NAME}": entity-id` pairs. |

A token is accepted when its signature, validity and (if set) issuer and audience check out, the
sender is listed in the Central Registry, and the sender's type is allowed to use that role header
(for example only an FIU may send `client_api_key`). Until the token service's keys are loaded,
every api-key is refused.

### 5.5 Tokens for your own calls: `tokenService`

| Key | Default | Meaning |
|---|---|---|
| `tokenService.baseUrl` | – (required with `tokenService`) | The token service's base URL. |
| `tokenService.path` | `/entity/token/generate` | Where the **access token** is generated. |
| `tokenService.iopPath` | `/entity/iopToken/generate` | Where the **IopToken** is generated. |
| `tokenService.credentialsFile` | – (required) | A JSON file `{"entityId": "<your id>", "entitySecret": "<secret>"}`. It is read again on every token generation, so a rotated secret needs no restart. Its `entityId` must equal `self.id`. |
| `tokenService.refreshBeforeSeconds` | `3600` | A token is renewed when less than this much of its lifetime is left (or at half-life, for short-lived tokens). |
| `tokenService.timeoutSeconds` | `30` | Timeout for each token request. |

The two tokens are fetched and renewed independently. If a renewal fails, the current token is
used until it expires; failures are retried at most every 10 seconds. Neither the secret nor the
tokens are ever logged.

### 5.6 Participants: `cr` and `entities`

| Key | Default | Meaning |
|---|---|---|
| `cr.source` | `config` | `api` (production): the Central Registry. `config` (testing): the `entities` list below. |
| `cr.baseUrl` | – (required with `api`) | The Central Registry's base URL (HTTPS). |
| `cr.entityInfoPath` | `/v2/entityInfo` | Path of the entity lists. In AA mode the AA, FIP and FIU lists are fetched; in FIU and FIP mode only the AA list. |
| `cr.token` | – | A fixed bearer token (`${NAME}`) instead of the access token. Not allowed together with `tokenService`. |
| `cr.refreshSeconds`, `cr.retrySeconds`, `cr.timeoutSeconds` | `14400`, `300`, `30` | Refresh every 4 hours; after a failure, retry every 5 minutes. A failed fetch keeps the lists the gateway already has. |
| `entities` | – | With `cr.source: api`: optional **local overrides** per entity: `{id, baseUrl, outboundApiKey}` (no keys). With `cr.source: config` (testing): the full list, `{id, type, baseUrl, signingPublicKeys, encryptionPublicKeys, interop}`. |

Keys from the Central Registry carry an optional validity window (`validFrom`, `validTo`): the
gateway uses a key only inside its window, checked at every use.

### 5.7 Routes: `aigSource`, `linkedAAs`, `hopPreference`

| Key | Default | Meaning |
|---|---|---|
| `aigSource` | `config` | `api` (production): the AIG. `config` (testing): the `aig` graph below. |
| `aigBaseUrl` | – (required with `api`) | The AIG's base URL. |
| `fiuAigPath`, `fipAigPath`, `aaAigPath` | `/v1/aig/fiu`, `/v1/aig/fip`, `/v1/aig/aa` | AIG paths. AA mode uses the FIU and FIP graphs; FIU and FIP mode use the AA graph. |
| `aigToken` | – | A fixed bearer token (`${NAME}`) instead of the access token. Not allowed together with `tokenService`. |
| `aigRefreshSeconds`, `aigRetrySeconds`, `aigTimeoutSeconds` | `43200`, `300`, `30` | Refresh every 12 hours; retry every 5 minutes after a failure. |
| `aig` | – | Testing only, with `aigSource: config`: the graph as lists of `{id: [AA ids]}`. |
| `linkedAAs.source` | `config` | `config`: the list in `linkedAAs.aas`. `api`: fetched from your core (section 6.3). |
| `linkedAAs.aas` | – (required with `config`) | The AAs you are linked to. **Only these are used as hops**, and (in AA mode) only AA targets in this list are forwarded to. With `source: api`, until the list is loaded the gateway sends nothing (`503`), and as a hop it answers calls for AA targets with `503 InternalError`. |
| `linkedAAs.url`, `.token`, `.refreshSeconds` | `<core>/linkedAAs`, –, `3600` | With `api`: where to fetch the list, the bearer token (`${NAME}`, required) and how often. |
| `hopPreference.connectedAAs` | – | AAs to try first, in order, when reaching an AA or FIU through a Connected-AA (not in FIP mode). |
| `hopPreference.interAAs` | – | AAs to try first, in order, when reaching a FIP (not in FIU mode). |

How a hop is chosen: an eligible hop is an AA in `linkedAAs` that the AIG says can reach the
target, that is interop ready and has a base URL. Your core's `Preferred-Hop` header comes first,
then `hopPreference`, then the remaining eligible hops in random order.

### 5.8 Internal APIs: `gwApi`

| Key | Default | Meaning |
|---|---|---|
| `gwApi.listenAddr` | – (required) | The internal HTTPS listener (`host:port`). Must differ from `listenAddr`. |
| `gwApi.tls.certFile`, `.keyFile` | – (required) | Its certificate and key. The internal APIs always run on HTTPS. |
| `gwApi.httpListenAddr` | – | Optional extra plain-HTTP internal listener, for message calls only (key push is refused on it). Leave it out in production unless your network requires it. |
| `gwApi.token` | – | The internal API token (`${NAME}`). Your core sends `Authorization: Bearer <token>` on every call. Without it, internal calls need no authorization (a warning is logged). **Set it in production.** |
| `gwApi.maxRetries` | `3` | Upper limit on your core's `Http-Retries` header. |
| `gwApi.maxRouteRetries` | `2` | Upper limit on your core's `Route-Retries` header. |
| `gwApi.ver` | `2.0.0` | API version used when a payload carries none (e.g. Heartbeat). |
| `gwApi.broadcastTimeoutSeconds` | `10` (FIU mode only) | How long the user discovery broadcast waits for the AAs. |

### 5.9 Forwarding (AA mode)

| Key | Default | Meaning |
|---|---|---|
| `forwarding.timeoutSeconds` | `30` | Timeout for each call to another gateway. |
| `forwarding.httpRetries` | `2` | As a hop: extra attempts towards the target when it does not answer, or answers 502, 503 or 504 without a payload (AA mode only). |
| `forwarding.skipUpstreamResponseSignature` | `false` | Do not verify the target's response signature. Leave `false`. |
| `forwarding.pathRewrite` | – | AA mode only: `[{targetType, from, to}]` path rewrites per target type. None by default. |
| `forwarding.preserveUnknownEnvelopeFields` | – | AA mode only: carry envelope fields the gateway does not know when forwarding. |

### 5.10 Cache, limits, signatures

| Key | Default | Meaning |
|---|---|---|
| `cache.dir` | – | Keep fetched data on disk (tokens, CR lists, AIG, token-service keys) so that a restarted gateway serves at once, even while a service is briefly unreachable. Without it, data is held in memory only. Private keys and secrets are never written. **Point it at a subdirectory of your volume** (e.g. `/var/lib/iop-gw/cache/store`): the gateway creates it with mode `0700`. One gateway process per directory. |
| `cache.engine` | `rocksdb` | `rocksdb`, or `file` (one file per entry) for hosts where RocksDB's native library cannot load. |
| `limits.maxBodyBytes` | 2 MiB | Largest request body accepted. |
| `limits.maxUpstreamBytes` | 64 MiB | Largest response read from another gateway or your core. |
| `jws.algorithm` | `RS256` | Signature algorithm. Only `RS256` is accepted; signatures with any other algorithm (PS256 included) are refused. |

### 5.11 A complete example (AA mode, production sources)

```yaml
mode: AA
logging: {level: INFO, audit: true, statsIntervalSeconds: 60}
listenAddr: "0.0.0.0:8080"
self:
  id: aa-test-002
  signingKey: {source: file, kid: aa-test-002-sig-2026-11, file: /etc/iop-gw/secrets/signing.pem}
  decryptionKeys:
    source: file
    keys: [{kid: aa-test-002-enc-2026-11, file: /etc/iop-gw/secrets/decryption.pem}]
core: {baseUrl: "http://aa-core.internal:8090", timeoutSeconds: 30, token: "${IOPGW_CORE_TOKEN}"}
tokenService:
  baseUrl: "https://<token service>"
  credentialsFile: /etc/iop-gw/secrets/credentials.json
apiKey:
  mode: jwt
  issuerKeysUrl: "https://<token service JWKS>"
cr: {source: api, baseUrl: "https://<central registry>"}
aigSource: api
aigBaseUrl: "https://<aig>"
gwApi:
  listenAddr: "0.0.0.0:8443"
  tls: {certFile: /etc/iop-gw/secrets/gw-tls.crt, keyFile: /etc/iop-gw/secrets/gw-tls.key}
  token: "${IOPGW_API_TOKEN}"
linkedAAs: {source: config, aas: [aa-test-003, aa-test-004]}
forwarding: {timeoutSeconds: 30}
cache: {dir: /var/lib/iop-gw/cache/store}
```

For FIU or FIP mode, change `mode` and `self`, and list your Connected-AAs (FIU) or Inter-AAs
(FIP) in `linkedAAs`. `forwarding.httpRetries`, `pathRewrite` and `preserveUnknownEnvelopeFields`
are not allowed outside AA mode.

---

## 6. What your core needs to do

**Signature formats.** Your core **sends** `x-jws-signature` in the Direct API format (RFC 7797,
unencoded payload) and **receives** the other participant's signature as a standard detached JWS
(RFC 7515, base64url-encoded payload). Between gateways, `x-jws-signature` is always RFC 7797.

### 6.1 Send through the gateway

For a participant you are **not directly connected to**, call your gateway's internal API instead
of the Direct API, with the same payload:

```
POST https://<gateway internal>:8443/aa-sgw/Accounts/discover        (AA → FIP)
POST https://<gateway internal>:8443/aa-dgw/FI/Notification          (AA → FIU)
POST https://<gateway internal>:8443/fiu-dgw/Consent                 (FIU → AA)
POST https://<gateway internal>:8443/fip-sgw/FI/Notification         (FIP → AA)
GET  https://<gateway internal>:8443/fiu-dgw/Heartbeat               (likewise /aa-sgw, /fip-sgw)
```

Available APIs per mode:

| Mode | Internal API | Paths |
|---|---|---|
| FIU | `/fiu-dgw` | `Consent`, `Consent/handle`, `Consent/fetch`, `FI/request`, `FI/fetch`, `Consent/Notification`, `User/discover`, `GET Heartbeat`, and `broadcast/User/discover` (asks every AA whether it holds a customer, and returns one merged answer) |
| AA | `/aa-dgw` | `FI/Notification`, `Consent/Notification` (to an FIU) |
| AA | `/aa-sgw` | `Accounts/discover`, `Accounts/link`, `Accounts/link/verify`, `Accounts/link/reverify`, `Accounts/delink`, `Consent`, `FI/request`, `FI/fetch`, `Consent/Notification`, `GET Heartbeat` (to a FIP) |
| FIP | `/fip-sgw` | `Consent/Notification`, `FI/Notification`, `Account/link/Notification`, `GET Heartbeat` (to an AA) |

Request headers:

| Header | Required | Value |
|---|---|---|
| `Authorization` | when `gwApi.token` is set | `Bearer <internal API token>` |
| `Target-Entity` | yes (not on the broadcast) | `{"type":"AA","id":"aa-test-003"}`: the final recipient |
| `Correlation-Id` | yes | A UUID for the whole flow, the same on every message of it |
| `Preferred-Hop` | no | An AA id to try first as hop. It is ignored when that AA is not an eligible hop (section 5.7). |
| `Http-Retries` | no | Attempts per hop when the hop does not answer (default 2, capped by `gwApi.maxRetries`) |
| `Route-Retries` | no | Other hops to try after a hop fails (default 2, capped by `gwApi.maxRouteRetries`) |
| `x-jws-signature` | no | Your own detached signature over the body, made with one of your registered signing keys, in the same format as on the Direct APIs: RS256 with an unencoded payload (RFC 7797), protected header `{"alg":"RS256","kid":"<kid>","b64":false,"crit":["b64"]}`, signed over `BASE64URL(header) + "." + <body as sent>`. The gateway checks it and refuses the call (`400`) if it does not verify, or if it is in another format. Either way, the gateway signs the message itself; your signature is not passed on. |

The response carries the target's payload and status, with:

| Header | Meaning |
|---|---|
| `x-jws-signature` | The **target's** signature over the body, already checked by the gateway. It is a standard detached JWS (RFC 7515: the payload is base64url-encoded), **not** RFC 7797, because it is taken from the target's own signed payload. To check it yourself (optional), verify RS256 over `BASE64URL(header) + "." + BASE64URL(body)` with the target's key from the Central Registry. |
| `Forwarding-Hop` | The AA that delivered the message |
| `Correlation-Id` | Echoed from your request |
| `IOP-Gw-Error: true` | Present only when the **gateway itself** refused or failed the call (for example `503 AllRoutesUnavailable` when no hop could deliver). Without it, an error status is the target's own answer. |

### 6.2 Receive from the gateway

Serve the same APIs as your Direct APIs under `core.pathPrefix` (for example `POST
/aa-core/Consent`), with the same payloads. The gateway adds:

| Header | Meaning |
|---|---|
| `Initiator-Entity` | `{"type","id"}` of the participant that sent the message |
| `Forwarding-Hop` | The AA that delivered it to your gateway |
| `Correlation-Id` | The flow's correlation id |
| `x-jws-signature` | The initiator's signature over the body, already checked by the gateway: a standard detached JWS (RFC 7515, base64url-encoded payload), **not** RFC 7797, as for responses (section 6.1). |
| `Authorization` | `Bearer <core.token>`, when set: check it |

Your core must:

- **echo `Correlation-Id`** unchanged on every response (the gateway refuses a response without it);
- answer `GET <pathPrefix>/Heartbeat` (no body);
- **de-duplicate** on the payload's `txnid`: retries can deliver a message twice;
- in AA mode, serve `POST /aa-core/User/discover` (user discovery from FIUs you are not connected
  to), as the Direct API `/User/discover`.

Your core may sign its responses with `x-jws-signature` (RS256, RFC 7797, as for requests in
section 6.1). The gateway checks it: if it does not verify with your signing keys, the initiator receives `502
InternalError` instead of your answer. Either way, the gateway signs the reply itself.

On an error reply (status `400` or above), the gateway adds `errorSource` (`{"type": "AA", "id":
"<your id>"}`, with your type and id) to the envelope it sends back, so the initiator knows where
the error came from. Your core does not set it.

### 6.3 Optional: give the gateway its keys and linked AAs

Instead of mounting files, your core can serve them (`source: api`):

| Your core serves | Response | Pushed to the gateway (HTTPS listener only) |
|---|---|---|
| `GET <pathPrefix>/keys/signing` (HTTPS) | `{"keys":[{"kid","privateKey":"<PEM>","active",`<br>`"applied","expiry"}]}` | `POST <internal API>/keys/signing` |
| `GET <pathPrefix>/keys/decryption` (HTTPS) | same | `POST <internal API>/keys/decryption` |
| `GET <pathPrefix>/linkedAAs` | `{"linkedAAs":["aa-test-003", …]}` | `POST <internal API>/linkedAAs` |

The gateway fetches them at start-up and every `refreshSeconds` (retrying every 30 seconds while
it has none), with `Authorization: Bearer <token>`. A pushed set replaces the current one at once.
A set is accepted only whole: unique non-empty key ids, RSA keys of at least 2048 bits, `active`
and `applied` present, `expiry` after `applied`.

---

## 7. Keys, secrets and certificates

### 7.1 What goes where

| Item | Where it lives | Notes |
|---|---|---|
| Signing private key | file (Secret) or fetched from your core | Its public key and `kid` are registered in the CR |
| Decryption private key(s) | file(s) (Secret) or fetched from your core | Several allowed during a rotation |
| Token-service credentials | `credentialsFile` (Secret) | `{"entityId","entitySecret"}` |
| Internal API certificate and key | files (Secret) | Trusted by your core |
| Internal API token, core token | environment variables (`${NAME}`) | Random values you generate |

Private keys are held only in memory and never written to the cache or logs; logs show key ids
only.

### 7.2 Keys from your core

With `self.signingKey.source: api` (and likewise `decryptionKeys`), the default URL is
`<core.keysBaseUrl or core.baseUrl><core.pathPrefix>/keys/signing`. It **must be HTTPS** (private
keys are in transit), and `gwApi.tls` must be set (key push is accepted only over HTTPS).

### 7.3 What the gateway reads when

Some inputs are read once, at start-up; others are read again while the gateway runs. This decides
whether a change needs a restart.

| Input | Read | A change takes effect |
|---|---|---|
| Configuration file | at start-up | After a restart. On Helm, `helm upgrade` with a changed `config` restarts the pods itself. |
| Private key **files** (`signingKey.file`, `decryptionKeys.keys[].file`) | at start-up | After a restart. |
| Private keys from your core (`source: api`) | every `refreshSeconds`, or at once when pushed | Without a restart. |
| Internal API TLS certificate and key (`gwApi.tls`), `/iop` TLS (`tls`) | at start-up | After a restart. Renew the certificate before it expires and restart (for example after cert-manager renews it). |
| Token-service credentials file | at **every** token generation | Without a restart, at the next token generation (about hourly). The token already held stays in use until it is renewed. Restart if you need the new secret used at once. |
| Environment variables (`${NAME}`: internal API token, core token, …) | at start-up | After a restart. |
| Truststore, `javaOpts` | at start-up | After a restart. |
| linkedAAs from your core (`source: api`) | every `refreshSeconds`, or at once when pushed | Without a restart. |

On Kubernetes:

- A file from a Secret appears in a running pod some time after you change the Secret: usually
  within a minute or two, depending on the kubelet's sync period. This works because the chart
  mounts the Secret as a directory, so Kubernetes can replace its files. A pod that restarts gets
  the current files at once.
- Changing a Secret **does not** restart the pods. Where a restart is needed, run
  `kubectl rollout restart deployment/iop-gw` (or `statefulset/iop-gw` with `cache.persistent`)
  after updating the Secret.

### 7.4 Making changes: Helm and Docker

The rotation steps in 7.5 are built from these basic operations. The examples assume the Helm
release and the Docker container are both called `iop-gw`, the Secrets are `iop-gw-env` and
`iop-gw-files`, and on Docker the secrets folder `./secrets` is mounted at `/etc/iop-gw/secrets`
as in section 4.2.

| Operation | Helm | Docker |
|---|---|---|
| **Restart** with the same settings | `kubectl rollout restart deployment/iop-gw` (`statefulset/iop-gw` with `cache.persistent`) | `docker restart iop-gw` |
| **Change the configuration** | Edit `config` in your values file, then `helm upgrade iop-gw ./helm/iop-gw -f helm/iop-gw/values-production.yaml -f my-entity.yaml`. The pods restart by themselves. | Edit `config.yaml`, then `docker restart iop-gw`. |
| **Add or replace a secret file** | Update the files Secret with all its files (below). The new file appears in running pods within a minute or two. | Copy the file into `./secrets`. It is visible in the container at once. |
| **Change an environment variable** (`${NAME}`) | Update the env Secret, then restart. | Remove and re-create the container with the new `-e` value (`docker rm -f iop-gw`, then the `docker run` of section 4.2). `docker restart` keeps the old values. With Compose: edit `.env`, then `docker compose up -d`. |

Updating the files Secret on Kubernetes (list **every** file it should hold, old and new: the
command replaces the whole Secret):

```bash
kubectl create secret generic iop-gw-files \
  --from-file=signing-2026-11.pem=... --from-file=signing-2026-12.pem=... \
  --from-file=decryption-2026-11.pem=... --from-file=credentials.json=... \
  --from-file=gw-tls.crt=... --from-file=gw-tls.key=... \
  --dry-run=client -o yaml | kubectl apply -f -
```

If your Secrets come from Vault or a cloud secret store, change them there instead. The timing
rules stay the same.

On Docker, mount the secrets **folder**, as in section 4.2, not single files. A single-file bind
mount keeps showing the old file after the file is replaced on the host.

### 7.5 Rotating keys and secrets

Other gateways verify your signatures, and choose a key to encrypt for you, from their copy of the
Central Registry. They refresh that copy every **4 hours** by default. The key rotations below
allow for that delay.

Give every new key a **new file name** (for example `signing-2026-12.pem`) and a new key id. The
old file then stays in place until you remove it, so a gateway that restarts in the middle of a
rotation still finds the key its configuration names.

#### Signing key

Messages carry the key id they were signed with, and other gateways accept only key ids they
already know.

1. Create the new key pair. Register the new public key in the Central Registry with its new key
   id, and keep the old key registered.
2. **Wait at least 4 hours** (and until the new key's `validFrom`, if you set one), so every
   gateway has the new key.
3. Switch the gateway to the new private key:

   | Helm | Docker |
   |---|---|
   | Add `signing-2026-12.pem` to the files Secret, keeping the old file. Set `config.self.signingKey.kid` and `.file` to the new key and run `helm upgrade`. | Copy `signing-2026-12.pem` into `./secrets`. Set `self.signingKey.kid` and `.file` in `config.yaml` to the new key and run `docker restart iop-gw`. |

4. Check that the restart has finished (`kubectl rollout status` on Helm) and that a call through
   the gateway still succeeds (a Heartbeat, section 9). Then set a `validTo` on the old public key a
   few minutes ahead, for messages still in flight.
5. Remove the old file: from the files Secret on Helm, from `./secrets` on Docker. Nothing needs
   restarting.

#### Decryption key

Other gateways encrypt for you with **any** of your currently valid encryption keys, picked at
random. The gateway must therefore hold a private key before its public key becomes valid, and
keep it until nobody can still encrypt for it.

1. Create the new key pair. Add the private key to the gateway **alongside the old one**, both
   listed:

   | Helm | Docker |
   |---|---|
   | Add `decryption-2026-12.pem` to the files Secret **first**. Then add `{kid: <new kid>, file: /etc/iop-gw/secrets/decryption-2026-12.pem}` to `config.self.decryptionKeys.keys` and run `helm upgrade`. **Never the other way round:** if the configuration names a file the Secret does not have yet, the new pod refuses to start (`file not found`). With `cache.persistent` (a StatefulSet) the old pod has already been stopped, so the gateway is down until the file is added. It then restarts by itself. | Copy `decryption-2026-12.pem` into `./secrets`, add the entry to `self.decryptionKeys.keys` in `config.yaml`, and run `docker restart iop-gw`. |

2. Check that every pod is running with the new configuration (`kubectl rollout status` on Helm;
   on Docker, that the container restarted cleanly). Then register the new public key in the Central
   Registry.
3. Set a `validTo` on the old public key **at least 4 hours ahead**, so gateways with an older copy
   of the registry also stop using it in time.
4. After that `validTo` has passed, remove the old entry from `decryptionKeys.keys` and apply it:
   `helm upgrade` on Helm, `docker restart iop-gw` on Docker. Then remove the old file.

#### Keys served by your core (`source: api`)

The steps and the waits are the same as above, but there are no files and no restarts. Your core
pushes the new set (`POST <internal API>/keys/signing` or `/keys/decryption`), or the gateway picks
it up at its next fetch:

- **Signing:** after the 4-hour wait, push a set in which the new key is `active`.
- **Decryption:** push a set holding both keys, and later a set without the old one.

This works the same on Helm and Docker.

#### Token-service secret

1. Get the new secret from Sahamati and write a new `credentials.json` with it.
2. Replace the file. On Helm, update `credentials.json` in the files Secret; on Docker, overwrite
   `./secrets/credentials.json`.
3. The gateway reads the file at its next token generation (normally within the hour). If the old
   secret stops working first, the gateway keeps the tokens it already holds until they expire. To
   switch at once, restart: `kubectl rollout restart …` on Helm, `docker restart iop-gw` on Docker.
4. Check the log for errors at the next renewal: `token service refused`, `credentials file
   unreadable`, or `credentials file is not for self.id`. Their absence, with calls still
   succeeding, means the new secret works.

#### Internal API token (`gwApi.token`)

Your core sends this token, and the gateway accepts only one value at a time. Change both sides
together, at a quiet time: calls from your core fail between the two changes.

| Helm | Docker |
|---|---|
| Update `IOPGW_API_TOKEN` in the env Secret, run `kubectl rollout restart …`, and switch your core to the new value. | Re-create the container with the new `-e IOPGW_API_TOKEN=…` (or edit `.env` and run `docker compose up -d`), and switch your core to the new value. |

#### Core token (`core.token`)

This is the same as the internal API token, in the other direction: the gateway sends it, and your
core checks it. If your core can accept the old and the new value for a while, there is no
interruption. Change it in your core first (accept both), then in the gateway (env Secret and
restart, or re-create the container), then remove the old value from your core.

#### TLS certificates (`gwApi.tls`, and `tls` if the gateway serves `/iop` over TLS itself)

The certificate must be valid for the host name its clients use. For the internal API, that is
the name your core calls (for example `iop-gw-internal.<namespace>.svc`). Certificates are read
at start-up, so do this **before** the old one expires:

| Helm | Docker |
|---|---|
| Update `gw-tls.crt` and `gw-tls.key` in the files Secret. Wait a minute, then `kubectl rollout restart …`. If cert-manager writes the Secret, restart after each renewal. | Overwrite `./secrets/gw-tls.crt` and `./secrets/gw-tls.key`, then `docker restart iop-gw`. |

If TLS for `/iop` is terminated at your Ingress or load balancer, renew it there; the gateway is
not involved.

#### Truststore

Update the truststore Secret on Helm, or the mounted file on Docker, then restart the gateway.

## 8. Security checklist

- [ ] `gwApi.token` is set, and the internal APIs (`gwApi.listenAddr`, `gwApi.httpListenAddr`) are
  **not reachable from outside** your network. Only `/iop` is exposed.
- [ ] `/iop` is served over **TLS** (`tls.*`, or TLS terminated at your Ingress or load balancer).
- [ ] Secrets are environment variables or mounted files, never literal values in the configuration.
- [ ] The gateway runs as a **non-root** user with a **read-only root filesystem** (the image and
  chart do this by default); `/tmp` can be a small `noexec` in-memory volume.
- [ ] **No heap dumps or core dumps**: they would contain private keys held in memory. The image
  disables heap dumps; keep core dumps off (`ulimit -c 0`) and swap off or encrypted.
- [ ] No debug or management ports (JDWP, JMX) are enabled.
- [ ] `core.token` is set if your core can be reached by anything other than the gateway.
- [ ] Logs are collected but not exposed: they contain ids, statuses and key ids, never payloads,
  tokens or secrets.

---

## 9. Check that it works

1. **Up:** `GET /healthz` on the `/iop` listener answers `200`. This only means the listeners are up;
   steps 2 and 3 show that the gateway can actually serve.
2. **Start-up log** (JSON lines), for a gateway on production sources:

   ```
   "msg":"IOP Gateway started","mode":"AA","self":"aa-test-002"
   "msg":"CR loaded","entities":…
   "msg":"AIG loaded"
   "msg":"issuer keys loaded","kids":[…]
   "msg":"persistent cache opened","engine":"rocksdb"      (with cache.dir)
   ```

3. **A first call:** a Heartbeat from your core to a participant through a linked AA:

   ```bash
   curl https://<gateway internal>:8443/fiu-dgw/Heartbeat \
     -H "Authorization: Bearer $IOPGW_API_TOKEN" \
     -H 'Target-Entity: {"type":"AA","id":"<target AA>"}' \
     -H "Correlation-Id: $(uuidgen)"
   ```

   Expect the target's status, with `Forwarding-Hop` naming the AA that delivered it.

4. **Audit records:** one JSON record (`"tag":"IOPGW_AUDIT"`) per request and response on each leg:
   `core-in` (your core to your gateway), `hop-out` (to the hop), `iop-in` (received on `/iop`),
   `target-out` (a hop to the target), `core-out` (your gateway to your core). Each has the
   `correlationId`, status, timings and error code; never payloads or keys.
5. **Stats:** a line every `logging.statsIntervalSeconds` (`"tag":"IOPGW_STATS"`) with request,
   response, retry and failure counters for the interval.

---

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Exits at start-up with `invalid configuration` | Every problem is listed (`"level":"CRITICAL"`). Common ones: an unknown key (a typo), a literal secret instead of `${NAME}`, an unset environment variable, a missing file, an `http` URL where HTTPS is required (`cr.baseUrl`, `apiKey.issuerKeysUrl`, key URLs). |
| `gateway failed to start` … `cache…: Operation not permitted` | `cache.dir` points at the root of a mounted volume, which belongs to another user. Point it at a subdirectory (e.g. `/var/lib/iop-gw/cache/store`). |
| `gateway failed to start` … `AccessDeniedException` … `/etc/iop-gw/secrets/…` | The gateway's user (uid 10001) cannot read that file. On Docker, make the files readable by uid 10001 (section 4.2). On Kubernetes, the chart's `fsGroup` handles this: check that it has not been removed. |
| `cache.dir is in use by another gateway process` | Two gateways share one cache directory. Give each its own (one volume per pod). |
| `UnsatisfiedLinkError` … `librocksdbjni` | RocksDB's native library could not load. The published image includes it; for a plain-Java run on a `noexec` `/tmp`, set `cache.engine: file` or run the image. |
| `CR load failed` / `AIG load failed` / `issuer JWKS fetch failed` | The service is unreachable, refuses the token (check the credentials file and `self.id`), or its TLS certificate is not trusted (for a private CA, provide a truststore). The gateway keeps retrying; with a persistent cache it serves the last good copy meanwhile. |
| `token service refused` | Wrong entity id or secret in the credentials file, or the file's `entityId` differs from `self.id`. |
| Internal API answers `401` | Missing or wrong `Authorization: Bearer <gwApi.token>`. |
| Internal API answers `400` with `IOP-Gw-Error` | The request itself: missing `Target-Entity` or `Correlation-Id`, a `Correlation-Id` that is not a UUID, a target not in the CR or not interop ready, or no linked AA that can reach it. The `errorMsg` says which. |
| Internal API answers `503 AllRoutesUnavailable` | No hop could deliver: the hops did not answer or refused. Check `linkedAAs`, the AIG, and the hops' status. |
| A hop answers `400 InvalidRoute` | That AA is not linked to the target (or does not know it); the gateway tries the next hop. |
| `/iop` requests from others get `401` | Their token did not verify (token-service keys not loaded yet, wrong issuer, or the sender is not in the CR). |
| Your core gets nothing after a call reached your gateway | Your core did not echo `Correlation-Id`, or is unreachable at `core.baseUrl`. |

---

## 11. Try it locally

`examples/local` runs mock Sahamati services and four gateways (FIU, two AAs, FIP) with Docker
Compose, so you can see a gateway working without credentials or a real core. **Testing only**:
the mocks are not the real services and every key is generated on your machine.

```bash
cd examples/local
./setup.sh                    # synthetic keys, credentials and .env (git-ignored)
docker compose up -d --wait   # needs the iop-gw and iop-gw-mocks images: docker build in each folder (section 4.2)
./smoke.sh                    # one call: FIU -> Connected-AA -> Customer-AA's core
docker compose down -v
```

To point those gateways at the real services, change the four mock URLs in
`examples/local/gateways/*.yaml` and remove the truststore options in `compose.yaml`.

---

## 12. Not yet available

- **Checking that a received api-key is an IopToken** (and not an access token): the verification
  procedure is still to be published. Until then, any valid token-service token from an entity of
  the right type is accepted.
- **User discovery is started by the FIU only** (`/fiu-dgw/User/discover`,
  `/fiu-dgw/broadcast/User/discover`). An AA never sends it: `/aa-dgw/User/discover` answers
  `404 InvalidURI`.
