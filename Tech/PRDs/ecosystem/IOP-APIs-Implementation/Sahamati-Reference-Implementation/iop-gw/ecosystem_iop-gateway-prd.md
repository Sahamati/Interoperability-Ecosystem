# IOP Gateway — Product Requirements

| | |
|---|---|
| **Version** | Draft 4.5, 2026-11-10 |
| **Audience** | AA ecosystem participants (AAs, FIUs, FIPs) and teams implementing or operating the IOP Gateway |
| **Published by** | Sahamati |
| **Scope** | Behaviour and interfaces of the IOP Gateway, independent of the implementation language. Library and runtime choices are left to each implementation. |

This document states what the IOP Gateway does and exposes, not how a particular
implementation is built. The AA_Interop_1_0_0 specification remains the reference for the
`/iop/*` APIs themselves; this document describes how the gateway implements them.

---

## 1. Problem

The AA Interoperability (IOP) specification, AA_Interop_1_0_0, lets an FIU work with a
customer whose account sits with a *different* AA, and lets an AA reach FIPs through another
AA. Each `/iop/*` call passes through an intermediate ("hop") AA. Each party has to:

- work out its role on the call (hop or final recipient) from the api-key header and the
  envelope;
- authenticate the caller, verify signatures, and re-sign at every hop;
- decrypt the end-to-end payload only at the final recipient, check the Initiator's
  signature, and encrypt the reply back to the Initiator.

Building this into each AA's, FIU's and FIP's core application duplicates
security-critical code and makes it easy to get the cryptography wrong. The IOP Gateway does
it once, in a single component that sits in front of the core, in both directions: the core
receives plaintext, already-verified requests, and sends plaintext requests that the
gateway signs, encrypts and routes.

## 2. Goals and non-goals

### Goals
- G1. A single deployable that serves the IOP surface for an **AA**, an **FIU** or an **FIP**,
  selected by configuration.
- G2. Handle every check in the IOP security model at the gateway: role api-key, sender
  identity, detached JWS, JWE payload and the Initiator's inner JWS.
- G3. Give the core application a simple, stable interface in both directions: plaintext
  payload, the Initiator's signature, and who the Initiator or Target is.
- G4. Fail closed: unknown configuration, unknown paths, wrong roles and anything outside the
  cryptographic profile are rejected.
- G5. Never expose regulated data: request and response bodies are never logged, and secrets
  never live in configuration files or the repository.

### Non-goals (this release)
- NG1. Replay protection beyond signatures.
- NG2. Business logic (consent, FI data). That stays in the core application.

## 3. Users and stakeholders

| Stakeholder | Interest |
|---|---|
| AA operators | Run the gateway in `AA` mode in front of their AA core. |
| FIU / FIP integrators | Run the gateway in `FIU` / `FIP` mode as a connector in front of their core. |
| Core application teams | Use the gateway→core interface (§6.2) and the core→gateway APIs (§6.3). |
| Sahamati | Security model, operability and maintenance of this document. |

## 4. Scope — operating modes

The configuration key `mode` selects one mode per process. `AA` is the default.

| Mode | Acts as | `/iop/*` paths served | Accepted caller(s) |
|---|---|---|---|
| `AA` | AA gateway, both demand and supply side | All AA-hosted IOP paths (§5.3) | FIU, FIP, other AAs (six role keys) |
| `FIU` | FIU connector | `/iop/Consent/Notification`, `/iop/FI/Notification` | Connected-AA (`x-conn_aa_api_key`) |
| `FIP` | FIP connector | `/iop/Accounts/discover`, `/iop/Accounts/link`, `/iop/Accounts/link/verify`, `/iop/Accounts/link/reverify`, `/iop/Accounts/delink`, `/iop/Consent`, `/iop/FI/request`, `/iop/FI/fetch`, `/iop/Consent/Notification`, `/iop/Heartbeat` | Inter-AA (`x-inter_aa_api_key`) |

In every mode, `GET /healthz` is unauthenticated and exists for liveness probes only.

In addition, each mode serves **internal APIs** (`/fiu-dgw` (FIU), `/aa-dgw` and `/aa-sgw` (AA), `/fip-sgw` (FIP)) on separate internal
listeners (HTTPS always, plain HTTP optionally). The participant's own core (fiu-core, aa-core
or fip-core) calls these to send `/iop/*` calls (§5.7).

**Requirement on all participants:** every `/iop` request must carry a non-empty
`correlationId`, created by the Initiator and unchanged on every message of the flow. The
gateway never generates one and refuses requests without it on every leg (FR-6, FR-15).

## 5. Functional requirements

### 5.1 Common request pipeline (all modes)

| ID | Requirement |
|---|---|
| FR-1 | Unknown `/iop/*` paths return `404 InvalidURI`. A wrong HTTP method returns `405`. |
| FR-2 | Exactly one of the six role api-key headers must be present (`client_api_key`, `x-conn_aa_api_key`, `x-cust_aa_api_key`, `x-orig_aa_api_key`, `fip_api_key`, `x-inter_aa_api_key`). None, or more than one, returns `401`. A header the path does not accept in the current mode returns `403`. |
| FR-3 | The sender-id is read from the api-key. In `jwt` mode, the token's signature (RS256/PS256), `exp`/`nbf` (with clock skew), and optionally `iss`/`aud` are checked against the issuer keys, and the sender-id is the `azp` claim (configurable). Issuer keys come from the issuer's **JWKS URL** (`apiKey.issuerKeysUrl`, https), fetched at start-up, every `issuerKeysRefreshSeconds` (default 3600), and again when a token names an unknown `kid` (at most once a minute, to pick up issuer rotation), or from PEM files (`issuerPublicKeys`), not both. Only RSA signing keys of at least 2048 bits are taken from the JWKS. A failed fetch keeps the current keys, and while none are loaded api-keys are rejected (`401`) and the fetch is retried every 30 s. A `static` mode exists for development and tests only. |
| FR-4 | The sender must be a configured entity whose type owns that key header (e.g. only an FIU may use `client_api_key`). Otherwise the call returns `401` or `403`. |
| FR-5 | `x-jws-signature` (detached JWS, RS256/PS256, base64url-encoded payload) must verify over the exact received bytes using the sender's configured signing key(s), matched by `kid`. A missing or failed signature returns `401` (`InvalidSecurity` or `SignatureDoesNotMatch`). |
| FR-6 | The envelope must be a JSON object with `txnid` and a non-empty `correlationId` (otherwise `400 InvalidRequest`, on forwarding and terminating legs alike; the gateway never generates a `correlationId`). The key header's leg decides which party field is read: `Target` on forwarding legs (set by the Initiator), `Initiator` on terminating legs (set by the hop), Heartbeat included. The field the leg needs must be present (else `400 InvalidRequest`); the other one, if also present, is ignored. |
| FR-7 | Request bodies are size-limited (default 2 MiB, configurable). Larger bodies return `413`. |

### 5.2 Terminate behaviour (AA terminating legs, FIU and FIP modes)

| ID | Requirement |
|---|---|
| FR-10 | The `Initiator.type` must match the leg, and the Initiator must be a configured entity of that type. |
| FR-11 | `encryptedData` (compact JWE, RSA-OAEP-256 / A256GCM) is decrypted with this participant's key(s), matched by `kid`. Several keys can be configured, which supports key rotation. |
| FR-12 | The decrypted compact JWS must verify against the Initiator's signing keys. If it doesn't, the call returns `401 SignatureDoesNotMatch` and the core is **not** called. |
| FR-13 | The gateway calls `<core.baseUrl><core.pathPrefix>/<api>` (`/iop/X` → `<prefix>/X`), where the prefix defaults by mode to `/fiu-core`, `/aa-core` or `/fip-core`, as described in §6.2. |
| FR-14 | The core's response is returned as `{ver, timestamp, txnid, correlationId, encryptedData}`, whatever the status: the HTTP status tells success from error. `encryptedData` is JWE(JWS(response)), encrypted to the Initiator's encryption key. The inner JWS is the core's own `x-jws-signature` if it sends one; otherwise the gateway signs. The outer body is signed by the gateway. |
| FR-15 | `correlationId` is **copied, never generated**: it is taken from the request and carried unchanged on every leg, at a hop and at the terminating gateway alike. Every call to the core carries a **mandatory** `Correlation-Id` equal to the envelope's `correlationId`. The core must return the same `Correlation-Id` in its response; a missing or different value is refused with `502 InternalError` and the response is not delivered. The reply envelope carries the same `correlationId`. `correlationId` must be in standard UUID format (8-4-4-4-12 hex digits); an `/iop` request with any other value is refused with `400 InvalidRequest`. |
| FR-16 | If the Initiator has no encryption key configured, the call is rejected **before** the core is called. |
| FR-18 | **Internal API token towards the core.** With `core.token` set (an `${ENV}` reference; literals and empty variables are refused at start-up), every `<core.pathPrefix>/*` call (e.g. `/aa-core/*`), Heartbeat included, carries `Authorization: Bearer <core.token>` so the core can authenticate the gateway. Without it no `Authorization` header is sent, and a warning is logged at start-up. The `<core.pathPrefix>/keys/*` fetches use their own key-fetch tokens. |

### 5.3 AA mode — role table and forwarding

| Inbound key | Leg | Envelope | Action | Outbound key |
|---|---|---|---|---|
| `client_api_key` | FIU → Connected-AA | `Target{AA}` | forward | `x-conn_aa_api_key` |
| `x-cust_aa_api_key` | Customer-AA → Connected-AA | `Target{FIU}` | forward | `x-conn_aa_api_key` |
| `x-orig_aa_api_key` | Origin-AA → Inter-AA | `Target{FIP}` | forward | `x-inter_aa_api_key` |
| `fip_api_key` | FIP → Inter-AA | `Target{AA}` | forward | `x-inter_aa_api_key` |
| `x-conn_aa_api_key` | Connected-AA → Customer-AA | `Initiator{FIU}` | terminate | core |
| `x-inter_aa_api_key` | Inter-AA → Origin-AA | `Initiator{FIP}` | terminate | core |

| ID | Requirement |
|---|---|
| FR-20 | Forwarding: `Target.type` must match the leg. The target must be a configured entity with a `baseUrl`, must not be this AA, and must be linked to this AA (FR-126). `encryptedData` must be shaped like a compact JWE. The hop never decrypts it. |
| FR-21 | The hop builds a new envelope `{ver, timestamp (new), txnid (new UUID v4 for the hop → Target leg, the same on every retry of FR-136), correlationId (copied unchanged), Initiator{sender type, sender-id}, encryptedData (unchanged; none for a Heartbeat)}`, signs it, and POSTs it to `<target.baseUrl><path>` with the leg's outbound key. |
| FR-22 | The target's response signature is verified (on by default). A `2xx`/`3xx` response is relayed to the caller with its status, re-signed by the hop, with its `txnid` set to the `txnid` of the caller's request (the caller's leg). A `4xx`/`5xx` response is answered with the Target's status and `{ver, txnid, timestamp, correlationId, errorCode: "IopDownstreamError", errorMsg, encryptedData, errorSource}`, with the caller's `txnid`, signed by the hop: `encryptedData` is the Target's `encryptedData` copied unchanged when present (`errorMsg` "Target responded with HTTP <status>"); otherwise it is omitted and `errorMsg` is "No error payload received". `errorSource` is the `errorSource` object of the Target's response envelope (for example `{"type": "FIP", "id": "fip-test-001"}`), copied unchanged when present and otherwise omitted. Success replies are relayed as received. Network failures return `502`/`504 IopDownstreamError`. |
| FR-136 | **Hop retries towards the Target** (AA mode). As a hop, the gateway sends the same envelope to the Target up to 1 + `forwarding.httpRetries` times (default 2; `0` = no retry; refused in FIU and FIP mode), waiting 200 ms, doubling, at most 2 s between attempts. It retries only when the Target does not answer (connection failure or timeout) or answers `502`/`503`/`504` without `encryptedData`; an answer with `encryptedData` (the Target core's own answer) and every other status are final. After the last attempt, FR-22 applies to the last answer (or `502`/`504` if there was none). Each attempt is a separate audit record (`target-out`, `attempt`) and SNA `requestOut`/`responseIn` pair; `targetRetries` counts the retries. The `/iop` listener's write timeout covers (1 + `httpRetries`) × (forwarding timeout + 2 s) + core timeout. **The Initiator's gateway waits at most its own forwarding timeout for each attempt**, so hop retries help only if they finish within it: keep the hop's `forwarding.timeoutSeconds` × (1 + `httpRetries`) below the Initiator's forwarding timeout. |
| FR-23 | Redirects are never followed. Upstream responses are size-limited (default 64 MiB). |
| FR-24 | Paths can be rewritten per Target type (`forwarding.pathRewrite`, AA mode only). There is no default rewrite. |

**Hop retries towards the Target, by answer** (FR-136)

| Status from the Target | `encryptedData` | Retry | What the Initiator's gateway gets (after the last attempt) |
|---|---|---|---|
| No answer (connection failure) | — | Yes | `502`, `errorCode` `IopDownstreamError`, no `encryptedData` |
| No answer (timeout) | — | Yes | `504`, `errorCode` `IopDownstreamError`, no `encryptedData` |
| `502`, `503`, `504` | No | Yes | The same status, `errorCode` `IopDownstreamError`, `errorMsg` "No error payload received" |
| `502`, `503`, `504` | Yes | No | The same status, `errorCode` `IopDownstreamError`, the Target's `encryptedData` copied unchanged |
| Any other `4xx`/`5xx` | Yes | No | The same status, `errorCode` `IopDownstreamError`, the Target's `encryptedData` copied unchanged |
| Any other `4xx`/`5xx` | No | No | The same status, `errorCode` `IopDownstreamError`, `errorMsg` "No error payload received" |
| `2xx`, `3xx` | — | No | The Target's response, signed by the hop |
| Unreadable, too large, or wrongly signed | — | No | `502`, `errorCode` `IopDownstreamError` |

- Calls carried as a hop are never delivered to the hop's own core.
- The Initiator's gateway treats every `IopDownstreamError` it gets from the hop as final: no retry,
  no other route (FR-74).
- **Timeouts must nest:** keep the hop's `forwarding.timeoutSeconds` × (1 + `forwarding.httpRetries`)
  below the Initiator's forwarding timeout (for example 9 s × 3 = 27 s < 30 s); otherwise the
  Initiator's gateway may give up and resend while the hop is still retrying.

AA-mode routes and the key headers each accepts:

| Path | Accepted keys |
|---|---|
| `/iop/Accounts/discover`, `/link`, `/link/verify`, `/link/reverify`, `/delink` | `x-orig_aa_api_key` |
| `/iop/Account/link/Notification` | `fip_api_key`, `x-inter_aa_api_key` |
| `/iop/Consent`, `/iop/FI/request`, `/iop/FI/fetch` | `client_api_key`, `x-conn_aa_api_key`, `x-orig_aa_api_key` |
| `/iop/Consent/handle`, `/iop/Consent/fetch` | `client_api_key`, `x-conn_aa_api_key` |
| `/iop/User/discover` | `client_api_key`, `x-conn_aa_api_key` (FR-139) |
| `/iop/Consent/Notification` | all six, including `fip_api_key` (FIP → Inter-AA) |
| `/iop/FI/Notification` | `fip_api_key`, `x-inter_aa_api_key`, `x-cust_aa_api_key` |
| `/iop/Heartbeat` | all six |

### 5.4 FIU and FIP connector modes

| ID | Requirement |
|---|---|
| FR-30 | Connectors only terminate (§5.2). They never forward. |
| FR-31 | `FIU` mode: the caller is the Connected-AA (`x-conn_aa_api_key`), and `Initiator{type: AA}` is the Customer-AA. |
| FR-32 | `FIP` mode: the caller is the Inter-AA (`x-inter_aa_api_key`), and `Initiator{type: AA}` is the Origin-AA. |
| FR-33 | `FIP` mode serves `/iop/Accounts/link/reverify` like `/iop/Accounts/link/verify`: from the Inter-AA (`x-inter_aa_api_key`), delivered to `<core.pathPrefix>/Accounts/link/reverify` (e.g. `/fip-core/Accounts/link/reverify`). |
| FR-34 | Configuration that only applies to forwarding `/iop/*` calls is **rejected at start-up** in connector mode: `forwarding.pathRewrite`, `forwarding.preserveUnknownEnvelopeFields`, `terminating.plaintextPaths`. `entities` may list AAs only. `self.outboundApiKey`, `forwarding.timeoutSeconds`, `forwarding.skipUpstreamResponseSignature` and entity `baseUrl`/`outboundApiKey` are allowed, because connectors send core-originated calls to a hop AA. |

### 5.5 Heartbeat (`POST /iop/Heartbeat`)

| ID | Requirement |
|---|---|
| FR-40 | Served in `AA` and `FIP` modes. **Not** served in `FIU` mode. |
| FR-41 | `/iop/Heartbeat` is always a `POST`, never a `GET`. Request: `POST {ver, timestamp, txnid, correlationId, Target}` from the Initiator to the hop, and `POST {ver, timestamp, txnid, correlationId, Initiator}` from the hop to the Target: like every request, the leg reads only the field it needs (FR-6), and **no** `encryptedData`. The whole body is covered by the sender's `x-jws-signature`. There is no inner signature. |
| FR-42 | On a forwarding leg, the heartbeat is forwarded like any request (FR-20 – FR-22): `Target` is replaced by `Initiator{sender}`, with a new `txnid`. A `Target` that is this gateway is refused with `400` (FR-20): a directly connected participant is checked with the Direct API `GET /Heartbeat`, not `/iop/Heartbeat`. On a terminating leg, the gateway answers (FR-44). |
| FR-43 | The Initiator is always set by the hop from the authenticated sender (FR-21), so it cannot be spoofed. A heartbeat with `Target{FIU}` is refused by the Connected-AA. |
| FR-44 | Answering: the gateway calls `GET <core.pathPrefix>/Heartbeat` (e.g. `/aa-core/Heartbeat`) with `Initiator-Entity` and `Correlation-Id`, and no body or signature. The response is wrapped exactly as FR-14: `encryptedData` = JWE(JWS(core response)) for the Initiator, with the outer body signed. |

### 5.6 Errors

| ID | Requirement |
|---|---|
| FR-50 | Errors raised by the gateway itself are plaintext `ErrorResponse` `{ver, txnid, timestamp, errorCode, errorMsg}` (on the internal APIs `ver` and `txnid` come from the payload, `ver` defaulting to `gwApi.ver`, and for Heartbeat the generated `txnid`), signed by the gateway, except on the internal APIs, where they go to the core unsigned. Codes: `InvalidURI`, `InvalidRequest`, `InvalidSecurity`, `SignatureDoesNotMatch`, `InvalidRoute`, `IopDownstreamError`, `InternalError`; on the internal APIs, `BadGateway` and `GatewayTimeout` replace `IopDownstreamError`. |
| FR-51 | Error messages never contain payload content, keys or token values. |
| FR-127 | The errors listed in "Errors returned to the core" (§5.6) are the **complete set** the gateway generates on the internal APIs, each with its status, `errorCode` and `errorMsg`. A change to any of them, or a new one, is made in that list first. |
| FR-128 | **Production uses the APIs.** For every setting that can come from an API or from the configuration (entity registry, AIG, linked AAs, signing and decryption keys, api-key issuer keys, api-key checking, role api-key), production deployments use the API source; the configuration alternative is for testing only (§8). |

Error responses on `/iop/*` (to the calling participant; signed by this gateway):

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | Body unreadable or not a valid envelope (no `txnid`, no `correlationId`, Target/Initiator rules of FR-6); wrong Target or Initiator type for the leg; Initiator not registered; Target is this AA (Heartbeat included); `encryptedData` not a compact JWE, not decryptable, or without a compact JWS inside; heartbeat rules (FR-41–FR-43) |
| `400` | `InvalidRoute` | Forwarding: the Target is not registered with this AA, has no `baseUrl`, or is not linked to this AA; the Target is not called (the Initiator's gateway may try another route, FR-126) |
| `401` | `InvalidSecurity` | No role api-key header, or more than one; invalid api-key; sender not registered; missing `x-jws-signature` |
| `401` | `SignatureDoesNotMatch` | `x-jws-signature` or the Initiator's inner signature does not verify |
| `403` | `InvalidSecurity` | The key header is not accepted on this path, or the sender's type does not own it |
| `404` | `InvalidURI` | Unknown `/iop` path for this mode |
| `405` | `InvalidRequest` | Wrong HTTP method |
| `413` | `InvalidRequest` | Body too large |
| `500` | `InternalError` | No encryption key for the Initiator; unable to sign, encrypt or build the envelope |
| `502` | `IopDownstreamError` | Forwarding: the Target is unreachable, or its response is unreadable, oversized or wrongly signed |
| `4xx`/`5xx` (the Target's) | `IopDownstreamError` | Forwarding: the Target answered with an error; its `encryptedData` is copied unchanged, or `errorMsg` is "No error payload received"; its `errorSource`, if any, is copied unchanged (FR-22) |
| `502` | `InternalError` | Terminating: the core is unavailable, its response is unreadable or oversized, or its `Correlation-Id` is missing or different (FR-15) |
| `503` | `InternalError` | Registry not loaded; IopToken unavailable; decryption keys not loaded; forwarding: AIG not loaded, "hop directory unavailable" (FR-126) |
| `504` | `IopDownstreamError` | Forwarding: the Target did not answer in time |

#### Errors returned to the core (internal APIs)

This is the complete list of errors the gateway generates for the core (FR-127). Every one has:

- **Headers:** `IOP-Gw-Error: true` and `Correlation-Id` (when the request carried one); no
  `x-jws-signature` and no `Content-Type`.
- **Body:** `{ver, txnid, timestamp, errorCode, errorMsg}`, unsigned. `ver` and `txnid` come from
  the core's payload; `ver` defaults to `gwApi.ver`; for a Heartbeat, `txnid` is the one the
  gateway generated.

Checks run in the order below; the first that fails is returned. `errorMsg` is shown as sent.

**1. The core's request**

| Status | `errorCode` | `errorMsg` | When |
|---|---|---|---|
| `404` | `InvalidURI` | unknown internal API path in `<mode>` mode | The path is not served in this mode, including a key endpoint for a key type not taken from the core |
| `405` | `InvalidRequest` | method not allowed | Wrong method; `Allow` names the accepted one |
| `413` | `InvalidRequest` | body too large or unreadable | The body is over the size limit or cannot be read |
| `401` | `InvalidSecurity` | invalid or missing internal API token | `gwApi.token` is set and the `Authorization` token is missing or wrong |
| `501` | `NotImplemented` | `<path>` is not implemented yet | `/aa-dgw/User/discover` (FR-122) |
| `400` | `InvalidRequest` | Correlation-Id header is required, in standard UUID format | `Correlation-Id` is missing or not a UUID (8-4-4-4-12 hex digits) |
| `400` | `InvalidRequest` | Target-Entity header must be {"type":...,"id":...} | `Target-Entity` is missing or not valid JSON with `type` and `id` |
| `400` | `InvalidRequest` | Target.type must be `<type>` on `<path>` | The Target type does not match the API |
| `503` | `InternalError` | entity registry not loaded | The entity lists are not loaded yet |
| `400` | `InvalidRequest` | Target is not registered | The Target is unknown, of another type, or this participant |
| `400` | `InvalidRequest` | Target is not interop ready | The Target's `interop` flag is not `true` |
| `400` | `InvalidRequest` | Http-Retries: `<reason>` | Not a non-negative integer |
| `400` | `InvalidRequest` | Route-Retries: `<reason>` | Not a non-negative integer |

**2. Route selection (§5.8)**

| Status | `errorCode` | `errorMsg` | When |
|---|---|---|---|
| `503` | `InternalError` | linkedAAs not loaded | No `linkedAAs` list is loaded yet |
| `502` | `BadGateway` | hop directory unavailable | The AIG is not loaded |
| `400` | `InvalidRequest` | no interop-ready linked AA can reach this Target | No eligible route |

**3. Building the IOP request**

| Status | `errorCode` | `errorMsg` | When |
|---|---|---|---|
| `500` | `InternalError` | no encryption key configured for Target | The Target has no encryption key |
| `400` | `InvalidRequest` | body must be a JSON object with txnid | The payload is not a JSON object with `txnid` |
| `400` | `InvalidRequest` | core x-jws-signature does not verify with any of this participant's signing keys | The core's own signature does not verify (FR-64) |
| `400` | `InvalidRequest` | core x-jws-signature cannot be attached | The core's signature is malformed |
| `500` | `InternalError` | unable to sign payload | The gateway cannot sign the payload |
| `500` | `InternalError` | unable to encrypt for Target | Encryption failed |
| `500` | `InternalError` | unable to build envelope | The envelope cannot be built |
| `500` | `InternalError` | unable to sign | The gateway cannot sign the envelope |

**4. Sending to the routes (FR-74, FR-75)**

| Status | `errorCode` | `errorMsg` | When |
|---|---|---|---|
| `503` | `AllRoutesUnavailable` | no route could deliver the call (`<n>` tried) | Every route failed: no answer, or an error with no `encryptedData` and an `errorCode` other than `IopDownstreamError` |
| `503` | `InternalError` | IopToken unavailable | No route could be used, for want of an api-key for every hop |
| `504` | `GatewayTimeout` | request cancelled while retrying | The core's request was cancelled while the gateway waited to retry |

**5. Checking the hop's final answer (FR-66).** These carry `Forwarding-Hop`, except where noted.

| Status | `errorCode` | `errorMsg` | When |
|---|---|---|---|
| `502` | `BadGateway` | hop response signature invalid | The hop's signature does not verify on a success or on an answer with `encryptedData` |
| `502` | `BadGateway` | hop response signature invalid | The hop's signature does not verify on an `IopDownstreamError` without `encryptedData`; no `Forwarding-Hop` |
| `503` | `InternalError` | decryption keys not loaded | This participant's decryption keys are not loaded |
| `502` | `BadGateway` | unable to decrypt reply | `encryptedData` cannot be decrypted |
| `502` | `SignatureDoesNotMatch` | Target signature on reply invalid | The Target's signature inside the reply does not verify |
| `502` | `BadGateway` | reply does not contain a compact JWS | The decrypted content is not a compact JWS |

**6. User discovery broadcast (`/fiu-dgw/broadcast/User/discover`, FR-143).** The checks of
list 1 apply, except those on `Target-Entity` and the Target, which the broadcast does not use;
then:

| Status | `errorCode` | `errorMsg` | When |
|---|---|---|---|
| `500` | `InternalError` | unable to build request | A request to an AA cannot be built |
| `503` | `AllRoutesUnavailable` | no AA answered the user discovery (`<n>` asked) | No AA answered successfully within `gwApi.broadcastTimeoutSeconds` |

**Not generated by the gateway** (no `IOP-Gw-Error`): the Target's own error payload (its
`encryptedData`, passed on with the Target's signature), and a Target error without a payload (the
hop's status with an empty body) (FR-74).

**Key push and `linkedAAs` push** (`POST <family>/keys/{signing,decryption}`,
`POST <family>/linkedAAs`): the same body, but the reply carries **no headers** (FR-92, FR-121),
so no `IOP-Gw-Error` and no `Correlation-Id`.

| Status | `errorCode` | `errorMsg` | When |
|---|---|---|---|
| `403` | `InvalidSecurity` | key push is accepted only over HTTPS | Key push on the plain-HTTP listener |
| `405` | `InvalidRequest` | method not allowed | Not `POST` |
| `401` | `InvalidSecurity` | invalid or missing internal API token | `gwApi.token` is set and the token is missing or wrong |
| `413` | `InvalidRequest` | body too large or unreadable | Over the size limit or unreadable |
| `400` | `InvalidRequest` | `<reason>` | Invalid key set or `linkedAAs` list (not JSON, empty, duplicates, unusable key) |

The `errorCode` values `AllRoutesUnavailable`, `BadGateway` and `GatewayTimeout` are defined by
the gateway; the others are the AA ecosystem's standard codes.

### 5.7 Core-originated calls (internal APIs)

| Mode | Internal API (→ `/iop` path) | Role key sent | `Target-Entity` type | Hop |
|---|---|---|---|---|
| `FIU` | `POST /fiu-dgw/Consent`, `/fiu-dgw/Consent/handle`, `/fiu-dgw/Consent/fetch`, `/fiu-dgw/FI/request`, `/fiu-dgw/FI/fetch`, `/fiu-dgw/Consent/Notification`; `GET /fiu-dgw/Heartbeat`, `POST /fiu-dgw/User/discover` (FR-138) (→ same path under `/iop`) | `client_api_key` | `AA` (Customer-AA) | Connected-AA |
| `FIU` | `POST /fiu-dgw/broadcast/User/discover` (FR-140) (→ Direct API `POST /User/discover` to each linked AA; `/iop/User/discover` to each other interop-ready AA) | `client_api_key` | None: every AA in the entity registry | None (Direct API) or Connected-AA (`/iop`) |
| `AA` | `POST /aa-dgw/FI/Notification`, `/aa-dgw/Consent/Notification` (→ same path under `/iop`); `POST /aa-dgw/User/discover` (`501`) | `x-cust_aa_api_key` | `FIU` | Connected-AA |
| `AA` | `POST /aa-sgw/Accounts/discover`, `/aa-sgw/Accounts/link`, `/aa-sgw/Accounts/delink`, `/aa-sgw/Accounts/link/verify`, `/aa-sgw/Accounts/link/reverify` (→ same path under `/iop`), `/aa-sgw/FI/request`, `/aa-sgw/FI/fetch`, `/aa-sgw/Consent/Notification`, `/aa-sgw/Consent` (→ same path under `/iop`); `GET /aa-sgw/Heartbeat` | `x-orig_aa_api_key` | `FIP` | Inter-AA |
| `FIP` | `POST /fip-sgw/Consent/Notification`, `/fip-sgw/FI/Notification`, `/fip-sgw/Account/link/Notification`; `GET /fip-sgw/Heartbeat` (→ same path under `/iop`) | `fip_api_key` | `AA` (Origin-AA) | Inter-AA |

| ID | Requirement |
|---|---|
| FR-60 | The internal APIs (`/fiu-dgw` (FIU), `/aa-dgw` and `/aa-sgw` (AA), `/fip-sgw` (FIP)) are served **only** on the internal listeners, never on the public one. The HTTPS listener (`gwApi.listenAddr`, `gwApi.tls` required) always runs; `gwApi.httpListenAddr` adds an optional plain-HTTP listener with the same APIs except key push (FR-92). Both addresses must differ from `listenAddr`. When `gwApi.token` is configured, every call must carry `Authorization: Bearer <gwApi.token>`, compared in constant time; otherwise the call returns `401`. Without `gwApi.token`, calls need no `Authorization` and a warning is logged at start-up. Paths belonging to another mode return `404`, and a wrong method returns `405`. |
| FR-61 | The core names the final recipient in `Target-Entity: {"type","id"}`. The type must match the API (table above) and the Target must be a configured entity other than this participant. |
| FR-62 | Hops are chosen as in §5.8: only AAs in `linkedAAs` (FR-120) that the AIG says can reach the Target. A hop must be an interop-ready AA with a `baseUrl` and an api-key (`self.outboundApiKey`, the IopToken, or the hop's own `outboundApiKey`). The Target is never used as its own hop, Heartbeat included. |
| FR-63 | Payload: a JSON object containing `txnid`. The envelope's `ver` comes from the payload, or `gwApi.ver` if absent. The envelope's `txnid` is **not** the payload's: it identifies the Initiator → hop leg, a new UUID v4 for each route, the same on retries of that route. The payload's `txnid` is used in the internal API error bodies. `correlationId` comes from the **mandatory** `Correlation-Id` header, in standard UUID format (8-4-4-4-12 hex digits, either case, any version); a missing or non-UUID value returns `400 InvalidRequest`. Every internal API response, including errors, echoes the request's `Correlation-Id`. The key endpoints (`…/keys/*`) do not require it. |
| FR-64 | Inner JWS: if the core sends its own `x-jws-signature`, it must verify with this participant's signing key and is attached as the inner JWS. Otherwise the gateway signs. The inner JWS is encrypted (JWE) to the Target's encryption key. |
| FR-65 | The gateway sends `{ver, timestamp, txnid, correlationId, Target, encryptedData}` with a detached signature to `<hop.baseUrl>/iop/<api>` using the role key header from the table. The envelope carries `Target` only; the hop sets `Initiator` (FR-21). It is built and signed once per route (FR-63). |
| FR-66 | Reply: the hop's signature is verified. `encryptedData` (success or error) is decrypted with this participant's key, and the inner JWS must verify against the Target's signing key. The core receives the Target's payload, the Target's detached `x-jws-signature`, the upstream status, and `Forwarding-Hop` (the hop that delivered it). Error answers without `encryptedData` are handled as in FR-74. On the internal APIs, `x-jws-signature` is only ever the Target's. |
| FR-124 | Errors generated by this gateway on the internal APIs (its own rejections, and `503 AllRoutesUnavailable`) carry the header `IOP-Gw-Error: true`. Errors passed on from the Target (its decrypted error payload, or its status with an empty body) do not carry it. It is not sent on success, on `/iop`, or on key-push and `linkedAAs` replies. |
| FR-67 | `GET /fiu-dgw/Heartbeat`, `/aa-sgw/Heartbeat` and `/fip-sgw/Heartbeat` become `POST /iop/Heartbeat` with `{ver: gwApi.ver, timestamp, txnid: generated UUID v4 per route, correlationId: from Correlation-Id, Target}`, no `Initiator` and no `encryptedData`. The Target is never the hop itself. The reply is opened as in FR-66. |
| FR-68 | The hop AAs accept every leg used here, with no change on their side. This is checked by an automated test against the AA-mode route table. |
| FR-69 | **Transport between core and gateway.** Calls to `<core.pathPrefix>/*` use `core.baseUrl` as given (http or https). The private-key fetches (`<core.pathPrefix>/keys/*`) use `core.keysBaseUrl` (default `core.baseUrl`; `self.signingKey.url` / `self.decryptionKeys.url` override per key type) and **must be https**: an http key URL stops start-up. Key push is accepted only on the HTTPS internal listener (FR-92). The internal APIs always run on HTTPS (FR-60), with an optional plain-HTTP listener for message calls and `linkedAAs` push. |

### 5.8 Hop selection, retries and failover

| ID | Requirement |
|---|---|
| FR-70 | Hops come from the **AA Interoperability Graph (AIG)**, read per `aigSource`: `api`, the AIG read APIs (FR-78), or `config` (default), an `aig` graph in the configuration with the same lookups. **AA mode** uses `aig.fiu` (per FIU its connected-AAs) and `aig.fip` (per FIP its inter-AAs); **FIU and FIP mode** use `aig.aa` (per AA its peer-AAs; peering counts in both directions). Each is a list with one single-entry map per id, e.g. `- fiu-test-001: [aa-test-002, aa-test-003]`; each entry names exactly one id, an id appears once, and its list is non-empty. Both sources go through one graph-fetch operation, and the graph is held in memory and in the persistent cache (`aig/graph`) either way. A configured graph is loaded at start-up and not refreshed. A Target absent from the graph has no hops. The configured graph may list this gateway's own `self.id` (for example as one of an FIU's Connected-AAs): it is never used as its own hop, and in AA mode it is what the hop's route check reads (FR-126). Each source refuses the other's settings. |
| FR-135 | **FIU and FIP mode: sending to an AA Target**. (1) The Target AA (Customer-AA or Origin-AA) must be registered and interop ready (else `400`). (2) The AIG for these modes (`GET /v1/aig/aa`) lists only AAs and the AAs each is linked to, no FIUs or FIPs; the candidates are the AAs the AIG links to the Target AA, in either direction. (3) A candidate is used only if it is in `linkedAAs` (the FIU's Connected-AAs or the FIP's Inter-AAs), interop ready, with a `baseUrl` and an api-key; the Target is never its own route, Heartbeat included. (4) The eligible AAs are ordered as in FR-77, and the request is sent to the first, then to others as FR-74 allows. With no eligible AA, the call returns `400`. |
| FR-71 | Optional `Preferred-Hop: <hop entity id>`: tried first if it is an eligible hop (a linked AA that the AIG says reaches the Target, interop ready). Otherwise it is ignored and the reason logged. |
| FR-72 | Optional `Http-Retries: <n>`: retries per hop, only when the hop does not answer (no connection, or a timeout). Default 2, capped by `gwApi.maxRetries` (default 3); a lower cap also lowers the default. Backoff is 200 ms, doubling, at most 2 s. |
| FR-73 | Optional `Route-Retries: <n>`: how many **further** hops (routes) to try after the first. **`0` means: do not try another route.** Default 2, capped by `gwApi.maxRouteRetries` (default 2). `Http-Retries: 0` likewise means: do not retry the same hop. |
| FR-74 | **Hop error answers** (status `4xx` / `5xx`): (1) a payload with `encryptedData`: opened and passed on with the hop's status and the Target's signature; (2) no `encryptedData` and `errorCode` `IopDownstreamError` (the Target answered without a payload): the core gets the hop's status with an empty body, with no retry and no other route; (3) no `encryptedData` and any other `errorCode`, (4) no payload, or no response at all: the route failed and the next route is tried, within `Route-Retries`. The same hop is retried first, within `Http-Retries`, only on no response; a hop error, `502` / `503` / `504` included, moves to the next route at once. Success answers are final. This limits duplicate delivery, since the same payload (same payload `txnid`) is re-sent. |
| FR-137 | **Duplicates.** Retries resend the same envelope, and other routes resend the same payload in a new envelope (FR-63, FR-72 – FR-74, FR-136), so a Target can receive a message more than once. The envelope `txnid` differs per leg and per route; the payload's `txnid` stays the same. The gateway does not de-duplicate; every Target's core **must** de-duplicate on the **payload's** `txnid` (the body it receives) and must not process a repeated `txnid` again (for example, it returns the earlier response). |
| FR-126 | As a hop (AA mode), the gateway answers `400 InvalidRoute`, without calling the Target, when the Target is not registered with it, has no `baseUrl`, or is not linked to it. Linked means: for a Target FIU, the AIG lists this AA as one of the FIU's Connected-AAs; for a Target FIP, the AIG lists this AA as one of the FIP's Inter-AAs; for a Target AA (the Customer-AA on the FIU leg, the Origin-AA on the FIP leg), the AA is in this AA's `linkedAAs`. If the AIG is not loaded, the hop answers `503 InternalError` ("hop directory unavailable"). Like any hop error other than `IopDownstreamError`, `InvalidRoute` sends the Initiator's gateway on to another route (FR-74). `InvalidRoute` is not yet confirmed as a ReBIT IOP error code. |
| FR-75 | When every route failed (FR-74), the core gets `503 AllRoutesUnavailable` with `IOP-Gw-Error: true` and no `Forwarding-Hop`. If no hop could be used for want of an IopToken, the call returns `503 InternalError`. An AIG not yet loaded returns `502`; `linkedAAs` not loaded returns `503 InternalError`. No interop-ready linked AA able to reach the Target returns `400`, and a Target that is not interop ready returns `400 InvalidRequest` (FR-106). Invalid header values return `400`. |
| FR-76 | The internal listeners' write timeout covers the worst case: `(maxRouteRetries + 1) × (maxRetries + 1) × (forwarding timeout + 2 s)`. Cores choose `Http-Retries` / `Route-Retries` to fit their own HTTP timeout (core guides §3.12). |
| FR-77 | **Hop order:** (1) the core's `Preferred-Hop`, if eligible; (2) the **hop-preference policy** in its configured order: `hopPreference.connectedAAs` for Targets reached through a Connected-AA (FIU mode; FIU Targets in AA mode), `hopPreference.interAAs` for Targets reached through an Inter-AA (FIP mode; FIP Targets in AA mode); (3) the remaining eligible AAs in **random order**, chosen afresh for each call. Policy entries that are not eligible are skipped. `hopPreference.interAAs` is refused in FIU mode and `hopPreference.connectedAAs` in FIP mode. |
| FR-78 | **AIG client.** With this participant's access token as bearer, the graphs are loaded at start-up and every `aigRefreshSeconds` (default 43200 = 12 h). AA mode: `GET <aigBaseUrl><fiuAigPath>` (default `/v1/aig/fiu`) returns `{"ver", "timestamp", "txnid", "fiu": [{"id", "connected-AA": [{"id", "verified", "attr"}]}]}`, and `GET <aigBaseUrl><fipAigPath>` (default `/v1/aig/fip`) returns `{"fip": [{"id", "inter-AA": [...]}]}`. FIU and FIP mode: `GET <aigBaseUrl><aaAigPath>` (default `/v1/aig/aa`) returns `{"aa": [{"id", "peer-AA": [...]}]}`. `attr` is ignored. **Lookups are served from memory only; the AIG is never called per request.** `verified` does not affect the hop order (FR-77). A load succeeds only if every graph for the mode is fetched and valid; otherwise the previous graph is kept, a warning is logged, and the load is retried after `aigRetrySeconds` (default 300). Until the first successful load, the directory is unavailable (FR-75: `502`). The configured `aig` graph is refused with `aigSource: api`. |

#### Retry logic at a glance: Initiator's gateway and hop

A call can be retried in two places: by the **Initiator's gateway** (the IOP Gateway of the FIU,
FIP or AA whose core sent the call), and by the **hop** (the IOP Gateway of the Connected-AA or
Inter-AA that carries it to the Target). Each retries only the failures it can see.

| | Initiator's gateway | Hop |
|---|---|---|
| Sends to | A hop AA (`/iop`) | The Target (`/iop`) |
| Retries the same route | `Http-Retries` header from the core: default 2, capped by `gwApi.maxRetries` (default 3) | `forwarding.httpRetries` in its configuration: default 2 (AA mode only) |
| … when | The hop does not answer (no connection, or a timeout); a hop error, `502`/`503`/`504` included, is not retried on the same route | The Target does not answer, or answers `502`/`503`/`504` without `encryptedData` |
| Tries another route | Yes: `Route-Retries` header, default 2, capped by `gwApi.maxRouteRetries` (default 2); after the retries when the hop does not answer, and at once on any hop error that is not from the Target (e.g. `503`, `400 InvalidRoute`) | No: there is only one Target |
| Never retries | Success; an answer with `encryptedData` (the Target's error); `IopDownstreamError` without `encryptedData` | Success; an answer with `encryptedData` (the Target core's answer); any other status |
| Wait between attempts | 200 ms, doubling, at most 2 s | 200 ms, doubling, at most 2 s |
| Most sends per call (defaults) | (1 + 2 routes) × (1 + 2 retries) = 9 | 1 + 2 = 3 |
| When all attempts fail | The core gets `503 AllRoutesUnavailable` with `IOP-Gw-Error: true` | The Initiator's gateway gets the Target's status, or `502`/`504`, with `errorCode` `IopDownstreamError` |

**How the two fit together**

1. **A failing Target is retried by the hop only.** When the hop gives up, it answers
   `IopDownstreamError`. The Initiator's gateway treats that as final: it neither retries nor
   tries another route, because every route leads to the same Target.
2. **A failing hop is handled by the Initiator's gateway.** No answer from the hop, or the hop's
   own error, is retried on the same route and then on other routes.
3. **Timeouts must nest.** The Initiator's gateway waits at most its forwarding timeout
   (`forwarding.timeoutSeconds`, default 30 s) for each attempt. If the hop is still retrying
   when that expires, the Initiator's gateway counts the route as failed and may resend; the
   Target can then receive the message more than once. Keep the hop's
   `forwarding.timeoutSeconds` × (1 + `forwarding.httpRetries`) below the Initiator's forwarding
   timeout (for example 9 s × 3 = 27 s < 30 s).
4. **Every resend carries the same payload and `correlationId`.** Retries on one route resend the
   same envelope; another route, and the hop's leg to the Target, use a new envelope `txnid`.
   Recipients de-duplicate on the payload's `txnid` (FR-137).

### 5.9 Access token and IopToken

| ID | Requirement |
|---|---|
| FR-80 | The gateway obtains **two tokens** from the Sahamati IAM token service: the **access token** with `POST <tokenService.baseUrl><path>` (default `/entity/token/generate`) and the **IopToken** with `POST <tokenService.baseUrl><iopPath>` (default `/entity/iopToken/generate`). Both use the form `id=<self.id>`, `secret=<entitySecret>`. The id and secret come from a **mounted credentials file** (`tokenService.credentialsFile`, JSON `{"entityId", "entitySecret"}`). The file is read afresh on every token generation, so secret rotation needs no restart. Its `entityId` must equal `self.id`, checked at start-up and on every read; a mismatch is an error, not a change of identity. The response is `{"accessToken", "expiresIn", …}`; errors are `{"errorCode", "errorMsg"}`. |
| FR-81 | The **IopToken** is the **role api-key** on every `/iop/*` call this gateway sends to another AA, both forwarded calls (AA mode, as Connected-AA, Customer-AA, Origin-AA or Inter-AA) and core-originated calls (all modes). The **access token** is the api-key on Direct API calls (the user discovery broadcast, FR-141) and the **Central Registry and AIG bearer token**. An entity's own `outboundApiKey` overrides both for that entity. Without `tokenService`, `self.outboundApiKey` serves as both api-keys (testing only). |
| FR-82 | Each token is fetched at start-up, cached in memory, and regenerated when less than `refreshBeforeSeconds` (default 3600) of its lifetime remains, or at half-life if it lives shorter than that. If regeneration fails, the current token is used until it expires. A failed generation is retried at most every 10 s. The two tokens are refreshed independently. |
| FR-83 | Without a usable IopToken, a forwarded call fails with `503 InternalError`. A core-originated call tries the next hop (which may have its own api-key), then fails with `503`. Without a usable access token, the AIG and Central Registry loads fail and are retried on their schedule, and a Direct API user discovery call is not sent (that AA gives no answer). |
| FR-84 | With `tokenService` set, the static `self.outboundApiKey` and `aigToken` are rejected (one source). The tokens and the secret are never logged. Token service errors log only status, `errorCode` and `errorMsg`. |
| FR-85 | The gateway checks that a received role api-key is an IopToken (a hop token), in every mode; in FIU and FIP mode this check is the gateway's, not the core's. It is not yet done: the verification procedure is to be published. Until then, received role api-keys are checked as in §5.3 and §5.4. |

### 5.10 Signing and decryption keys

| ID | Requirement |
|---|---|
| FR-90 | `self.signingKey.source` selects where this participant's signing keys come from: `file` (default: one RSA key from a mounted PEM file, with its `kid`) or `api` (a set of keys from the core). |
| FR-91 | `api`: `GET <self.signingKey.url>`, default `<core.keysBaseUrl><core.pathPrefix>/keys/signing` (e.g. `/fiu-core/keys/signing`), **https only** (private keys are in transit; an http URL stops start-up). Sent with `Authorization: Bearer <token>` as the only header (an `${ENV}` secret), at start-up and every `refreshSeconds` (default 3600 = 1 h). Response: `{"keys": [{"kid", "privateKey": "<PEM>", "active", "applied", "expiry"}]}` (validity: FR-97). |
| FR-92 | The core can replace the set at any time with `POST <family>/keys/signing` (`/fiu-dgw` in FIU mode, `/aa-dgw` or `/aa-sgw` in AA mode, `/fip-sgw` in FIP mode), with the same body, **only on the HTTPS internal listener**: the plain-HTTP listener answers `403 InvalidSecurity`. The internal API token is required if one is configured. The reply lists the kids now in use. Only `Authorization` is used on these calls: the request needs no other header, and replies, success or error, carry no headers. The next scheduled GET overwrites the set again. |
| FR-93 | A set is accepted only whole: non-empty, unique non-empty kids, every key a valid RSA key of at least 2048 bits. Otherwise it is rejected (POST `400`) and the current set is kept. |
| FR-94 | Each signature (outer `x-jws-signature`, replies, errors, inner JWS) uses a key chosen **at random** from the set, with its `kid` in the protected header. Every verifier must therefore hold the public keys of every key in the set. A core-supplied inner signature is accepted if it verifies with any key in the set. |
| FR-95 | A failed GET keeps the current set and is retried at the next interval. While no key is loaded, the gateway cannot sign: responses fail `500`, and the GET is retried every 30 s. Key material is never logged or returned, only kids. |
| FR-96 | Decryption keys use the same mechanism: `self.decryptionKeys.source` is `file` (`keys: [{kid, file}]`) or `api`. With `api`: `GET <url>`, default `<core.keysBaseUrl><core.pathPrefix>/keys/decryption`, https only (FR-69), bearer token, every `refreshSeconds` (default 3600 = 1 h); `POST <family>/keys/decryption` (HTTPS listener only) to replace; same body and validation as FR-93. **All** keys in the set are offered for decryption, matched by the JWE `kid`, so old and new keys overlap during rotation. While no decryption key is loaded, encrypted requests (terminate) and encrypted replies (core-originated calls) fail with `503 InternalError`, and the GET is retried every 30 s. |
| FR-97 | **Key validity**. Every signing and decryption key carries `active` (bool), `applied` (date) and `expiry` (date or null = none). A key is usable while active, from `applied` (inclusive) until `expiry` (exclusive), checked at every use, so keys take effect and lapse on time without a refetch. Signing picks at random among usable keys; decryption tries only usable keys. From the core, `active` and `applied` are required and `expiry` may be null or absent. For file keys all three are optional (defaults: active, always applied, no expiry). Dates are RFC 3339 or `YYYY-MM-DD` (00:00 UTC). `expiry` must be after `applied`, and invalid values reject the whole set or stop start-up. A set with no key usable now is accepted with a warning: until a key applies, the gateway cannot sign, not even error replies (bare `500`), or decrypt (`503`). The POST reply and logs list each key's kid, active, applied, expiry and whether it is usable now, never key material. |

### 5.11 Entity registry (Central Registry)

| ID | Requirement |
|---|---|
| FR-100 | `cr.source` selects the entity registry: `config` (default), the configuration's `entities` with keys from PEM files, or `api`. With `cr.source: api` and `cr.baseUrl` (https), the Central Registry is the entity registry. The gateway calls `GET <cr.baseUrl><cr.entityInfoPath>/<type>` (default `/v2/entityInfo`) for each type the mode needs: `AA`, `FIP` and `FIU` in AA mode; only `AA` in FIU and FIP mode, where every sender, Initiator and Target is an AA, with `Authorization: Bearer <access token>` (or `cr.token` without `tokenService`), at start-up and every `cr.refreshSeconds` (default 14400 = 4 h). The `/iop/...` path is appended to the entity's `baseurl`. |
| FR-101 | The response is a **top-level JSON array**, one element per participant: `[{"ver", "timestamp", "txnid", "entityinfo": {…}}, …]` (a `requester` object may also be present). Only `entityinfo` is used; the other fields are ignored. Each element's `entityinfo` gives an entity: `id`; type = the list it is in; `baseurl`, ignored if not an absolute http(s) URL; `interop` (boolean; absent = `false`, FR-106); **signature-verification keys** from `keys.signature`, or from `certificate` when that list is empty; **encryption keys** from `keys.encryption`. Each item of `keys.signature` and `keys.encryption` is `{"key": <JWK>, "validFrom", "validTo"}`, a key with its optional validity window (FR-107); a bare JWK in these lists is skipped. `certificate` is a bare JWK with no window. Keys are JWKs, accepted if RSA, at least 2048 bits, with a kid and the right use/alg (`sig`, RS256/PS256; `enc`, RSA-OAEP-256; unset allowed). Others are skipped with a warning. Entries without an id are skipped, and an id listed under two types keeps the first. |
| FR-102 | Encrypting to an entity uses one of its encryption keys usable now (FR-107), **chosen at random**. Verification tries the keys usable now (FR-107) that match the JWS `kid`. |
| FR-103 | A load replaces the registry only if every list the mode needs (FR-100) is fetched and parsed. Otherwise the previous lists are kept and the load is retried after `cr.retrySeconds` (default 300). A body that is not a JSON array, `null`, or an **empty** array for any type is a failed load. Until the first successful load, `/iop` and internal API calls fail with `503 InternalError`. |
| FR-104 | With the CR, config `entities` are local overrides of CR entries (`baseUrl`, `outboundApiKey`; `type` optional and, if different from the CR, ignored with a warning). They may not carry keys. Overrides for ids absent from the CR are ignored with a warning, and an entity absent from the CR is not registered. Hops for core-originated calls are resolved from the registry at call time. Without `cr`, config `entities` are the full registry. |
| FR-105 | One entity-fetch operation returns the entity lists from the CR (`cr.source api`) or from the configuration (`cr.source config`). Either way the result is held in memory and persisted (`cr/entities`), with only public data persisted: id, type, baseUrl, interop flag and public keys. The configuration's `outboundApiKey` and `baseUrl` override are applied on top and `outboundApiKey` is never persisted. Configured entities are usable as soon as the gateway is initialised, persisted when it starts, and not refreshed. In the configuration, `signingPublicKeys` and `encryptionPublicKeys` are both arrays; one encryption key is chosen at random per message. |
| FR-106 | **Interop readiness**. Each entity carries an `interop` flag: from the CR's `entityinfo.interop` (absent or not `true` = not interop ready), or, with `cr.source config`, from the entity's optional `interop` setting (default `true`; refused on CR overrides). When the gateway originates a message (core-originated internal API calls, including heartbeats, in every mode), both the **Target** and every **hop** (connected AA or inter-AA, preferred or from the directory) must be interop ready. A Target that is not is refused with `400 InvalidRequest` before anything is sent. A preferred hop that is not is ignored with a log line, and directory hops that are not are skipped. If no interop-ready hop remains, the call returns `400`. Forwarding and terminating inbound `/iop` calls are unchanged. |
| FR-107 | **Key validity window**. Each CR key may have a `validFrom` and a `validTo`, both optional: each an RFC 3339 timestamp with its time zone (for example `2026-11-01T00:00:00Z` or `2026-11-01T05:30:00+05:30`); absent or empty means no limit. A key is used, to verify a signature or to encrypt, only while the current time is between `validFrom` and `validTo`, both included. The window is checked each time a key is used, not only when the lists load, so a key comes into use at its `validFrom` and goes out of use at its `validTo` without a CR refresh. Keys outside their window stay in the lists. A key whose `validFrom` or `validTo` is not an RFC 3339 timestamp (a date alone included), or with `validTo` before `validFrom`, is skipped with a warning; the load does not fail. A signature whose `kid` matches only keys outside their window fails verification like an unknown key (`401`). With no encryption key in its window, nothing can be encrypted for that participant: as Target the gateway answers `500 InternalError` ("cannot encrypt response for Initiator") before calling the core; as Initiator the call fails as for a participant without encryption keys. The persisted entity lists keep the windows; snapshots from before the windows are not restored. Configured entities (`cr.source config`, for testing) have no windows. |

### 5.12 Persistent cache

| ID | Requirement |
|---|---|
| FR-110 | Fetched data is held in memory for every lookup and, with `cache.dir` set, also persisted in an **embedded persistent key-value store** on local disk. The in-memory copy serves every lookup; the persistent copy survives restarts. Persisted: the access token (`token/<self.id>`: token, issued-at, expiry), the IopToken (`iopToken/<self.id>`, the same fields), the AIG graph (`aig/graph`), the entity lists (`cr/entities`) from the CR or the configuration, **without local settings**, and the token issuer keys (`issuer/keys`). Each is written whenever its in-memory copy is replaced. |
| FR-111 | At start-up the persisted copy is loaded and served at once. It is refetched immediately only if older than its refresh interval; for the token, only if it is within its refresh margin, and an expired token is never restored. Otherwise it is refetched when it reaches that age. If the source is unavailable, the persisted copy keeps the gateway serving. |
| FR-112 | **Private signing and decryption keys are never persisted** (memory only, refetched from the core). Configured secrets (per-entity `outboundApiKey`) are never persisted. |
| FR-113 | The store is not encrypted at rest. The directory is created with mode `0700`. One gateway process per directory. The store is compacted periodically (for example every 10 minutes) so that repeated rewrites do not grow it. Without `cache.dir`, data is held in memory only. A store that cannot be opened stops start-up. |

### 5.13 Linked AAs, User discovery

| ID | Requirement |
|---|---|
| FR-120 | **linkedAAs**: the AAs this participant is linked to, the only AAs used as hops. Like `cr.source` and `aigSource`, `linkedAAs.source` selects where the list comes from, through one linked-AAs fetch operation: `config` (default; `linkedAAs.aas`, required when the internal APIs are enabled; usable as soon as the gateway is initialised, persisted when it starts, not refreshed) or `api`. Each source refuses the other's settings. With `api`: `GET <linkedAAs.url>`, default `<core.baseUrl><core.pathPrefix>/linkedAAs`, **http or https**, with `Authorization: Bearer <linkedAAs.token>` as the only header, at start-up and every `refreshSeconds` (default 3600 = 1 h), every 30 s while no list is loaded. Response: `{"linkedAAs": ["<aa id>", …]}`, non-empty, ids unique; otherwise the current list is kept. Either way the list is held in memory and in the persistent cache (`linked/aas`); with `api`, a restart serves the last list. While no list is loaded, core-originated calls return `503 InternalError`. |
| FR-121 | The core can replace the list at any time with `POST <family>/linkedAAs` (same body), over HTTP or HTTPS, with the internal API token if one is configured; only when `linkedAAs.source` is `api` (otherwise `404`). Replies, success (`200` with the new list) or error (`400`, `401`, `405`, `413`), carry no headers. |
| FR-122 | `POST /aa-dgw/User/discover` (AA mode) is served but not implemented: after the token check it returns `501 NotImplemented`. `POST /fiu-dgw/User/discover` (FIU mode) is described in FR-138. |
| FR-123 | Calls to the core carry only `Initiator-Entity`, `Correlation-Id`, `Forwarding-Hop`, `x-jws-signature` and, when configured, `Authorization`: **no role api-key header and no `Content-Type`**. Internal API responses to the core carry no `Content-Type`. The core is not required to send `Content-Type` on its requests or responses. |
| FR-138 | **`POST /fiu-dgw/User/discover`** (FIU mode) works like every other `/fiu-dgw` API (§5.7, §5.8). The body is a CustDiscoveryRequest, the payload of the Direct API `POST /User/discover`: `{ver, timestamp, txnid, correlationId, customer: {vuaHash, mobileHash}}`, with at least one of `vuaHash` (SHA-256 of the canonicalised VUA, base64url) and `mobileHash` (SHA-256 of the E.164 mobile number, base64url). `Target-Entity` is `{"type":"AA","id":"<Customer-AA>"}`. The gateway sends `/iop/User/discover` to a Connected-AA with `client_api_key`, choosing and retrying routes as for the other APIs, and returns the Customer-AA's CustDiscoveryResponse `{ver, timestamp, txnid, correlationId, status, customerDiscoveryResponse: [{customerAddress, maskedMobile, vuaAttestation}]}` (`status` `User Found` or `User Not Found`) with the Customer-AA's detached `x-jws-signature` and `Forwarding-Hop` (FR-66). |
| FR-139 | **`/iop/User/discover`** (AA mode) is encrypted like every other `/iop` API: the CustDiscoveryRequest travels signed, then encrypted, in `encryptedData`, and the reply carries the CustDiscoveryResponse in `encryptedData`. It is accepted with `client_api_key` (FIU → Connected-AA: this AA is a hop and forwards to the Customer-AA with `x-conn_aa_api_key`; the Target must be an AA in its `linkedAAs`, FR-126) and with `x-conn_aa_api_key` (Connected-AA → Customer-AA: this AA decrypts and calls `POST <core.pathPrefix>/User/discover` with `Initiator-Entity` = the FIU, like any other terminating call; the core's CustDiscoveryResponse is encrypted for the FIU, FR-14). Any other key returns `403`. `terminating.plaintextPaths` is a generic setting and is empty by default. |
| FR-140 | **`POST /fiu-dgw/broadcast/User/discover`** (FIU mode only; AA and FIP mode return `404 InvalidURI`) asks every AA whether it knows a customer. Request headers: `Authorization: Bearer <gwApi.token>` when a token is configured, `Correlation-Id` (mandatory, standard UUID format, FR-63), and optional `Http-Retries` / `Route-Retries`, which apply to the `/iop` requests. No `Target-Entity` and no `x-jws-signature`. Body: a CustDiscoveryRequest (FR-138). |
| FR-141 | **Broadcast fan-out.** For every AA in the Central Registry entity list (the copy held by the gateway), in parallel: (1) an AA in `linkedAAs` gets the Direct API `POST <AA baseUrl>/User/discover` with `client_api_key` (the FIU's access token, not the IopToken), `x-jws-signature` (detached, signed by the gateway with the FIU's signing key) and a plaintext body; its answer must be `200`, and its `x-jws-signature` must verify with the AA's signing keys (unless `forwarding.skipUpstreamResponseSignature` is set); (2) an AA not in `linkedAAs` and interop ready gets `/iop/User/discover` through a linked AA, chosen and retried as in FR-138; (3) an AA not in `linkedAAs` and not interop ready is not asked. Every request carries its own new `txnid` and the `Correlation-Id` value as `correlationId`; the rest of the body is the core's. |
| FR-142 | **Broadcast reply.** The gateway waits until every AA asked has answered, or until `gwApi.broadcastTimeoutSeconds` (FIU mode; default 10; must not be negative) has passed; later answers are ignored. It answers the core `200` with `{ver, timestamp, txnid (the core's), correlationId, status, customerDiscoveryResponse}`: the `customerDiscoveryResponse` entries of every answer whose `status` is `User Found`, merged; `status` is `User Found` when there is at least one entry, otherwise `User Not Found` with an empty array. Like other internal API replies it echoes `Correlation-Id` and carries no `Content-Type`; it carries no `x-jws-signature`, since the entries come from several AAs. |
| FR-143 | **Broadcast errors** carry `IOP-Gw-Error: true` (FR-124): `401 InvalidSecurity` (internal API token); `400 InvalidRequest` (`Correlation-Id` missing or not a UUID, body not a JSON object with `txnid`, invalid `Http-Retries` / `Route-Retries`); `405`; `503 InternalError` (entity lists not loaded yet); `503 AllRoutesUnavailable` when no AA answered successfully (§5.6, list 6). |
| FR-125 | Headers between the core and the gateway have no `x-` prefix, except `x-jws-signature`: `Target-Entity`, `Correlation-Id`, `Preferred-Hop`, `Route-Retries`, `Http-Retries` (core → gateway), `Forwarding-Hop`, `IOP-Gw-Error` (gateway → core, internal API errors) and `Initiator-Entity` (gateway → core calls). Other names with an `x-` prefix are not recognised. The `/iop` role api-key headers keep their ReBIT names. |


### 5.14 Audit records and stats

| ID | Requirement |
|---|---|
| FR-129 | **Audit records.** For every request and every response on every leg, the gateway writes one JSON log record tagged `"tag":"IOPGW_AUDIT"` (`logging.audit`, default on). Bodies are never logged; secret headers and signatures are logged as `<present>` only; other headers outside the known IOP set are listed by name with `<not logged>`. `errorMsg` is logged only for errors this gateway generated. |
| FR-130 | **Stats.** Every `logging.statsIntervalSeconds` (default 60; `0` = off) the gateway writes one JSON log record tagged `"tag":"IOPGW_STATS"`, whose `stats` field holds the counts for that interval as `\|`-separated fields; a last record is written at shutdown. Counts restart from 0 for each interval. |
| FR-131 | Audit and stats records are written at INFO whatever `logging.level` is, on the same stdout stream as the other logs, so that they can be fetched by their tag. |

**Legs**

| `leg` | Request from → to | `role` of this gateway |
|---|---|---|
| `core-in` | The core → this gateway's internal APIs | `initiator` |
| `hop-out` | This gateway → a hop AA (`/iop`), one pair per attempt | `initiator` |
| `iop-in` | Another gateway → this gateway (`/iop`) | `hop` or `target` |
| `target-out` | This gateway (hop) → the Target (`/iop`) | `hop` |
| `core-out` | This gateway → its core (`<core.pathPrefix>/*`) | `target` |

**Audit record fields** (present when known)

| Field | Value |
|---|---|
| `tag` | `IOPGW_AUDIT` |
| `event` | `request` or `response` |
| `leg`, `role` | As above |
| `self`, `mode` | This participant's id and the gateway mode |
| `method`, `path` | HTTP method and path |
| `peer` | The other side: `core`, the hop, the Target, or the calling AA (on `iop-in`, known once its api-key is checked) |
| `route`, `attempt` | `route`: `hop-out` only, the route number; `attempt`: `hop-out` and `target-out`, the attempt (on that route), from 1 |
| `bodyBytes` | Body length in bytes (never the body) |
| `ver`, `txnid`, `envTimestamp`, `correlationId` | From the body; on responses, the request's `txnid` and `correlationId`. On `/iop` legs `txnid` is the envelope's, which differs per leg (FR-63); on `core-in` and `core-out` it is the payload's |
| `initiator`, `target` | `<type>/<id>` from the envelope |
| `encryptedDataBytes` | Length of `encryptedData` |
| `status` | Response: HTTP status |
| `errorCode` | Response: the error code (this gateway's, or read from the error body received) |
| `errorMsg` | Response: only for errors generated by this gateway |
| `noResponse` | Outbound response: no answer — `timeout`, `unreachable`, `cancelled` or `response unreadable or too large` |
| `ms` | Response: latency in milliseconds |
| `headers` | Every header: the value for `Target-Entity`, `Correlation-Id`, `Forwarding-Hop`, `Preferred-Hop`, `Http-Retries`, `Route-Retries`, `Initiator-Entity`, `IOP-Gw-Error`, `Content-Type`, `Content-Length`, `Accept`, `Allow`; `<present>` for `Authorization`, role api-keys and `x-jws-signature`; `<not logged>` for any other |

**Stats record.** `stats` holds `IOPGW_STATS|<interval start>|<interval end>|<self.id>|<mode>|<seconds>|` followed by `key=count` fields in this order:

| Field | Counts |
|---|---|
| `coreReq`, `coreResp`, `coreRespOk`, `coreRespErr` | Requests from the core on the internal APIs, and the responses to them (ok: status < 400) |
| `coreNotif`, `coreNotifResp`, `coreNotifOk`, `coreNotifErr`, `coreNotifNoResp` | Calls from this gateway to its core (messages delivered to the core), and the core's responses |
| `iopReq`, `iopResp`, `iopRespOk`, `iopRespErr` | `/iop` requests from other gateways, and the responses to them |
| `hopReq`, `hopResp`, `hopOk`, `hopErr`, `hopNoResp` | Attempts towards hop AAs, and their answers |
| `targetReq`, `targetResp`, `targetOk`, `targetErr`, `targetNoResp`, `targetRetries` | Calls from this gateway (as hop) to the Target, its answers, and the retries towards it (FR-136) |
| `retries`, `nextRoute`, `allRoutesUnavailable` | Same-route retries, moves to another route, and calls where every route failed |
| `success`, `failure` | Responses given to callers (core and `/iop`) with status < 400, and ≥ 400 |

Example:

```text
IOPGW_STATS|2026-11-08T10:15:00.000Z|2026-11-08T10:16:00.000Z|fiu-test-001|FIU|60|coreReq=42|coreResp=42|coreRespOk=40|coreRespErr=2|coreNotif=17|coreNotifResp=17|coreNotifOk=17|coreNotifErr=0|coreNotifNoResp=0|iopReq=17|iopResp=17|iopRespOk=17|iopRespErr=0|hopReq=45|hopResp=44|hopOk=40|hopErr=4|hopNoResp=1|targetReq=0|targetResp=0|targetOk=0|targetErr=0|targetNoResp=0|targetRetries=0|retries=2|nextRoute=1|allRoutesUnavailable=1|success=57|failure=2
```

## 6. Interfaces

### 6.1 Inbound (network)
- HTTPS (TLS cert and key configured), or plain HTTP behind a TLS-terminating proxy.
- The header names contain underscores. Any nginx in front must set `underscores_in_headers on;`.

### 6.2 Gateway → core application

| Item | Terminating call | Heartbeat |
|---|---|---|
| Method / path | Same method as the inbound call, `<core.pathPrefix>/<api>` (e.g. `/aa-core/Consent`) | `GET <core.pathPrefix>/Heartbeat` |
| `Initiator-Entity` | Compact JSON `{"type":"…","id":"…"}` | Same |
| `Forwarding-Hop` | Id of the hop AA that delivered the call (the authenticated sender) | Same |
| `Correlation-Id` | Mandatory: the envelope's `correlationId`, copied unchanged (FR-15) | Same |
| `Authorization` | `Bearer <core.token>` when `core.token` is configured (FR-18); absent otherwise | Same |
| `x-jws-signature` | The Initiator's signature, detached | — |
| Body | The Initiator's payload: the exact bytes it signed | — |
| Not sent | The role api-key header and `Content-Type` (FR-123) | Same |
| Core response | Any status; headers below | Same |

Core response headers (core → gateway):

| Header | Required | Value |
|---|---|---|
| `Correlation-Id` | Yes | Equal to the one sent; missing or different → the response is refused with `502 InternalError` (FR-15) |
| `x-jws-signature` | No | The core's detached JWS over the response body, with this participant's signing key; used as the inner JWS. If absent, the gateway signs |

`<core.pathPrefix>/keys/*` (HTTPS only) and `<core.pathPrefix>/linkedAAs`: the request carries only `Authorization`; no response header is used.

### 6.3 Core → gateway (internal APIs)

| Item | Value |
|---|---|
| Listener | `gwApi.listenAddr` (HTTPS, always) and optionally `gwApi.httpListenAddr` (plain HTTP, no key push); internal interface only (FR-60). |
| Authentication | Optional: `Authorization: Bearer <gwApi.token>` (from an `${ENV}` secret) when a token is configured |
| Headers | See the request header table below |
| Body | Plaintext JSON payload with `txnid` (none for Heartbeat) |
| Response | The Target's payload and the upstream status, or an unsigned `ErrorResponse`; headers below |

Internal API request headers (core → gateway):

| Header | Required | Value |
|---|---|---|
| `Authorization` | When `gwApi.token` is set | `Bearer <gwApi.token>` |
| `Target-Entity` | Yes (not on the user discovery broadcast, FR-140) | `{"type","id"}` of the final recipient (FR-61) |
| `Correlation-Id` | Yes (not on `…/keys/*`) | Standard UUID format (FR-63) |
| `x-jws-signature` | No | The core's own detached JWS over the body (FR-64) |
| `Preferred-Hop` | No | Hop entity id to try first (FR-71) |
| `Http-Retries` | No | Retries per hop; `0` = do not retry (FR-72) |
| `Route-Retries` | No | Further routes to try; `0` = do not try another route (FR-73) |

Internal API response headers (gateway → core):

| Header | Present | Value |
|---|---|---|
| `x-jws-signature` | When the Target answered | The Target's detached JWS over the body. Absent on empty bodies, on errors generated by the gateway and on the user discovery broadcast reply (FR-142). (Key-push replies carry no headers, FR-92.) |
| `Correlation-Id` | Whenever the request carried one (not on `…/keys/*`) | Echoed unchanged, including on errors |
| `Forwarding-Hop` | When the answer came through a hop | The AA that delivered the call (FR-66) |
| `IOP-Gw-Error` | Only on errors generated by this gateway | `true` (FR-124) |
| `Allow` | On `405` | The accepted method |

## 7. Non-functional requirements

| ID | Area | Requirement |
|---|---|---|
| NFR-1 | Data protection | Request and response bodies are never logged. Logs carry only txnid, correlationId, path, key header, sender, target and Initiator ids, status and latency. Test fixtures use synthetic ids (`*-test-*`) and generated keys only. Audit records (FR-129) add the values of the known IOP headers, body and payload lengths, status and errorCode; secret headers and signatures appear only as `<present>`. |
| NFR-2 | Secrets | Static api-key values and the AIG token in configuration must be `${ENV_VAR}` references; literal values are refused at start-up. The entity secret lives only in the mounted credentials file, which is referenced by path. Issued tokens are held in memory only. Keys are referenced by PEM file path. Credentials files, environment files, key and certificate files and deployment configuration files must not be committed to source control. |
| NFR-3 | Cryptographic profile | JWS: RS256/PS256 with base64url-encoded payloads only. `alg: none`, HMAC, `b64: false` and `crit` are rejected. JWE: RSA-OAEP-256 / A256GCM only, and `zip` is rejected. |
| NFR-4 | Fail closed | Configuration is strict YAML: unknown keys, empty files and multi-document files are rejected. All configuration errors are reported together at start-up. |
| NFR-5 | Timeouts | Separate timeouts for forwarding and core calls (default 30 s each), with read/write timeouts on the server and graceful shutdown on SIGINT/SIGTERM. |
| NFR-6 | Dependencies | Implementation-specific; use well-established, maintained libraries from the project's pinned stack. Required capabilities: strict YAML parsing (unknown keys rejected); JOSE (JWS RS256/PS256 compact and detached, JWE RSA-OAEP-256 / A256GCM, JWK); an HTTPS client and server with TLS; an embedded persistent key-value store; structured JSON logging. |
| NFR-7 | Dev switches | `apiKey.skipVerification`, `skip*` flags and `plaintextResponses` default to off and must stay off in production. |
| NFR-8 | Performance / SLA | Throughput, latency and availability targets are not specified in this version. |
| NFR-9 | Internal API isolation | The internal APIs make the gateway sign as this participant, so they are never served on the public listener. They must be reachable only from the core's network, and should be protected with the bearer token and TLS; running them without a token or over plain HTTP relies on that network isolation alone. |
| NFR-10 | Logging | JSON lines on stdout, produced with a standard, well-established JSON logging library for the implementation language, with fields `time` (UTC, RFC 3339, milliseconds), `level` and `msg`, plus attributes. Levels are **TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL**, set by `logging.level` (default INFO). TRACE covers per-request steps; CRITICAL covers conditions that stop the gateway or leave it unable to work. NFR-1 still applies: bodies, keys and secrets are never logged. |

## 8. Configuration summary

YAML file (default `config.yaml`): `mode`, `listenAddr`, `tls`,
`self` (id, signing key, decryption keys, outbound api-key), `core` (baseUrl, keysBaseUrl, pathPrefix,
timeout, token), `apiKey` (jwt/static, claim, issuer and keys, audience, skew), `jws.algorithm`,
`entities` (id, type, baseUrl, `signingPublicKeys` and `encryptionPublicKeys` arrays, outbound api-key override),
`forwarding` (timeout and response signature check: all modes; pathRewrite and preserveUnknownEnvelopeFields: AA only),
`apiKey.issuerKeysUrl`, `apiKey.issuerKeysRefreshSeconds`, `tokenService` (baseUrl, path, iopPath, credentialsFile, refreshBeforeSeconds, timeoutSeconds), `aigBaseUrl`, `fipAigPath`, `fiuAigPath`, `aaAigPath`, `aigToken` (without tokenService), `aigRefreshSeconds`, `aigRetrySeconds`, `aigTimeoutSeconds`, `cache.dir`, `logging.level`, `terminating`, `gwApi` (listenAddr, httpListenAddr, tls, token, ver, maxRetries, maxRouteRetries, broadcastTimeoutSeconds (FIU mode)), `linkedAAs` (source, aas, url, token, refreshSeconds), `hopPreference` (connectedAAs, interAAs), `aigSource` (api | config) and `aig` (configured graph: `fiu`/`fip` in AA mode, `aa` in FIU/FIP mode), `cr.source` (api | config), `limits`.


**Production and testing.** Wherever the gateway can take something either from an API or from its
configuration, production uses the API; the configuration alternative is for testing only (FR-128):

| What | Production: API | Testing only: configuration |
|---|---|---|
| Entity registry (participants, keys, interop flags) | `cr.source: api` (Central Registry) | `cr.source: config` (`entities` with key files) |
| AIG | `aigSource: api` | `aigSource: config` (`aig` graph) |
| Linked AAs | `linkedAAs.source: api` (from the core) | `linkedAAs.source: config` (`linkedAAs.aas`) |
| Signing and decryption keys | `self.signingKey.source: api`, `self.decryptionKeys.source: api` (from the core) | `source: file` (mounted PEM files) |
| Api-key issuer keys | `apiKey.issuerKeysUrl` (JWKS) | `apiKey.issuerPublicKeys` (PEM files) |
| Api-key checking | `apiKey.mode: jwt` | `apiKey.mode: static` |
| Role api-key on `/iop` calls (IopToken); Direct API api-key and CR / AIG bearer token (access token) | `tokenService` | `self.outboundApiKey`, `cr.token`, `aigToken` |

Each core integration guide carries a default production configuration for its mode.

## 9. Acceptance criteria

Each item below must be covered by automated tests (unit, integration and end-to-end with
synthetic participants). Any implementation of this PRD must pass all of them.

- AC-1 Demand side end to end: FIU → Connected-AA → Customer-AA core, response decryptable and verifiable by the FIU.
- AC-2 A core error is returned with the core's status, encrypted in `encryptedData`.
- AC-3 Supply side end to end: FIP → Inter-AA → Origin-AA core.
- AC-4 Route tables: an `/iop` path not in the mode's route table gets `404 InvalidURI`, and no path is rewritten unless `forwarding.pathRewrite` names it.
- AC-5 Rejections: tampered body, missing signature, unknown api-key, key not allowed on the path, wrong sender type, wrong Target type, neither Target nor Initiator, unknown path, Target sent on a terminating leg.
- AC-6 A spoofed Initiator past the hop is rejected by inner-signature verification, and the core is not called.
- AC-7 FIU connector end to end via a real AA-mode Connected-AA. FIP connector end to end via a real AA-mode Inter-AA.
- AC-8 Connector route and key restrictions. AA-only settings rejected in connector mode.
- AC-9 Heartbeat: forwarded to the Target (sent with `Target` only, delivered with `Initiator` only) and reaching the FIP connector. The core receives `GET` with no body or signature, with `Forwarding-Hop`. Rejections: neither Initiator nor Target, `encryptedData` present, Initiator on a forwarding leg, Target on a terminating leg, wrong Initiator type, Target is the hop itself, unsigned, tampered, FIU as Target, a `GET` on `/iop/Heartbeat` (`405`; it is `POST` only).
- AC-10 JOSE: the RS256/PS256 detached round trip works, and `b64:false`, `alg:none` and a `kid` mismatch are rejected. A tampered JWE fails to decrypt.
- AC-11 Configuration: the example configuration parses. Unknown keys, multiple documents, empty files and literal secrets are rejected.
- AC-12 Core-originated calls end to end through real hop and far-end gateways: FIU → Connected-AA → Customer-AA core (`/fiu-dgw/Consent` → `/aa-core/Consent`); FIP → Inter-AA → Origin-AA core (`/fip-sgw/FI/Notification` → `/aa-core/FI/Notification`); Origin-AA → Inter-AA → fip-iop-gw (`/aa-sgw/Accounts/discover` → `/fip-core/Accounts/discover`); Customer-AA → Connected-AA → fiu-iop-gw (`/aa-dgw/FI/Notification` → `/fiu-core/FI/Notification`). In each case the core receives the Target's payload with the Target's signature.
- AC-13 A core-supplied `x-jws-signature` reaches the far-end core unchanged.
- AC-14 `GET /fiu-dgw/Heartbeat` (FIU) and `GET /fip-sgw/Heartbeat` (FIP) end to end.
- AC-15 Internal API rejections: no or wrong token, missing `Target-Entity`, wrong Target type, Target is the hop, no `txnid`, core signature by another key, API of another mode, wrong method. The internal APIs are not served on the public listener.
- AC-16 Internal API configuration is refused for: a literal token; a core `baseUrl` that is not http(s); no internal API TLS (HTTPS always), or a TLS key file missing; an HTTP listener without the HTTPS one, or on the same address; the same address as the public listener; a hop without `baseUrl`; no api-key for the hop; a negative `maxRetries` or `maxRouteRetries`; `linkedAAs` missing, unknown, duplicated, of an unknown source, or `api` without a token; `hopPreference.interAAs` in FIU mode, or a duplicate policy entry; an AIG graph of the wrong mode, an unknown or unconfigured id (this gateway's own `self.id` is accepted as a listed AA), an empty list, a malformed entry, an unknown `aigSource`, or API settings with the config source. Every internal API's leg is accepted by the AA-mode route table.
- AC-17 Hop selection: a preferred hop with connectivity is used; one without connectivity falls back to the directory without being called. A hop that does not answer is retried (1 + 2 attempts), then the second hop delivers; a hop's own `502`/`503`/`504` moves to the next hop at once. Defaults are 1 + 2 attempts per route and up to 3 routes; `Http-Retries: 0` and `Route-Retries: 0` give one attempt on one route. There is no retry and no other route on `IopDownstreamError` without `encryptedData`. Config caps limit the headers. Network errors exhaust hops (`503 AllRoutesUnavailable`). Rejections: bad or negative retries, zero hops, no hop reaching the Target, directory down (502).
- AC-18 `Forwarding-Hop` reaches the core on terminating calls, heartbeats included (Customer-AA core, FIU connector). The core-originated reply carries the delivering hop.
- AC-19 Linked hops: a preferred hop that is an eligible linked AA is used first; one that is not eligible is ignored; failover from an unavailable preferred AA to the next eligible one (with `Route-Retries: 1`).
- AC-20 AIG: AA mode loads both graphs (`/v1/aig/fiu`, `/v1/aig/fip`) with the bearer token in two calls; FIU and FIP mode load only `/v1/aig/aa` (AC-45); any number of lookups after that make no further calls. Unverified links still count as reachable; `verified` does not affect the hop order (FR-77). FIP inter-AAs don't reach an FIU. An FIU absent from the graph has no hops, and in AA mode an AA Target is not looked up. A lookup before the first load is an error. A refresh where one graph fails or is malformed swaps nothing in, and the previous graph survives an AIG outage. A 401, or the wrong list for a path, fails the load. Schedule: when the AIG is down at start-up, the graph loads on the retry interval once it recovers, then nothing more is called before the refresh interval. End to end: an AA that is unknown, not in `linkedAAs`, not linked to the Target in the AIG, or not interop ready is skipped and the next eligible linked AA delivers; a preferred hop not linked in the AIG is ignored; an empty link list gives 400; an AIG never loaded gives 502. Config: token required and must be `${ENV}`, absolute URL, paths start with `/`, an `aig` graph refused with the API source, FIU and FIP graphs refused in FIP mode, defaults 12 h / 5 min.
- AC-21 Access token: the token form carries `id` and `secret`. The token is cached until the refresh margin, then regenerated; a short-lived token is regenerated at half-life. A failed refresh keeps the valid token, and errors once it has expired. Failures are throttled to one per 10 s. Error messages carry `errorCode` but never the secret. A response without `expiresIn` is rejected. End to end: core-originated calls authenticate at the hop with the issued token, with one token request for several calls; forwarding uses the issued token; the AIG is loaded with the issued token; the token service down gives 503 without calling the hop. Config: secret required and `${ENV}`, absolute URL, path starts with `/`, `self.outboundApiKey` / `aigToken` refused alongside it, the AIG needs a token source, and the token service alone satisfies the hop api-key check.
- AC-22 Credentials file: a rotated secret in the mounted file is used for the next generation without a restart. A missing file, a file for another entity, a blank secret, or invalid JSON yields no token, the token service is not called, and errors never contain the secret. Config: credentials file required, must exist, and must be for `self.id`.
- AC-23 Signing keys from the core: both keys in a fetched set are used (random), from one fetch. A key rotated at the core is picked up on the refresh interval. With the core down at start-up, responses fail `500`, then are signed once the keys arrive on the 30 s retry. A POST replaces the set: the reply lists kids only, carries no headers, and later signatures use the new key. No token, wrong token or an invalid set (400) leave the set unchanged; `/fip-sgw/keys/signing` is 404 in FIU mode; paths per mode (AA `/aa-dgw` and `/aa-sgw`, FIU `/fiu-dgw`, FIP `/fip-sgw`, none with source `file`). Key list: unique kids, PEM RSA ≥ 2048 bits, and errors never contain key material. Config: https only (explicit or the core base URL default), token required and `${ENV}`, no mixing with file fields, `gwApi.tls` required, defaults 1 h and `<core.baseUrl>/fiu-core/keys/signing` (FIU mode).
- AC-24 Decryption keys from the core: with the core down at start-up, an encrypted request fails `503` and the core app is not called. After a POST of {old, current}, the request is decrypted by kid and delivered. After a POST via `/aa-sgw` (AA mode) of a set without that kid, it is no longer decryptable (400). Keys fetched by GET on the retry interval once the core recovers. Paths per mode for both key sets. Config: https only, token required, `keys` not mixed with `api`, unknown source refused, file source needs keys, `gwApi.tls` required, default URL `<core.baseUrl>/aa-core/keys/decryption` (AA mode) and 1 h.
- AC-25 Key validity: with current, not-yet-applied, expiring and inactive keys, the usable set changes by date (the next key joins at `applied`, the expiring key drops at `expiry`) and signatures never use unusable keys. Nothing usable means no signature. The status lists expiry null versus set. Parsing: expiry null or absent accepted; offsets accepted; missing `active` or `applied`, a bad date, or expiry before or equal to applied rejected without leaking key material. End to end (POST): only the current key signs; the reply marks usability per key with no key material; a list without validity fields gets 400; a set with only a future key leaves the gateway unable to sign (500). File keys: an inactive key is excluded, dated keys are honoured, bad dates stop start-up, and an expired signing key loads but cannot sign.
- AC-26 Issuer JWKS: RSA signing keys are parsed (encryption, EC and HMAC-alg entries skipped; no kid, under 2048 bits or a bad modulus rejected) and verify issued tokens. A rotated issuer key is picked up by one refetch on its unknown kid; a second unknown kid within a minute triggers no refetch and is rejected; a forged token with a known kid never triggers a refetch. With the JWKS down at start-up, api-keys are rejected until the 30 s retry loads them. End to end in jwt mode, a real call authenticates via the JWKS and a token from another key gets 401. Config: https only, not alongside PEM files, one of them required, refresh only with the URL, default 1 h.
- AC-27 CR registry: entities and types from the three lists in AA mode; in FIU and FIP mode only `/v2/entityInfo/AA` is called and the FIU and FIP lists are never fetched. `keys.signature` is used, falling back to `certificate` when empty. Encryption keys are chosen at random, with a `sig` key under encryption skipped. An undecodable key is skipped; an entry without an id is skipped; an invalid baseurl is ignored; an id under two types keeps the first. Overrides apply `baseUrl` and `outboundApiKey`; an override for an id absent from the CR is ignored. Nothing is ready before the first load. A failing, empty or null list keeps the previous registry whole. A CR down at start-up is loaded on the retry interval, with no calls before the refresh interval. End to end, the sender, Initiator and the reply's encryption key all come from the CR; an Initiator removed from the CR is refused; a CR not yet loaded gives 503. Config: https only, a token source required (not both), path starts with `/`, no keys on override entities, `cr` settings need `baseUrl`, defaults 4 h / 5 min / `/v2/entityInfo`.
- AC-28 Persistent cache: the persistent store survives a reopen, snapshots are replaced on save, the directory is created `0700`, and decoding into the wrong type fails. The access token is restored without a token-service call, refreshed within its margin, and not restored once expired. Issuer keys, CR lists and the AIG graph are restored at restart with their source down and no fetch while fresh; a stale copy is refetched at once and still served when that fails. CR overrides are re-applied but never persisted. A gateway fetching private signing keys from the core persists only the access token. Smoke run: the gateway starts with `cache.dir` and the directory is `0700`.
- AC-29 Source switches: the configured AIG graph returns hops in configured order, a FIP's inter-AA does not reach an FIU, an absent FIU has no hops, and an AA Target is refused. AA-mode end-to-end core-originated calls run on the configured graph. Config: an unknown `aigSource` or `cr.source` is refused; API settings with source `config` are refused, as are the graph with `aigSource: api`, `api` without its base URL, AIG settings in FIU mode, unknown graph hops or Targets, empty hop lists, entries naming two ids or none, and duplicate ids. The graph parses from its YAML list form, and a map form is rejected. A configured graph is usable as soon as the gateway is initialised, is persisted when it starts and never fetched over the network, and the runtime configuration is not mutated through it.
- AC-30 Configured entities through the entity-fetch operation: the registry is ready as soon as the gateway is initialised, with `outboundApiKey` applied and two `encryptionPublicKeys` loaded, both used at random. They are persisted when the gateway starts, without the api-key. A gateway with configured entities and an access token persists only `cr/entities` (no api-key or private key material) and `token/<id>`.
- AC-31 Logging: every level writes one JSON object with `level` TRACE, DEBUG, INFO, WARN, ERROR or CRITICAL, `time` in UTC RFC 3339 and the given attributes. A runtime level change filters lower levels. Level names parse case-insensitively, with WARNING and FATAL as aliases and unknown names refused (also in config). Smoke run at TRACE: request-received TRACE lines, request summaries; invalid configuration logs CRITICAL.
- AC-32 Route header: see AC-46 (`Route-Retries`).
- AC-33 CR response format: a top-level array with per-element `ver`, `timestamp`, `txnid`, `requester` and `entityinfo` parses into the entity (type from the list, `baseurl`, `interop`, signature keys and two encryption keys). An object body (e.g. `{"entities": [...]}`), `[]` and `null` each fail the load.
- AC-34 Interop readiness: `interop: true` is parsed; `false` and absent both read as not ready; signature keys are read from `keys.signature` only. A preferred hop and a directory hop that are not interop ready are skipped and the next interop-ready hop delivers without the others being called. With no interop-ready hop the call is refused with `400`. A Target that is not interop ready is refused with `400` before any hop is called.
- AC-35 Core link: `<core.pathPrefix>/*` on http and keys from an https `core.keysBaseUrl` resolve to those URLs (`/fiu-core/keys/signing`); an explicit https key `url` overrides `core.keysBaseUrl`; an http key URL, `core.keysBaseUrl` or (as key default) `core.baseUrl` is refused; a non-http(s) `core.baseUrl`, a relative key URL and a certificate without its key file are refused. Without `gwApi.token`, an internal API call without `Authorization` is accepted and delivered; with a token, a missing or wrong one gets `401`.
- AC-36 Correlation id: an internal API call's `Correlation-Id` reaches the Target's core and is echoed on the internal API response. A missing one, or one that is not a UUID, gets `400` and the Target's core is not called. A core response without `Correlation-Id`, or with a different one, is refused (`502`), and the internal API response still carries the request's value. An `/iop` request without `correlationId` is refused with `400` ("correlationId is required"), and one that is not a UUID with `400` ("correlationId must be in standard UUID format"), at the terminating gateway and at a hop, and no core is called; no correlationId is ever generated.
- AC-37 Core token: with `core.token` set, the core receives `Authorization: Bearer <token>` on a terminating call; without it, no `Authorization` header is sent. A literal value or an empty environment variable is refused at start-up.
- AC-38 Internal API signatures: a reply from the Target carries the Target's `x-jws-signature`; a gateway error (e.g. missing `Target-Entity`) and `503 AllRoutesUnavailable` carry no `x-jws-signature` and no `Content-Type`.
- AC-39 Internal API upstream codes: every hop unreachable, and a hop slower than the forwarding timeout, give `503 AllRoutesUnavailable`; the hop directory down gives `502 BadGateway`; all with `IOP-Gw-Error: true`. On `/iop`, a hop forwarding to an unreachable Target still gives `502 IopDownstreamError`, without `IOP-Gw-Error`.
- AC-40 Hop error wrapping and internal error bodies: the Target's core answering `400` reaches the FIU via the Connected-AA as `400 IopDownstreamError` with the Customer-AA's `encryptedData` unchanged (decryptable by the FIU, signed by the Customer-AA), `txnid` and `correlationId` kept; a Target `503` without a body and a Target's signed plaintext `401` both give the Target's status, `IopDownstreamError`, `errorMsg` "No error payload received" and no `encryptedData`. On `/fiu-dgw`, a missing `Target-Entity` and a wrong token give `{ver, txnid, timestamp, errorCode, errorMsg}` in that order with the payload's `ver` and `txnid`; a Heartbeat error carries `gwApi.ver` and a generated `txnid`.
- AC-41 Key API headers: a successful key push, an invalid set (`400`), a missing token (`401`) and a `GET` on the push path (`405`) all return no `x-jws-signature`, `Content-Type`, `Correlation-Id` or `Allow`, even when `Correlation-Id` was sent.
- AC-42 Internal listeners: the HTTPS listener requires `gwApi.tls`; `gwApi.httpListenAddr` needs `gwApi.listenAddr` and a different address; on the plain-HTTP handler a key push gets `403` ("only over HTTPS") with no headers; an http key URL or `core.keysBaseUrl` is refused.
- AC-43 linkedAAs: pulled at start-up (over HTTP here) and used as the only hops (an AIG-preferred AA that is not linked is skipped); a push over HTTP replaces the list with a header-less reply; an empty list, a repeated id or a missing token are refused and keep the list; a restart with the core down serves the persisted list without a fetch; with no list, calls get `503 InternalError`. Config: `aas` required with the internal APIs (source config), unknown or duplicate ids, `api` without token and unknown sources are refused.
- AC-44 Hop policy: with `hopPreference.connectedAAs` [inter, conn] the policy's first AA is used every time; without a policy, the remaining AAs are tried first in random order (each is first at least once over 40 calls); a policy AA that is not linked is never used. `interAAs` in FIU mode and duplicate entries are refused.
- AC-45 AIG v1: AA mode loads `/v1/aig/fiu` and `/v1/aig/fip` (12 h default); FIU/FIP mode loads only `/v1/aig/aa`, where peering counts in both directions, verified first, `attr` ignored, and an FIU Target is not looked up. `aig.fiu`/`aig.fip` are refused in FIP mode and `aig.aa` in AA mode.
- AC-46 `Route-Retries`: `1` lets a second route deliver after the first returns `503`; `0` tries one route only; `-1` is refused.
- AC-47 User discovery: `/aa-dgw/User/discover` returns `501 NotImplemented` after the token check (`401` without it); `/fiu-dgw/User/discover` is covered by AC-62.
- AC-48 Core calls: the core receives no role api-key header and no `Content-Type`; internal API responses carry no `Content-Type`.
- AC-49 `IOP-Gw-Error`: a gateway rejection (e.g. missing `Target-Entity`), every route failing and the hop directory down carry `IOP-Gw-Error: true`, spelled so on the wire; the Target's error payload, a Target error without payload (status, empty body), a success and an `/iop` response carry none.
- AC-50 Header names: the core's `Target-Entity`, `Correlation-Id`, `Preferred-Hop`, `Route-Retries` and `Http-Retries` are honoured; the core receives `Initiator-Entity`, `Correlation-Id` and `Forwarding-Hop`.
- AC-51 Hop errors: `400 InvalidRoute` and `401 InvalidSecurity` from a hop move to the next route without retrying it; `502`, `503` and `504` `InternalError` are not retried either: the next route delivers after one call; a `400` without a body moves on too; a hop's `503 IopDownstreamError` without `encryptedData` gives the core `503` with an empty body, no retry and no other route; with no further route, the core gets `503 AllRoutesUnavailable`; a Connected-AA without a route to the Target answers `400 InvalidRoute`.
- AC-52 Audit: one FIU → Connected-AA → Customer-AA call gives request and response records for `core-in`, `hop-out`, `iop-in` (hop and target), `target-out` and `core-out`, each with the request's `correlationId`; `core-in` and `core-out` carry the payload's `txnid`, the Initiator → hop leg (`hop-out`, `iop-in` hop) and the hop → Target leg (`target-out`, `iop-in` target) each their own, different, envelope `txnid`; no record contains a payload value, the internal API token or an api-key; a call where every route fails gives a `core-in` response with `503`, `AllRoutesUnavailable`, its `errorMsg` and `IOP-Gw-Error: true`, and a `hop-out` response with `noResponse: unreachable`.
- AC-53 Stats: the stats line has the tag, interval, `self.id`, mode and seconds, then every counter as `key=count`; counts restart from 0 for each interval; records are written at each interval and at shutdown, even with `logging.level: CRITICAL`.
- AC-55 FIU with the AIG API: `/v1/aig/aa` links the Connected-AA to the Customer-AA (listed under the Connected-AA only); a second linked AA not linked to the Customer-AA is never called, even as `Preferred-Hop`; with the Connected-AA not interop ready the call returns `400` (no eligible route); with the Customer-AA not interop ready it returns `400 Target is not interop ready`.
- AC-56 Hop retries: a Target that answers `503` without a body twice and then succeeds is delivered with the default `forwarding.httpRetries` (3 calls); with `0`, one call and `503 IopDownstreamError`; with the retries used up, the last `503` is wrapped; a `503` with `encryptedData` reaches the Target core once and is not retried; an unreachable Target gives `502` after the retries; `forwarding.httpRetries` is refused in FIU mode and when negative.
- AC-57 Envelope `txnid`: retries on one route carry the same envelope `txnid`; another route gets a new one; both are UUIDs other than the payload's `txnid`. A hop relays the Target's reply with the `txnid` of the caller's request, signed by the hop.
- AC-58 Unused party field: an Initiator next to the Target on a forwarding leg is ignored (the hop sets the sender as Initiator), and a Target next to the Initiator on a terminating leg is ignored; both calls are delivered.
- AC-59 Link reverify: `/iop/Accounts/link/reverify` from the Origin-AA through the Inter-AA reaches the FIP connector and is delivered to `/fip-core/Accounts/link/reverify`; in AA mode it accepts `x-orig_aa_api_key` with `Target{FIP}` and is sent on with `x-inter_aa_api_key`; `/aa-sgw/Accounts/link/reverify` is in the internal API table and its leg is accepted by the AA-mode route table.
- AC-60 Hop route check: as a hop, an AA answers `400 InvalidRoute` and does not call the Target when an AA Target is not in its `linkedAAs`, when the AIG does not list it as a Connected-AA of the Target FIU, or when the AIG does not list it as an Inter-AA of the Target FIP.
- AC-61 `errorSource`: when the Target's error answer carries an `errorSource` object, with or without `encryptedData`, the hop's answer carries it unchanged next to `errorCode` `IopDownstreamError`.
- AC-62 FIU user discovery: a CustDiscoveryRequest on `/fiu-dgw/User/discover` with `Target-Entity` naming the Customer-AA goes to the Connected-AA with `client_api_key`, is forwarded with `x-conn_aa_api_key` and delivered to `/aa-core/User/discover` with `Initiator-Entity` naming the FIU; the fiu-core receives the Customer-AA's CustDiscoveryResponse (synthetic handle, e.g. `customer-test-001@aa-test-002`) with the Customer-AA's `x-jws-signature` and `Forwarding-Hop`.
- AC-63 Broadcast fan-out: with two linked AAs (one answering `User Found`, one slower than `gwApi.broadcastTimeoutSeconds`), one interop-ready AA that is not linked (answering `User Found` through `/iop/User/discover` via a linked AA) and one AA that is neither linked nor interop ready, the fiu-core gets `200 User Found` with the two found entries merged; the slow answer is ignored; the AA that is not interop ready is never asked; the linked AAs are called on the Direct API `/User/discover`; each AA receives its own `txnid` and the core's `correlationId`.
- AC-64 Broadcast errors: when every AA fails, the fiu-core gets `503 AllRoutesUnavailable`; in AA mode the broadcast path returns `404`.
- AC-65 CR key windows: a key whose `validTo` has just passed is loaded but not used; a key valid from yesterday to tomorrow and one with no `validFrom` or `validTo` are used; a key starting in an hour is not used now and is usable after its `validFrom` without a refresh; a key whose `validFrom` is a date without a time, or with `validTo` before `validFrom`, is skipped; an encryption key whose `validTo` has passed is never chosen. The windows survive persistence. End to end: a request signed with a sender key whose `validTo` has passed gets `401`; when the Initiator's only encryption key has ended, the reply cannot be encrypted (`500`) and the core is not called.
- AC-66 Two tokens: the token service is asked once at `<path>` and once at `<iopPath>`; core-originated `/iop` calls carry the IopToken as the role api-key, and the Direct API `/User/discover` of the broadcast carries the access token as `client_api_key`. The two tokens are persisted under different names (`token/<self.id>`, `iopToken/<self.id>`). A relative `tokenService.iopPath` is rejected.
