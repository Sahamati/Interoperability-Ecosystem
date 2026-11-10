# IOP Gateway — Integration Guide for the fiu-core

|  |  |
|---|---|
| **Audience** | FIU core application teams (AA ecosystem participants) |
| **Version** | Draft 3.5, 2026-11-10 |
| **Covers** | How the fiu-core sends and receives messages through the fiu-iop-gw, when to call it, how the fiu-core gives it keys and its list of linked AAs, and how the fiu-iop-gw is configured |

All identifiers in examples are illustrative.

## Changes needed in the fiu-core

To work with the fiu-iop-gw, the fiu-core needs the changes below. "Yes" means needed in production.

| # | Change in the fiu-core | Needed | Section |
|---|---|---|---|
| 1 | Call the fiu-iop-gw's internal APIs (`/fiu-dgw/*`) instead of the Direct APIs when the customer's AA (Customer-AA) is not directly connected to the FIU. Keep using the Direct APIs for directly connected participants. | Yes | 2, 3.3 |
| 2 | Send `Target-Entity` and `Correlation-Id` on every call, and `Authorization` with the internal API token. Optionally send `Preferred-Hop`, `Http-Retries`, `Route-Retries` and the fiu-core's own `x-jws-signature`. | Yes | 3.4 |
| 3 | Create a non-empty correlation id for each new flow, and keep it on every message of that flow. | Yes | 2 |
| 4 | Handle the responses: the Target's payload and signature; Target errors (with a payload, or a status with an empty body); errors from the fiu-iop-gw (`IOP-Gw-Error: true`, for example `503 AllRoutesUnavailable`). | Yes | 3.6 – 3.10 |
| 5 | To find which AAs know a customer, call `POST /fiu-dgw/broadcast/User/discover` (one call asks every AA) and handle its merged answer. | Optional | 3.13 |
| 6 | Expose the `/fiu-core/*` APIs to receive messages from participants that are not directly connected. The payloads are those of the Direct APIs. | Yes | 4.3 – 4.5 |
| 7 | Return `Correlation-Id` unchanged on every `/fiu-core/*` response. | Yes | 4.6 |
| 8 | Check `Authorization` on every `/fiu-core/*` call (the token the fiu-iop-gw sends to the fiu-core). | Recommended | 4.4, 7 |
| 9 | De-duplicate incoming messages on `txnid`: retries can deliver a message twice, and the fiu-core must not process it twice. | Yes | 4.5 |
| 10 | Serve the key endpoints `GET /fiu-core/keys/signing` and `GET /fiu-core/keys/decryption` over HTTPS, checking the key-fetch token. | Yes | 5.1 |
| 11 | Push new key sets to `/fiu-dgw/keys/*` when keys rotate. | Recommended | 5.2 |
| 12 | Serve `GET /fiu-core/linkedAAs` with the AAs the FIU is linked to. | Yes | 6.1 |
| 13 | Push the list to `/fiu-dgw/linkedAAs` when it changes. | Recommended | 6.2 |
| 14 | Set the fiu-iop-gw's configuration and provide its tokens, certificates and credentials before starting it. | Yes | 8 |

## 1. Terminology

| Term | Meaning |
|---|---|
| fiu-core | The FIU's own application as it is today: the system that sends consent and FI requests and receives notifications. |
| aa-core | The AA's own application as it is today. |
| fip-core | The FIP's own application as it is today. |
| fiu-iop-gw, aa-iop-gw, fip-iop-gw | The IOP Gateway, run by the FIU, AA or FIP in front of its core. It handles the IOP security (signatures, encryption) and routing. |
| Internal APIs | The APIs the fiu-iop-gw offers to the fiu-core: `/fiu-dgw/*`. |
| Target | The participant that finally receives a message. |
| Initiator | The participant that created a message (the first sender of a flow). |
| Correlation-Id (`correlationId`) | The id of one flow, in **standard UUID format** (RFC 4122, for example `9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94`). The Initiator creates it; it stays the same on every message of the flow and is never created by the IOP Gateway. The fiu-core sends it in the `Correlation-Id` header; the IOP message carries it as `correlationId`. |
| Route (hop) | The AA that carries a message to a Target that is not directly connected. |
| Connected-AA | An AA directly connected to an FIU. It carries messages between the FIU and other AAs. |
| Inter-AA | An AA directly connected to a FIP. It carries messages between the FIP and other AAs. |
| Customer-AA / Origin-AA | The AA that holds the customer's consent (Customer-AA, towards FIUs) / that sends requests to a FIP (Origin-AA). |
| linkedAAs | The AAs the FIU is linked to: the only AAs the fiu-iop-gw uses as routes (section 6). |
| AIG | AA Interoperability Graph, published by the Central Registry: which AAs can reach which participant. |
| Direct APIs | The existing ReBIT APIs as of today (for example `/Consent`, `/FI/request`, `/FI/Notification`), which participants call on each other when they are directly connected. The IOP Gateway carries exactly the same payloads. |
| ReBIT specifications | The AA ecosystem API specifications that define the Direct APIs. |

## 2. When to call the fiu-iop-gw

| Situation | Does the fiu-core call the fiu-iop-gw? |
|---|---|
| The customer's AA is **directly connected** to the FIU | **No.** The fiu-core calls that AA's Direct APIs. |
| The customer's AA is **not directly connected** to the FIU | **Yes.** The fiu-core calls the fiu-iop-gw (`/fiu-dgw/*`). The fiu-iop-gw sends the message through one of the FIU's Connected-AAs. |
| A customer's AA that is not directly connected sends a notification | **No call needed.** The fiu-iop-gw receives it and calls the fiu-core (`/fiu-core/*`), see section 4. |
| The fiu-core wants to find which AAs know a customer | **Optional.** The fiu-core can call `POST /fiu-dgw/broadcast/User/discover` (section 3.13). One call asks every AA, directly connected or not. |

**Every message must carry a correlation id.**

- All AA ecosystem participants must send a non-empty `correlationId` in every IOP message.
- The Initiator creates it for the flow. It stays the same on every message of that flow.
- It must be in standard UUID format (section 1).
- The fiu-iop-gw never creates one. It refuses a message without one, or with one that is not a UUID, with `400 InvalidRequest`.
- When the fiu-core sends through the fiu-iop-gw, the mandatory `Correlation-Id` header (section 3.4)
  provides it.

## 3. Sending messages through the fiu-iop-gw

### 3.1 Who calls

| Caller | Callee | Connection |
|---|---|---|
| fiu-core | fiu-iop-gw | The fiu-iop-gw's internal APIs (`/fiu-dgw/*`). HTTPS always; plain HTTP as well if the fiu-iop-gw is configured with an HTTP listener. |

### 3.2 How it works

**Sending the request.** For each call, the fiu-iop-gw:

1. **Signs the payload.** If the fiu-core sends its own `x-jws-signature` (RFC 7797), the fiu-iop-gw
   checks it first. The fiu-iop-gw then signs the payload with the FIU's signing key: the signature inside
   the encrypted payload is a standard JWS (RFC 7515), so the fiu-core's RFC 7797 signature is not
   carried in it.
2. **Encrypts** the signed payload for the Target.
3. **Builds the IOP request** around the encrypted payload (`ver`, `timestamp`, `txnid`,
   `correlationId`, `Target`, `encryptedPayload`) and **signs it**. The request carries only `Target`;
   the route sets `Initiator` when it forwards the request. Its `txnid` is **not** the
   payload's: it identifies the transaction between the fiu-iop-gw and the route, a new one for each
   route.
4. **Chooses a route** (section 3.11) and sends the IOP request to that AA.

**Receiving the response.** When the answer comes back, the fiu-iop-gw:

1. **Checks the signature of the Connected-AA** on the answer.
2. **Decrypts** the Target's encrypted reply (`encryptedPayload`, in success and error answers alike;
   the HTTP status tells them apart).
3. **Checks the Target's signature** on the reply.
4. **Returns the Target's reply** to the fiu-core: the Target's payload, the Target's status and
   the Target's signature (`x-jws-signature`).

A Heartbeat has no encrypted payload: sending steps 1 and 2 are skipped, and the IOP request
(always `POST /iop/Heartbeat`) carries only the `Target`, without `encryptedPayload`. `/iop/Heartbeat` is only for a Target that is
not directly connected: a directly connected participant (for example the route itself) is
checked with the Direct API `GET /Heartbeat`.

### 3.3 APIs

| Method | Path | Caller | Callee | `Target-Entity` type | Same payload as the Direct API | Use |
|---|---|---|---|---|---|---|
| `POST` | `/fiu-dgw/Consent` | fiu-core | fiu-iop-gw | `AA` | `/Consent` | Consent request to the customer's AA |
| `POST` | `/fiu-dgw/Consent/handle` | fiu-core | fiu-iop-gw | `AA` | `/Consent/handle` | Consent handle status |
| `POST` | `/fiu-dgw/Consent/fetch` | fiu-core | fiu-iop-gw | `AA` | `/Consent/fetch` | Fetch a consent artefact |
| `POST` | `/fiu-dgw/FI/request` | fiu-core | fiu-iop-gw | `AA` | `/FI/request` | FI data request |
| `POST` | `/fiu-dgw/FI/fetch` | fiu-core | fiu-iop-gw | `AA` | `/FI/fetch` | FI data fetch |
| `POST` | `/fiu-dgw/Consent/Notification` | fiu-core | fiu-iop-gw | `AA` | `/Consent/Notification` | Consent status notification to the AA |
| `GET` | `/fiu-dgw/Heartbeat` | fiu-core | fiu-iop-gw | `AA` | `/Heartbeat` | Heartbeat towards the AA (no body) |
| `POST` | `/fiu-dgw/User/discover` | fiu-core | fiu-iop-gw | `AA` | `/User/discover` | User discovery at the customer's AA |

The Target (`Target-Entity`) is the **customer's AA** (the Customer-AA).

To ask **every** AA at once whether it knows a customer, the fiu-core calls `POST /fiu-dgw/broadcast/User/discover` instead (section 3.13).

### 3.4 Request headers

| Header | Mandatory | Value |
|---|---|---|
| `Authorization` | Yes, if the fiu-iop-gw is configured with an internal API token | `Bearer <internal API token>`. Without it (or with a wrong one) the call is refused with `401`. |
| `Target-Entity` | Yes | The final recipient, as compact JSON: `{"type":"<AA\|FIU\|FIP>","id":"<entity id>"}`. The type must match the API (section 3.3). The Target must be marked interop ready in the Central Registry. |
| `Correlation-Id` | Yes | The flow's correlation id, in standard UUID format (see section 1). It is carried in the IOP message and returned on every response. A missing value, or one that is not a UUID, is refused with `400 InvalidRequest`. |
| `x-jws-signature` | No | The fiu-core's own detached JWS over the request body (RFC 7797 unencoded payload: protected header `{"alg": "RS256", "kid", "b64": false, "crit": ["b64"]}`, signed over the raw body), made with one of the FIU's registered signing keys. The fiu-iop-gw checks it: if it does not verify, the call is refused with `400`. The fiu-iop-gw signs the payload either way (section 3.2). |
| `Preferred-Hop` | No | The entity id of the AA the core prefers as the route. Used first only if it is an eligible route (section 3.11); otherwise ignored. |
| `Http-Retries` | No | How many times to retry the same route when it does not answer (no connection, or a timeout). An error answer from the route, `502`/`503`/`504` included, is not retried on that route. **`0` means: do not retry.** Default `2`; capped by the gateway (by default at `3`). Waits 200 ms, doubling up to 2 s, between retries. |
| `Route-Retries` | No | How many **other** routes to try after the first route fails (section 3.7). **`0` means: do not try another route.** Default `2`; capped by the gateway (by default at `2`). |

No other header is needed. `Content-Type` is not required.

### 3.5 Request body

- The request body is **exactly the same payload** the FIU would send to a directly connected
  participant in the matching Direct API call (column "Same payload as the Direct API" in section 3.3).
- Example: `POST /fiu-dgw/Consent` carries exactly the payload the FIU would send in the Direct API `/Consent` call to an AA it is directly connected to.
- Example: `POST /fiu-dgw/User/discover` carries the same payload as the Direct API `/User/discover` call (a `CustDiscoveryRequest`). The response is the Customer-AA's `CustDiscoveryResponse`.
- The body must contain `txnid`; `ver` is taken from it.
- A Heartbeat (`GET`) has no body.
- Retries and further routes resend the **same payload, with the same `txnid` in the payload**.
  A duplicate delivery is still possible, so every Target **must** de-duplicate on the payload's
  `txnid` (section 4.5).

### 3.6 Response body

What the core receives depends on what comes back from the Connected-AA. Section 3.7 shows how each answer is handled.

| Outcome | Status | Body |
|---|---|---|
| The Target answered (success or error) | The Target's status | **Exactly the same payload** the Target returns in the matching Direct API call, as the Target signed it (decrypted by the gateway). |
| The Target answered an error without a payload | The Target's status (passed on by the Connected-AA) | Empty. |
| Every route failed | `503` | An `ErrorResponse` with `errorCode` `AllRoutesUnavailable` (section 3.9). |
| The fiu-iop-gw refused the call | 400, 401, 404, 405, 413, 500, 502, 503 or 504 | An `ErrorResponse` (section 3.9). |

### 3.7 How the gateway handles an error from the Connected-AA

This applies only when the Connected-AA answers with an error (status `4xx` or `5xx`). Success
answers (`2xx`, `3xx`) are opened and passed on as in section 3.6.

| Payload from the Connected-AA | `encryptedPayload` in the payload | `errorCode` in the payload | What the fiu-iop-gw does | Status to the core | Body to the core | `IOP-Gw-Error` |
|---|---|---|---|---|---|---|
| Yes | Yes | Any | Answers the core | The Connected-AA's status | The Target's error payload (decrypted), with the Target's signature | Not set |
| Yes | No | `IopDownstreamError` | Answers the core | The Connected-AA's status | Empty | Not set |
| Yes | No | Anything else | Tries another route (see below); if every route fails, answers the core | `503` | Generated: `errorCode` `AllRoutesUnavailable` | `true` |
| No | No | None | Tries another route (see below); if every route fails, answers the core | `503` | Generated: `errorCode` `AllRoutesUnavailable` | `true` |

- **Another route** is tried within the limits of section 3.11: up to `Route-Retries`
  other routes. The same route is first retried (up to `Http-Retries` times) only when it
  did not answer at all; an error answer, `502`, `503` or `504` included, moves to the next
  route at once.
- When the Connected-AA does not answer at all (no connection, or a timeout), it is handled like the
  last row.
- `IopDownstreamError` without `encryptedPayload` means the Connected-AA reached the Target, but the Target
  answered an error without a payload. Another route would reach the same Target, so the
  gateway does not try one.

### 3.8 Response headers

| Header | Present | Value |
|---|---|---|
| `x-jws-signature` | When the Target answered with a payload | **The Target's** detached JWS over the body, taken from the Target's signed payload: a standard detached JWS (RFC 7515, base64url-encoded payload), **not** RFC 7797. Already checked by the gateway; the core may store it as proof of what the Target sent. Checking it is optional: to check it, verify RS256 over `BASE64URL(header) + "." + BASE64URL(body)` with the other party's signing key from the Central Registry, not with an RFC 7797 verifier. Never present on an empty body or on an error generated by the gateway. |
| `Correlation-Id` | Always (when the request carried one) | The value the core sent. |
| `Forwarding-Hop` | When the answer came through a Connected-AA | The entity id of the Connected-AA that carried the call. Not present when every route failed. |
| `IOP-Gw-Error` | Only on errors generated by the fiu-iop-gw | `true`. The body is then the gateway's `ErrorResponse` (section 3.9). Without this header, an error came from the Target, through the Connected-AA. |
| `Allow` | On `405` | The method the API accepts. |

No `Content-Type` is sent.

### 3.9 Error codes

Errors generated by the fiu-iop-gw itself carry `IOP-Gw-Error: true` and have this body (not signed):

```json
{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-07T11:33:34.509Z",
  "errorCode": "InvalidRequest",
  "errorMsg": "Target-Entity header must be {\"type\":...,\"id\":...}"
}
```

- `ver` and `txnid` come from the request body. `ver` defaults to the gateway's configured
  version. For a Heartbeat, `txnid` is the one the gateway created for the call.
- `errorMsg` explains the specific cause.

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | `Target-Entity` missing, invalid or of the wrong type; the Target is not registered or not marked interop ready; `Correlation-Id` missing or not in standard UUID format; `Http-Retries` or `Route-Retries` not a non-negative number; the body is not a JSON object with `txnid`; the core's `x-jws-signature` does not verify; no interop-ready linked AA can reach the Target |
| `401` | `InvalidSecurity` | The internal API token is missing or wrong (when one is configured) |
| `404` | `InvalidURI` | The API is not available for the FIU |
| `405` | `InvalidRequest` | Wrong HTTP method (see `Allow`) |
| `413` | `InvalidRequest` | The request body is too large |
| `500` | `InternalError` | The gateway cannot sign the payload or encrypt it for the Target (for example, no encryption key published for the Target) |
| `502` | `BadGateway` | The AIG is not available; the answer of the Connected-AA has an invalid signature, cannot be decrypted, or is malformed |
| `502` | `SignatureDoesNotMatch` | The Target's signature on the reply does not verify |
| `503` | `AllRoutesUnavailable` | Every route failed: no Connected-AA answered, or each answered an error that is not from the Target (section 3.7) |
| `503` | `InternalError` | The gateway is not ready yet: registry, keys or linkedAAs not loaded, or IopToken unavailable |
| `504` | `GatewayTimeout` | The core's request was cancelled while the gateway waited to retry |

### 3.10 Error examples

**1. The fiu-iop-gw rejects the call** — for example, `POST /fiu-dgw/Consent` with a Target (`aa-test-002`) that is
not marked interop ready. No route is used.

```http
HTTP/1.1 400 Bad Request
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94
IOP-Gw-Error: true

{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-07T11:33:34.509Z",
  "errorCode": "InvalidRequest",
  "errorMsg": "Target is not interop ready"
}
```

**2. The Connected-AA rejects the call** — for example, the Connected-AA (`aa-test-001`) answers `400`
with `errorCode` `InvalidRoute` (it cannot route to the Target). The gateway tries the other
routes allowed by `Route-Retries`. When none is allowed or left, every route has failed.
`InvalidRoute` is the code the IOP Gateway uses when, as a hop, it cannot route to the Target. **It is not yet confirmed as a ReBIT IOP error code.**


```http
HTTP/1.1 503 Service Unavailable
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94
IOP-Gw-Error: true

{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-07T11:33:34.509Z",
  "errorCode": "AllRoutesUnavailable",
  "errorMsg": "no route could deliver the call (1 tried)"
}
```

**3. The Target returns an error without a body** — for example, `POST /fiu-dgw/FI/request` and the Target
(`aa-test-002`) answers `500` with no payload. The Connected-AA (`aa-test-001`) answers `IopDownstreamError`
without `encryptedPayload`. The core receives the status with an **empty body**. This answer is final:
the gateway does not retry it or try another route.

```http
HTTP/1.1 500 Internal Server Error
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94
Forwarding-Hop: aa-test-001
```

**4. The Target returns an error** — for example, `POST /fiu-dgw/FI/request` and the Target (`aa-test-002`) answers `400`
with an error payload. The core receives **the Target's own error payload**, exactly as the
Target signed it, with the Target's status and signature. Its content is defined by the Target.

```http
HTTP/1.1 400 Bad Request
x-jws-signature: <the Target's detached JWS over the body>
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94
Forwarding-Hop: aa-test-001

{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-07T11:33:34.509Z",
  "errorCode": "InvalidRequest",
  "errorMsg": "FI request is invalid for the consent"
}
```

### 3.11 How the route is chosen

The fiu-core does not need to choose a route. The fiu-iop-gw does it as follows.

**Which AAs can be a route** — an AA is eligible only if **all** of these hold:

- It is in the FIU's **linkedAAs** (section 6).
- The **AIG** says it can reach the Target. The fiu-iop-gw uses the AA graph (`GET /v1/aig/aa`). It lists only AAs and the AAs each is linked to (no FIUs or FIPs); an AA qualifies if the AIG links it to the Target AA, in either direction. It loads the AIG from the
  Central Registry at start-up and every 12 hours, with its own access token, and keeps a copy.
- It is marked interop ready in the Central Registry.
- It is not the Target itself, Heartbeat included.

The **Target** must also be marked interop ready in the Central Registry; otherwise the call is
refused with `400 InvalidRequest` before any route is chosen.

**In which order the routes are tried:**

1. The core's `Preferred-Hop`, if it is eligible.
2. The gateway's **hop-preference policy** (`hopPreference.connectedAAs`), in the configured order.
3. The other eligible AAs, in **random order** (this spreads the load across them).

**How many routes and retries:** the first route, plus up to `Route-Retries` other routes.

| Connected-AA's answer | Retry the same route | Try the next route |
|---|---|---|
| No answer (no connection, or a timeout) | Yes, up to `Http-Retries` | Yes, up to `Route-Retries` |
| Any error not from the Target, `502`/`503`/`504` included (for example `400 InvalidRoute`\*) | No | Yes, up to `Route-Retries` |
| An error with `encryptedPayload`, or with `IopDownstreamError` | No | No (the answer goes to the core, section 3.7) |
| Success | No | No |

"Not from the Target" means: no `encryptedPayload` in the payload, and `errorCode` is not
`IopDownstreamError` (section 3.7).

\* `InvalidRoute` is the code the IOP Gateway uses when, as a hop, it cannot route to the Target: the Target is unknown to the hop, or is not linked to the hop AA. Linked means: an FIU Target lists the hop AA as a Connected-AA in the AIG; a FIP Target lists the hop AA as an Inter-AA in the AIG; an AA Target is in the hop AA's linkedAAs. The hop then does not call the Target. If the hop cannot check this (its AIG is not loaded), it answers `503 InternalError`; both answers lead to the next route. **It is not yet confirmed as a ReBIT IOP error code.**

### 3.12 Retries

The fiu-iop-gw retries a call from the fiu-core as follows.

| | |
|---|---|
| Sends to | A Connected-AA (`/iop`), chosen as in section 3.11 |
| Retries the same route | `Http-Retries` header: default 2, capped by the gateway (by default at 3) |
| … when | The Connected-AA does not answer (no connection, or a timeout). An error answer from the Connected-AA, `502`/`503`/`504` included, is never retried on the same route |
| Tries another route | `Route-Retries` header: default 2, capped by the gateway (by default at 2). After the retries when the Connected-AA does not answer; at once on any error from the Connected-AA that is not from the Target (for example `503` or `400 InvalidRoute`) |
| Never retries | Success; an answer with `encryptedPayload` (the Target's error); `IopDownstreamError` without `encryptedPayload` |
| Wait between attempts | 200 ms, doubling, at most 2 s |
| Most sends per call (defaults) | (1 + 2 routes) × (1 + 2 retries) = 9 |
| When all attempts fail | The fiu-core gets `503 AllRoutesUnavailable` with `IOP-Gw-Error: true` |

**Received in response to an `/iop/*` API from the Connected-AA**

| StatusCode | ErrorCode | EncryptedPayload | Inference | RetryHttp | RetryRoute |
|---|---|---|---|---|---|
| — (no response) | — | — | The Connected-AA could not be reached, or did not answer in time | Yes, up to `Http-Retries` | Yes, after the retries |
| `2xx`, `3xx` | — | — | Success: the Target's answer. The fiu-core gets the Target's payload, status and signature | No | No |
| Any `4xx`/`5xx` | Any | Present | The Target answered with an error. The fiu-core gets the Target's error payload, status and signature | No | No |
| `4xx` | `IopDownstreamError` | Absent | The Target answered `4xx` without a payload. The fiu-core gets the same status with an empty body | No | No |
| `5xx` | `IopDownstreamError` | Absent | The Target failed (`5xx` without a payload), or the Connected-AA could not reach it (`502`) or got no answer in time (`504`). Every route leads to the same Target. The fiu-core gets the same status with an empty body | No | No |
| `502`, `503`, `504` | Other than `IopDownstreamError`, or none | Absent | The Connected-AA itself is unavailable | No | Yes, at once |
| `400` | `InvalidRoute`\* | Absent | The Connected-AA cannot route to the Target | No | Yes, at once |
| Any other `4xx`/`5xx` | Other than `IopDownstreamError`, or none | Absent | The Connected-AA refused the call, or failed | No | Yes, at once |

- **StatusCode:** the HTTP status code of the Connected-AA's response.
- **ErrorCode:** the `errorCode` set by the Connected-AA.
- **EncryptedPayload:** the `encryptedPayload` field: the Target's encrypted answer, forwarded by the Connected-AA.
- **RetryHttp:** whether the same route is retried. **RetryRoute:** whether a different route is tried.
- When every route has failed, the fiu-core gets `503 AllRoutesUnavailable` with `IOP-Gw-Error: true`.

\* See the note in section 3.11.

1. **Errors from beyond the Connected-AA are final.** `IopDownstreamError` without `encryptedPayload` means the
   Target could not be reached, or answered an error without a payload. Every route leads to the
   same Target, so the fiu-iop-gw neither retries nor tries another route.
2. **Every resend carries the same payload and `correlationId`.** The payload's `txnid` stays the
   same; the IOP request's own `txnid` is the same on retries of one route and new for each
   route. Every Target, including the fiu-core, **must** de-duplicate on the payload's `txnid`.
3. **Fit within the fiu-core's own timeout.** One call can take up to
   (1 + `Route-Retries`) × (1 + `Http-Retries`) × (forwarding timeout + 2 s): about 4.8 minutes
   with the defaults (3 × 3 × 32 s), and about 6.4 minutes at the gateway's caps (3 × 4 × 32 s).
   Choose `Http-Retries` and `Route-Retries` so that this fits the fiu-core's HTTP client timeout
   for the internal APIs; for example, with a 60 s timeout, send `Http-Retries: 0` and
   `Route-Retries: 0` (one attempt, at most 32 s).

### 3.13 User discovery at every AA (broadcast)

`POST /fiu-dgw/broadcast/User/discover` asks **every AA at once** whether it knows a customer, and
returns one merged answer. The fiu-core does not need to know which AA holds the customer, or
whether that AA is directly connected to the FIU.

**Who calls**

| Caller | Callee | Connection |
|---|---|---|
| fiu-core | fiu-iop-gw | The fiu-iop-gw's internal APIs, as in section 3.1. |

**API**

| Method | Path | Caller | Callee | `Target-Entity` type | Same payload as the Direct API | Use |
|---|---|---|---|---|---|---|
| `POST` | `/fiu-dgw/broadcast/User/discover` | fiu-core | fiu-iop-gw | — (not sent) | `/User/discover` | Ask every AA whether it knows the customer |

**Request headers**

| Header | Mandatory | Value |
|---|---|---|
| `Authorization` | Yes, if the fiu-iop-gw is configured with an internal API token | `Bearer <internal API token>`, as in section 3.4. |
| `Correlation-Id` | Yes | The flow's correlation id, in standard UUID format. It is copied as `correlationId` into every request the fiu-iop-gw sends for this call, and returned on the response. A missing value, or one that is not a UUID, is refused with `400 InvalidRequest`. |
| `Http-Retries` | No | As in section 3.4. Applies to the `/iop/User/discover` requests sent through a Connected-AA. |
| `Route-Retries` | No | As in section 3.4. Applies to the `/iop/User/discover` requests sent through a Connected-AA. |

`Target-Entity`, `Preferred-Hop` and `x-jws-signature` are not used: the fiu-iop-gw chooses the
AAs and signs every request itself. `Content-Type` is not required.

**Request body**

- A `CustDiscoveryRequest`: the same payload as the Direct API `/User/discover` call (`ver`,
  `timestamp`, `txnid`, `correlationId`, and `customer` with `vuaHash`, `mobileHash` or both).
- The body must be a JSON object with `txnid`.
- Each AA receives a copy with **its own new `txnid`** and with `correlationId` set to the
  `Correlation-Id` header value. All other fields are sent as the fiu-core sent them.

**How it works**

The fiu-iop-gw takes every AA in its copy of the Central Registry participant list and, for all of
them at the same time:

| The AA is | What the fiu-iop-gw sends | The answer is used when |
|---|---|---|
| In the FIU's linkedAAs (section 6) | The Direct API `POST <AA base URL>/User/discover`, with a plaintext body and the headers `client_api_key` (the FIU's api-key from the Sahamati token service) and `x-jws-signature` (a detached JWS made by the fiu-iop-gw with the FIU's signing key). | The status is `200` and the AA's `x-jws-signature` verifies with the AA's keys from the Central Registry. |
| Not in linkedAAs, and marked interop ready | `/iop/User/discover` through a Connected-AA, with the route chosen and retried as for `/fiu-dgw/User/discover` (sections 3.11 and 3.12). The reply is opened and checked as in section 3.2. | The Customer-AA's status is `200`. |
| Not in linkedAAs, and not marked interop ready | Nothing: the AA is not asked. | — |

- The fiu-iop-gw waits until every AA asked has answered, or until `gwApi.broadcastTimeoutSeconds`
  (default 10 seconds) has passed. Later answers are ignored.
- An AA that does not answer, or answers with an error, is left out of the result.
- The fiu-core's HTTP client timeout for this call should be longer than
  `gwApi.broadcastTimeoutSeconds`.

**Response**

`200` with a `CustDiscoveryResponse`:

| Field | Value |
|---|---|
| `ver` | From the request body (the gateway's configured version if the body has none) |
| `timestamp` | The time of the response |
| `txnid` | The fiu-core's `txnid`, from the request body |
| `correlationId` | The `Correlation-Id` header value |
| `status` | `User Found` if at least one AA found the customer; otherwise `User Not Found` |
| `customerDiscoveryResponse` | The `customerDiscoveryResponse` entries of every AA answer whose `status` is `User Found`, merged into one list. An empty list when no AA found the customer. |

| Response header | Present | Value |
|---|---|---|
| `Correlation-Id` | Always | The value the fiu-core sent. |
| `IOP-Gw-Error` | Only on errors generated by the fiu-iop-gw | `true` |
| `Allow` | On `405` | `POST` |

There is no `x-jws-signature` (the entries come from several AAs, each answer checked by the
fiu-iop-gw), no `Forwarding-Hop` and no `Content-Type`.

**Errors**

Errors carry `IOP-Gw-Error: true` and the `ErrorResponse` body of section 3.9.

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | `Correlation-Id` missing or not in standard UUID format; the body is not a JSON object with `txnid`; `Http-Retries` or `Route-Retries` not a non-negative number |
| `401` | `InvalidSecurity` | The internal API token is missing or wrong (when one is configured) |
| `405` | `InvalidRequest` | Wrong HTTP method (see `Allow`) |
| `413` | `InvalidRequest` | The request body is too large |
| `503` | `InternalError` | The Central Registry participant list is not loaded yet |
| `503` | `AllRoutesUnavailable` | No AA answered successfully |

**Examples**

All values are synthetic.

Request:

```http
POST /fiu-dgw/broadcast/User/discover HTTP/1.1
Authorization: Bearer <internal API token>
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94

{
  "ver": "2.0.0",
  "timestamp": "2026-11-07T11:33:34.509Z",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
  "customer": {
    "vuaHash": "synthetic-vua-hash",
    "mobileHash": "synthetic-mobile-hash"
  }
}
```

Response — one AA (`aa-test-002`) found the customer:

```http
HTTP/1.1 200 OK
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94

{
  "ver": "2.0.0",
  "timestamp": "2026-11-07T11:33:36.112Z",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
  "status": "User Found",
  "customerDiscoveryResponse": [
    {
      "customerAddress": "customer-test-001@aa-test-002",
      "maskedMobile": "XXXXXXXXXX",
      "vuaAttestation": "<the AA's attestation>"
    }
  ]
}
```

Error — no AA answered successfully:

```http
HTTP/1.1 503 Service Unavailable
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94
IOP-Gw-Error: true

{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-07T11:33:44.509Z",
  "errorCode": "AllRoutesUnavailable",
  "errorMsg": "no AA answered the user discovery (3 asked)"
}
```

## 4. Receiving messages from the fiu-iop-gw

### 4.1 Who calls

| Caller | Callee | Connection |
|---|---|---|
| fiu-iop-gw | fiu-core | `<fiu-core base URL>/fiu-core/<api>`, as set in the gateway configuration (HTTPS or plain HTTP). Expose these endpoints only to the fiu-iop-gw. |

| Message comes from | `Initiator-Entity` |
|---|---|
| A customer's AA (Customer-AA), delivered by one of the FIU's Connected-AAs | `{"type":"AA","id":"<customer AA id>"}` |

### 4.2 How it works

For IOP calls addressed to the FIU, the fiu-iop-gw:

1. **Checks the calling AA** (its api-key and its signature on the message).
2. **Decrypts** the payload.
3. **Checks the Initiator's signature** on the payload.
4. **Calls the fiu-core** with the plaintext payload (section 4.3).
5. **Signs and encrypts the fiu-core's response** for the Initiator and returns it through the
   route.

### 4.3 APIs the fiu-core must expose

| Method | Path | Caller | Callee | Same payload as the Direct API | Called for |
|---|---|---|---|---|---|
| `POST` | `/fiu-core/Consent/Notification` | fiu-iop-gw | fiu-core | `/Consent/Notification` | Consent status notification from a customer's AA |
| `POST` | `/fiu-core/FI/Notification` | fiu-iop-gw | fiu-core | `/FI/Notification` | FI status notification from a customer's AA |

### 4.4 Request headers the fiu-core receives

| Header | Mandatory | Value |
|---|---|---|
| `Authorization` | Yes, if the gateway is configured with a token for calls to the core | `Bearer <token>`. If a token is configured, the fiu-core should reject calls without it or with a different value. |
| `Initiator-Entity` | Yes | The Initiator, as compact JSON `{"type":"…","id":"…"}`. |
| `Correlation-Id` | Yes | The flow's correlation id, copied unchanged from the IOP message (the gateway never creates one). |
| `Forwarding-Hop` | Yes | The entity id of the AA that delivered the call. |
| `x-jws-signature` | Yes, when there is a body | The Initiator's detached JWS over the body, taken from the Initiator's signed payload. It is a standard detached JWS (RFC 7515, base64url-encoded payload), **not** RFC 7797, because it is the Initiator's own signature. Already checked by the gateway; the core may store it as proof of what the Initiator sent. Checking it is optional: to check it, verify RS256 over `BASE64URL(header) + "." + BASE64URL(body)` with the other party's signing key from the Central Registry, not with an RFC 7797 verifier. |

The role api-key header of the calling AA and `Content-Type` are **not** sent to the core.

### 4.5 Request body

- The body is **exactly the same payload** the Initiator would send in the matching Direct API call
  (column "Same payload as the Direct API" in section 4.3): the exact bytes the Initiator signed.
- Example: `POST /fiu-core/FI/Notification` carries exactly the payload an AA sends in the Direct API `/FI/Notification` call to an FIU.
- **Duplicates.** The same message can arrive more than once, with the same `txnid` in the
  payload, because gateways retry and try other routes. The fiu-core **must** de-duplicate on the
  payload's `txnid`: a repeated `txnid` must not be processed again (for example, return the
  earlier response).

### 4.6 Response

- The response body is **exactly the same payload** the FIU returns in the matching Direct API call.
- Use the appropriate HTTP status. A status of 300 or above reaches the Initiator as an error.
- Respond within the gateway's configured core timeout (30 seconds by default).
- The FIU does not receive IOP heartbeats.

**Response headers**

| Header | Mandatory | Value |
|---|---|---|
| `Correlation-Id` | Yes | The value received in the request, unchanged. |
| `x-jws-signature` | No | The fiu-core's own detached JWS over the response body (RFC 7797 unencoded payload: protected header `{"alg": "RS256", "kid", "b64": false, "crit": ["b64"]}`, signed over the raw body), made with one of the FIU's registered signing keys. If it is sent and does not verify, the Initiator receives `502 InternalError`. The gateway signs the response either way. |

`Content-Type` is not required.

**errorSource.** On an error reply (status `400` or above) the fiu-iop-gw adds `errorSource`
`{"type": "FIU", "id": "<the FIU's id>"}` to the reply envelope, for errors from the fiu-core and for
its own errors as Target. The fiu-core does not set it.

**If the fiu-iop-gw cannot use the response**, the Initiator receives this error instead:

| Status | `errorCode` | When |
|---|---|---|
| `502` | `InternalError` | The fiu-core is unreachable, or its response is unreadable or larger than the gateway's limit |
| `502` | `InternalError` | The response has no `Correlation-Id`, or a different value |
| `502` | `InternalError` | The response carries an `x-jws-signature` that does not verify with the FIU's signing keys |
| `500` | `InternalError` | The gateway cannot sign or encrypt the response for the Initiator |

## 5. Key provisioning

The FIU's private **signing** keys (to sign messages and replies) and **decryption** keys (to
decrypt incoming messages) reach the fiu-iop-gw in one of two ways, chosen in the gateway
configuration separately for each key type:

- **From the fiu-core** (production): the fiu-iop-gw pulls them (section 5.1), and the fiu-core can push
  them (section 5.2).
- **Key files** mounted on the gateway: **for testing only** (section 8.1).

### 5.1 Key pull

| Caller | Callee | Connection |
|---|---|---|
| fiu-iop-gw | fiu-core | **HTTPS only.** The key base URL is set in the gateway configuration and can differ from the other core endpoints. |

| Method | Path | Caller | Callee | Returns |
|---|---|---|---|---|
| `GET` | `/fiu-core/keys/signing` | fiu-iop-gw | fiu-core | The signing key set |
| `GET` | `/fiu-core/keys/decryption` | fiu-iop-gw | fiu-core | The decryption key set |

- **Request headers:** only `Authorization: Bearer <key-fetch token>` (set in the gateway
  configuration). The fiu-core must reject requests without it.
- **When:** at start-up, then every hour by default, and every 30 seconds while the gateway has
  no keys of that type.
- **Response headers:** none are needed. The gateway reads only the status and the body.
- **Response body** (`200`):

```json
{
  "keys": [
    {
      "kid": "<kid>",
      "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
      "active": true,
      "applied": "2026-11-01T00:00:00Z",
      "expiry": null
    }
  ]
}
```

| Field | Mandatory | Value |
|---|---|---|
| `kid` | Yes | Key id, unique in the set: the kid under which the public key is published in the Central Registry |
| `privateKey` | Yes | PEM, PKCS#8 or PKCS#1, RSA of at least 2048 bits |
| `active` | Yes | `true` to allow use; `false` to keep the key listed but unused |
| `applied` | Yes | From when the key may be used: RFC 3339 timestamp, or `YYYY-MM-DD` (00:00 UTC) |
| `expiry` | No | Until when the key may be used (same formats), after `applied`; `null` or absent for no expiry |

- The set is accepted only as a whole. If any entry is invalid, or the status is not `200`, the gateway keeps its current keys.

### 5.2 Key push

| Caller | Callee | Connection |
|---|---|---|
| fiu-core | fiu-iop-gw | **HTTPS only.** The fiu-iop-gw's plain-HTTP listener, if any, refuses key push with `403`. |

| Method | Path | Caller | Callee | Use |
|---|---|---|---|---|
| `POST` | `/fiu-dgw/keys/signing` | fiu-core | fiu-iop-gw | Replace the signing key set |
| `POST` | `/fiu-dgw/keys/decryption` | fiu-core | fiu-iop-gw | Replace the decryption key set |

- The fiu-core can replace a key set at once, without waiting for the next pull.
- **Request headers:** only `Authorization: Bearer <internal API token>`, when one is configured.
- **Request body:** the same as the pull response (section 5.1).
- **Response headers:** none. Replies, success or error, are not signed.
- These endpoints exist only for a key type the gateway takes from the fiu-core (otherwise `404`).
- The next scheduled pull replaces the set again, so the fiu-core's `GET` endpoints must return the
  same set.

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | The key set is invalid (empty, duplicate or missing `kid`, a key that is not RSA of at least 2048 bits, missing or invalid `active` / `applied` / `expiry`); the current set is kept |
| `401` | `InvalidSecurity` | The internal API token is missing or wrong (when one is configured) |
| `403` | `InvalidSecurity` | Sent over plain HTTP: key push is accepted only over HTTPS |
| `404` | `InvalidURI` | The gateway does not take this key type from the fiu-core, or the path is not for the FIU |
| `405` | `InvalidRequest` | Not `POST` |
| `413` | `InvalidRequest` | The request body is too large |

**Examples**

Request: `POST /fiu-dgw/keys/signing` with a current key and the next one.

```http
POST /fiu-dgw/keys/signing
Authorization: Bearer <internal API token>

{
  "keys": [
    {
      "kid": "fiu-test-001-sig-2026-10",
      "privateKey": "-----BEGIN PRIVATE KEY-----\n<base64 key data>\n-----END PRIVATE KEY-----\n",
      "active": true,
      "applied": "2026-10-01T00:00:00Z",
      "expiry": "2026-12-01T00:00:00Z"
    },
    {
      "kid": "fiu-test-001-sig-2026-12",
      "privateKey": "-----BEGIN PRIVATE KEY-----\n<base64 key data>\n-----END PRIVATE KEY-----\n",
      "active": true,
      "applied": "2026-12-01",
      "expiry": null
    }
  ]
}
```

Success — each entry repeats the key's validity and adds `usable` (can it be used now). No key material is returned.

```http
HTTP/1.1 200 OK

{
  "keys": [
    {"kid": "fiu-test-001-sig-2026-10", "active": true, "applied": "2026-10-01T00:00:00Z", "expiry": "2026-12-01T00:00:00Z", "usable": true},
    {"kid": "fiu-test-001-sig-2026-12", "active": true, "applied": "2026-12-01T00:00:00Z", "expiry": null, "usable": false}
  ]
}
```

Error — an invalid set (the same `kid` twice). The current set is kept. (`ver` is the gateway's configured version; `txnid` is empty because a key set has none.)

```http
HTTP/1.1 400 Bad Request

{
  "ver": "1.0.0",
  "txnid": "",
  "timestamp": "2026-11-07T11:33:34.509Z",
  "errorCode": "InvalidRequest",
  "errorMsg": "key list: duplicate kid \"fiu-test-001-sig-2026-10\""
}
```

Error — missing or wrong internal API token.

```http
HTTP/1.1 401 Unauthorized

{
  "ver": "1.0.0",
  "txnid": "",
  "timestamp": "2026-11-07T11:33:34.509Z",
  "errorCode": "InvalidSecurity",
  "errorMsg": "invalid or missing internal API token"
}
```

### 5.3 How the gateway uses the keys

- A key is used only while `active` is `true`, from `applied` until `expiry`, checked at every
  use. Rotations can therefore be scheduled in advance.
- **Signing:** each signature uses one usable signing key **chosen at random**, with its `kid` in
  the signature header. Every key that can be usable must have its public key published.
- **Decryption:** every usable decryption key is tried, matched by the `kid` of the incoming
  message.
- With no usable signing key the gateway cannot send or answer messages; with no usable
  decryption key it cannot accept encrypted messages. Keep at least one key usable at all times.

### 5.4 Rotation order

| Key type | Order |
|---|---|
| Signing | 1. Publish the new public key in the Central Registry. 2. Wait for participants to pick it up (their registry refresh interval). 3. Add the new private key to the set, `applied` now or later. 4. Set `expiry` (or `active: false`) on the old key. |
| Decryption | 1. Add the new private key to the set first. 2. Publish the new public encryption key in the Central Registry. 3. Keep the old private key until participants have switched (at least their registry refresh interval). 4. Then set its `expiry` (or `active: false`). |

### 5.5 Security

- The fiu-iop-gw keeps the keys **in memory only**. They are never written to its persistent cache,
  to disk, or to any temporary storage. After a restart it pulls them again.
- **Key pull and key push work only over HTTPS.** The gateway refuses an `http://` key URL at
  start-up, and its plain-HTTP listener refuses key push.
- The fiu-core must check the key-fetch token, serve the key endpoints only to the fiu-iop-gw, and never
  log key material.

## 6. Linked AAs (linkedAAs)

The fiu-iop-gw uses as routes only the AAs the FIU is linked to. The list reaches the gateway in one
of two ways, chosen in the gateway configuration:

- **From the fiu-core** (production): the fiu-iop-gw pulls the list, and the fiu-core can push it. Both
  may use HTTP or HTTPS.
- **In the gateway configuration:** **for testing only** (section 8.1).

### 6.1 Pull

| Method | Path | Caller | Callee | Returns |
|---|---|---|---|---|
| `GET` | `/fiu-core/linkedAAs` | fiu-iop-gw | fiu-core | The list of linked AAs |

- **Request headers:** only `Authorization: Bearer <token>` (set in the gateway configuration).
- **When:** at start-up, then every hour by default, and every 30 seconds while the gateway has
  no list. The gateway keeps the list in memory and in its persistent cache, so a restart can
  use the last list even if the fiu-core is down.
- **Response** (`200`, no response headers needed):

```json
{
  "linkedAAs": [
    "aa-test-002",
    "aa-test-003"
  ]
}
```

- The list must not be empty and must not repeat an id. Otherwise the gateway keeps its current list.

### 6.2 Push

| Method | Path | Caller | Callee | Use |
|---|---|---|---|---|
| `POST` | `/fiu-dgw/linkedAAs` | fiu-core | fiu-iop-gw | Replace the list |

- **Request headers:** only `Authorization: Bearer <internal API token>`, when one is configured.
- **Request body:** the same as the pull response.
- **Response:** `200` with the new list, no response headers. Errors: `400` (empty list or
  repeated id; the current list is kept), `401` (token), `405` (not `POST`), `413` (too large).
- The endpoint exists only when the gateway takes the list from the fiu-core (otherwise `404`).

```http
POST /fiu-dgw/linkedAAs
Authorization: Bearer <internal API token>

{
  "linkedAAs": [
    "aa-test-002",
    "aa-test-003"
  ]
}
```

## 7. Security notes

- The fiu-iop-gw's internal APIs always run over HTTPS. A plain-HTTP listener can be added for the
  message APIs; use it only on a trusted network segment, since messages then travel
  unencrypted. Key push is never accepted there.
- If the fiu-iop-gw is configured with an internal API token, the fiu-core must send it on every call
  and keep it secret. Without a token, anyone who can reach the internal APIs can send messages
  as the FIU: restrict network access to them.
- Expose the `/fiu-core/*` endpoints only to the fiu-iop-gw, and configure a token for calls to the core
  so the fiu-core can check `Authorization` on every call.
- Key endpoints: HTTPS only, check the key-fetch token, serve them only to the fiu-iop-gw, never log
  key material.

## 8. Configuring the fiu-iop-gw before start-up

### 8.1 Production and testing

Wherever the fiu-iop-gw can take something either from an API or from its configuration, **use the
API in production**. The configuration alternative is **for testing only**.

| What | Production: from the API | Testing only: from the configuration |
|---|---|---|
| Participants, their keys and interop flags | The Central Registry | A list of entities with public key files |
| Which AAs can reach a Target (AIG) | The Central Registry's AIG APIs | A graph in the configuration |
| Linked AAs | The fiu-core (section 6) | A list in the configuration |
| The FIU's signing and decryption keys | The fiu-core (section 5) | Key files mounted on the gateway |
| Public keys of the api-key token issuer | The issuer's key URL (JWKS) | Public key files |
| The FIU's IopToken (api-key on `/iop` calls) and access token | The Sahamati token service | A fixed api-key |

### 8.2 Production configuration

This is a production configuration for the fiu-iop-gw: everything comes from the APIs. Replace the
ids, URLs and file paths with the FIU's own; the Central Registry, token service and issuer URLs
are provided by Sahamati. All values shown are illustrative.

```yaml
mode: FIU
logging:
  level: INFO
  audit: true                          # IOPGW_AUDIT record per request and response (no bodies)
  statsIntervalSeconds: 60             # IOPGW_STATS record with "|"-separated counts

# Public listener for /iop calls from other AAs (HTTPS)
listenAddr: ":8443"
tls:
  certFile: /etc/iopgw/tls/server.crt
  keyFile: /etc/iopgw/tls/server.key

self:
  id: fiu-test-001                       # the FIU's entity id in the Central Registry
  signingKey:                          # from the fiu-core (section 5)
    source: api
    token: "${IOPGW_KEYS_TOKEN}"
  decryptionKeys:                      # from the fiu-core (section 5)
    source: api
    token: "${IOPGW_KEYS_TOKEN}"

# Access token and IopToken from the Sahamati token service (section 8.5)
tokenService:
  baseUrl: https://iam.example.invalid/iam/v1
  path: /entity/token/generate        # access token
  iopPath: /entity/iopToken/generate  # IopToken
  credentialsFile: /etc/iopgw/secrets/credentials.json

# The fiu-core
core:
  baseUrl: http://fiu-core.internal:8080        # message calls (http or https)
  keysBaseUrl: https://fiu-core.internal:8443   # key pull (https only)
  pathPrefix: /fiu-core
  token: "${IOPGW_CORE_TOKEN}"                   # sent to the fiu-core on every call
  timeoutSeconds: 30

# Checking the api-key of calling AAs
apiKey:
  mode: jwt
  senderIdClaim: azp
  issuer: https://token.example.invalid/auth/realms/sahamati
  issuerKeysUrl: https://token.example.invalid/auth/realms/sahamati/protocol/openid-connect/certs

jws:
  algorithm: RS256

# Participants, keys and interop flags: from the Central Registry
cr:
  source: api
  baseUrl: https://cr.example.invalid
  entityInfoPath: /v2/entityInfo

# AA Interoperability Graph: from the Central Registry
aigSource: api
aigBaseUrl: https://cr.example.invalid
aaAigPath: /v1/aig/aa                   # an AA's peer-AAs

# Internal APIs (/fiu-dgw) for the fiu-core
gwApi:
  listenAddr: "10.0.0.10:9443"         # internal interface only; always HTTPS
  tls:
    certFile: /etc/iopgw/tls/internal.crt
    keyFile: /etc/iopgw/tls/internal.key
  token: "${IOPGW_GWAPI_TOKEN}"      # the fiu-core sends it as Authorization: Bearer
  maxRetries: 3                        # cap on Http-Retries
  maxRouteRetries: 2                   # cap on Route-Retries
  broadcastTimeoutSeconds: 10          # how long /fiu-dgw/broadcast/User/discover waits for the AAs (section 3.13)

# Linked AAs: from the fiu-core (section 6)
linkedAAs:
  source: api
  token: "${IOPGW_LINKED_TOKEN}"

hopPreference:
  connectedAAs: [aa-test-002]          # tried first, in this order

forwarding:
  timeoutSeconds: 30

cache:
  dir: /var/lib/iopgw/cache
```

### 8.3 Local testing configuration

**For local testing only.** Here every item that production takes from an API is set in the
configuration file instead (section 8.1):

- **Participants and their public keys** (`cr.source: config`, `entities`) instead of the Central
  Registry.
- **The AIG** (`aigSource: config`, `aig`) instead of the AIG API.
- **Linked AAs** (`linkedAAs.source: config`, `linkedAAs.aas`) instead of `GET /fiu-core/linkedAAs`.
- **The FIU's signing and decryption keys** (`source: file`) instead of the fiu-core's key endpoints.
- **Api-keys** (`apiKey.mode: static`, `self.outboundApiKey`) instead of the token service and its
  issuer.
- **Routes preferred** (`hopPreference`), as in production.

Key files, peer public keys and TLS files are read from `./local/`. The api-keys and the internal
API token are environment variables: `IOPGW_OUTBOUND_API_KEY`, `IOPGW_GWAPI_TOKEN` and one
`IOPGW_TEST_..._API_KEY` per calling participant. All ids, addresses and values are illustrative.

```yaml
# LOCAL TESTING ONLY: everything below comes from this file, not from the APIs.
mode: FIU
logging:
  level: DEBUG
  audit: true
  statsIntervalSeconds: 60

listenAddr: "127.0.0.1:8443"           # /iop listener (HTTPS)
tls:
  certFile: ./local/tls/server.crt
  keyFile: ./local/tls/server.key

self:
  id: fiu-test-001
  signingKey:                          # key file instead of the fiu-core's key API
    source: file
    kid: fiu-test-001-sig
    file: ./local/keys/fiu-test-001-sig.pem
    active: true
    applied: "2026-11-01"
  decryptionKeys:                      # key files instead of the fiu-core's key API
    source: file
    keys:
      - { kid: fiu-test-001-enc, file: ./local/keys/fiu-test-001-enc.pem, active: true, applied: "2026-11-01" }
  outboundApiKey: "${IOPGW_OUTBOUND_API_KEY}"   # fixed api-key towards other AAs (no token service)

core:
  baseUrl: http://127.0.0.1:8080       # the fiu-core running locally
  pathPrefix: /fiu-core
  timeoutSeconds: 30

apiKey:                                # fixed api-keys instead of the token issuer
  mode: static
  static:
    "${IOPGW_TEST_AA_002_API_KEY}": aa-test-002   # api-key the Connected-AA sends to this gateway

jws:
  algorithm: RS256

cr:
  source: config                       # participants from this file, not the Central Registry
entities:
  - id: aa-test-002                       # Connected-AA: the route
    type: AA
    baseUrl: https://127.0.0.1:9002
    signingPublicKeys:
      - { kid: aa-test-002-sig, file: ./local/peers/aa-test-002-sig.pub.pem }
    encryptionPublicKeys:
      - { kid: aa-test-002-enc, file: ./local/peers/aa-test-002-enc.pub.pem }
  - id: aa-test-003                       # Customer-AA: the Target (reached through aa-test-002)
    type: AA
    baseUrl: https://127.0.0.1:9003
    signingPublicKeys:
      - { kid: aa-test-003-sig, file: ./local/peers/aa-test-003-sig.pub.pem }
    encryptionPublicKeys:
      - { kid: aa-test-003-enc, file: ./local/peers/aa-test-003-enc.pub.pem }

aigSource: config                      # AIG graph from this file, not the AIG API
aig:
  aa:                                  # per AA: the AAs it is linked to (both directions count)
    - aa-test-002: [aa-test-003]

gwApi:                                 # internal APIs (/fiu-dgw) for the fiu-core
  listenAddr: "127.0.0.1:8444"         # always HTTPS
  httpListenAddr: "127.0.0.1:8081"     # plain HTTP for local calls (no key push)
  tls:
    certFile: ./local/tls/internal.crt
    keyFile: ./local/tls/internal.key
  token: "${IOPGW_GWAPI_TOKEN}"
  maxRetries: 3
  maxRouteRetries: 2
  broadcastTimeoutSeconds: 10

linkedAAs:
  source: config                       # list from this file, not the fiu-core's API
  aas: [aa-test-002]

hopPreference:
  connectedAAs: [aa-test-002]

forwarding:
  timeoutSeconds: 30

cache:
  dir: ./local/cache
```

### 8.4 What the FIU provides (production)

| Item | What it is | Who uses it |
|---|---|---|
| `IOPGW_GWAPI_TOKEN` | Internal API token | The fiu-core sends it on every call to the internal APIs |
| `IOPGW_CORE_TOKEN` | Token for calls to the fiu-core | The fiu-iop-gw sends it on every `/fiu-core/*` call; the fiu-core checks it |
| `IOPGW_KEYS_TOKEN` | Key-fetch token | The fiu-iop-gw sends it on key pull; the fiu-core checks it |
| `IOPGW_LINKED_TOKEN` | Linked-AAs token | The fiu-iop-gw sends it on `GET /fiu-core/linkedAAs`; the fiu-core checks it |
| TLS certificate and key (public) | For the `/iop` listener | Other AAs calling the fiu-iop-gw |
| TLS certificate and key (internal) | For the internal APIs | The fiu-core |
| Credentials file | The FIU's entity credentials for the Sahamati token service | The fiu-iop-gw, to get its access token and IopToken |

- The four tokens are given to the fiu-iop-gw as environment variables; it does not start if one is
  empty. Keep them secret, and give each the same value on the fiu-core's side.
- `hopPreference` lists the FIU's preferred routes, tried first in that order (section 3.11).
- `gwApi.maxRetries` and `gwApi.maxRouteRetries` cap `Http-Retries` and `Route-Retries`.
- `gwApi.broadcastTimeoutSeconds` is how long `POST /fiu-dgw/broadcast/User/discover` waits for
  the AAs' answers (section 3.13). Default `10`; it must not be negative.
- `logging.audit` writes one JSON log record tagged `IOPGW_AUDIT` per request and per response
  (headers, lengths, ids, status and error code; never the body), and
  `logging.statsIntervalSeconds` one record tagged `IOPGW_STATS` per interval with
  `|`-separated counts. Both can be fetched from the gateway's logs by their tag.

### 8.5 IopToken

The fiu-iop-gw holds two tokens from the Sahamati token service, both got with the FIU's credentials
file (section 8.4):

| Token | Got from | Used by the fiu-iop-gw for |
|---|---|---|
| Access token | `POST <tokenService.baseUrl><tokenService.path>`, default `/entity/token/generate` | Direct API calls (the user discovery broadcast, section 3.13); the bearer token for the Central Registry and the AIG |
| IopToken | `POST <tokenService.baseUrl><tokenService.iopPath>`, default `/entity/iopToken/generate` | The role api-key `client_api_key` on every `/iop` call the fiu-iop-gw sends |

- With `tokenService.baseUrl` set to, for example, `https://token-generation-url/iam/v1`, the
  IopToken comes from `https://token-generation-url/iam/v1/entity/iopToken/generate`.
- Each token is cached, kept in the persistent cache, and refreshed on its own before it expires. If
  the IopToken is not available, `/iop` calls fail with `503 InternalError` ("IopToken
  unavailable").
- **Received tokens.** The fiu-iop-gw checks that the token on a received `/iop` call
  (`x-conn_aa_api_key`, from the Connected-AA) is a hop token (an IopToken). **Verification
  procedure:** *To be published.* The fiu-core needs no change for this: the token is not passed to
  it (section 4.4).
