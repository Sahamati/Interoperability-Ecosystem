# IOP Gateway — Integration Guide for the aa-core

|  |  |
|---|---|
| **Audience** | AA core application teams (AA ecosystem participants) |
| **Version** | Draft 2.1, 2026-11-09 |
| **Covers** | How the aa-core sends and receives messages through the aa-iop-gw, when to call it, how the aa-core gives it keys and its list of linked AAs, and how the aa-iop-gw is configured |

All identifiers in examples are illustrative.

## Changes needed in the aa-core

To work with the aa-iop-gw, the aa-core needs the changes below. "Yes" means needed in production.

| # | Change in the aa-core | Needed | Section |
|---|---|---|---|
| 1 | Call the aa-iop-gw's internal APIs (`/aa-dgw/*` and `/aa-sgw/*`) instead of the Direct APIs when the FIU or FIP is not directly connected to the AA. Keep using the Direct APIs for directly connected participants. | Yes | 2, 3.3 |
| 2 | Send `Target-Entity` and `Correlation-Id` on every call, and `Authorization` with the internal API token. Optionally send `Preferred-Hop`, `Http-Retries`, `Route-Retries` and the aa-core's own `x-jws-signature`. | Yes | 3.4 |
| 3 | Create a non-empty correlation id for each new flow, and keep it on every message of that flow. | Yes | 2 |
| 4 | Handle the responses: the Target's payload and signature; Target errors (with a payload, or a status with an empty body); errors from the aa-iop-gw (`IOP-Gw-Error: true`, for example `503 AllRoutesUnavailable`). | Yes | 3.6 – 3.10 |
| 5 | Expose the `/aa-core/*` APIs to receive messages from participants that are not directly connected. The payloads are those of the Direct APIs. | Yes | 4.3 – 4.5 |
| 6 | Return `Correlation-Id` unchanged on every `/aa-core/*` response. | Yes | 4.6 |
| 7 | Check `Authorization` on every `/aa-core/*` call (the token the aa-iop-gw sends to the aa-core). | Recommended | 4.4, 7 |
| 8 | De-duplicate incoming messages on `txnid`: retries can deliver a message twice, and the aa-core must not process it twice. | Yes | 4.5 |
| 9 | Serve the key endpoints `GET /aa-core/keys/signing` and `GET /aa-core/keys/decryption` over HTTPS, checking the key-fetch token. | Yes | 5.1 |
| 10 | Push new key sets to `/aa-dgw/keys/*` or `/aa-sgw/keys/*` when keys rotate. | Recommended | 5.2 |
| 11 | Serve `GET /aa-core/linkedAAs` with the AAs the AA is linked to. | Yes | 6.1 |
| 12 | Push the list to `/aa-dgw/linkedAAs` or `/aa-sgw/linkedAAs` when it changes. | Recommended | 6.2 |
| 13 | Set the aa-iop-gw's configuration and provide its tokens, certificates and credentials before starting it. | Yes | 8 |

## 1. Terminology

| Term | Meaning |
|---|---|
| fiu-core | The FIU's own application as it is today: the system that sends consent and FI requests and receives notifications. |
| aa-core | The AA's own application as it is today. |
| fip-core | The FIP's own application as it is today. |
| fiu-iop-gw, aa-iop-gw, fip-iop-gw | The IOP Gateway, run by the FIU, AA or FIP in front of its core. It handles the IOP security (signatures, encryption) and routing. |
| Internal APIs | The APIs the aa-iop-gw offers to the aa-core: `/aa-dgw/*` and `/aa-sgw/*`. |
| Target | The participant that finally receives a message. |
| Initiator | The participant that created a message (the first sender of a flow). |
| Correlation-Id (`correlationId`) | The id of one flow, in **standard UUID format** (RFC 4122, for example `9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94`). The Initiator creates it; it stays the same on every message of the flow and is never created by the IOP Gateway. The aa-core sends it in the `Correlation-Id` header; the IOP message carries it as `correlationId`. |
| Route (hop) | The AA that carries a message to a Target that is not directly connected. |
| Connected-AA | An AA directly connected to an FIU. It carries messages between the FIU and other AAs. |
| Inter-AA | An AA directly connected to a FIP. It carries messages between the FIP and other AAs. |
| Customer-AA / Origin-AA | The AA that holds the customer's consent (Customer-AA, towards FIUs) / that sends requests to a FIP (Origin-AA). |
| linkedAAs | The AAs the AA is linked to: the only AAs the aa-iop-gw uses as routes (section 6). |
| AIG | AA Interoperability Graph, published by the Central Registry: which AAs can reach which participant. |
| Direct APIs | The existing ReBIT APIs as of today (for example `/Consent`, `/FI/request`, `/FI/Notification`), which participants call on each other when they are directly connected. The IOP Gateway carries exactly the same payloads. |
| ReBIT specifications | The AA ecosystem API specifications that define the Direct APIs. |

## 2. When to call the aa-iop-gw

| Situation | Does the aa-core call the aa-iop-gw? |
|---|---|
| The FIU or FIP is **directly connected** to the AA | **No.** The aa-core calls that FIU's or FIP's Direct APIs. |
| An FIU is **not directly connected** to the AA | **Yes.** The aa-core calls the aa-iop-gw (`/aa-dgw/*`). The aa-iop-gw sends the message through the FIU's Connected-AA. |
| A FIP is **not directly connected** to the AA | **Yes.** The aa-core calls the aa-iop-gw (`/aa-sgw/*`). The aa-iop-gw sends the message through the FIP's Inter-AA. |
| An FIU or FIP that is not directly connected sends a request or notification | **No call needed.** The aa-iop-gw receives it and calls the aa-core (`/aa-core/*`), see section 4. |

**Every message must carry a correlation id.**

- All AA ecosystem participants must send a non-empty `correlationId` in every IOP message.
- The Initiator creates it for the flow. It stays the same on every message of that flow.
- It must be in standard UUID format (section 1).
- The aa-iop-gw never creates one. It refuses a message without one, or with one that is not a UUID, with `400 InvalidRequest`.
- When the aa-core sends through the aa-iop-gw, the mandatory `Correlation-Id` header (section 3.4)
  provides it.

## 3. Sending messages through the aa-iop-gw

### 3.1 Who calls

| Caller | Callee | Connection |
|---|---|---|
| aa-core | aa-iop-gw | The aa-iop-gw's internal APIs (`/aa-dgw/*` and `/aa-sgw/*`). HTTPS always; plain HTTP as well if the aa-iop-gw is configured with an HTTP listener. |

### 3.2 How it works

**Sending the request.** For each call, the aa-iop-gw:

1. **Signs the payload, if the aa-core has not already signed it.** If the aa-core sends its own
   `x-jws-signature`, the aa-iop-gw checks it and uses it. Otherwise the aa-iop-gw signs the payload
   with the AA's signing key.
2. **Encrypts** the signed payload for the Target.
3. **Builds the IOP request** around the encrypted payload (`ver`, `timestamp`, `txnid`,
   `correlationId`, `Target`, `iopPayload`) and **signs it**. The request carries only `Target`;
   the route sets `Initiator` when it forwards the request. Its `txnid` is **not** the
   payload's: it identifies the transaction between the aa-iop-gw and the route, a new one for each
   route.
4. **Chooses a route** (section 3.11) and sends the IOP request to that AA.

**Receiving the response.** When the answer comes back, the aa-iop-gw:

1. **Checks the signature of the Connected-AA / Inter-AA** on the answer.
2. **Decrypts** the Target's encrypted reply.
3. **Checks the Target's signature** on the reply.
4. **Returns the Target's reply** to the aa-core: the Target's payload, the Target's status and
   the Target's signature (`x-jws-signature`).

A Heartbeat has no encrypted payload: sending steps 1 and 2 are skipped, and the IOP request
carries only the `Target`, without `iopPayload`. `/iop/Heartbeat` is only for a Target that is
not directly connected: a directly connected participant (for example the route itself) is
checked with the Direct API `GET /Heartbeat`.

### 3.3 APIs

| Method | Path | Caller | Callee | `Target-Entity` type | Same payload as the Direct API | Use |
|---|---|---|---|---|---|---|
| `POST` | `/aa-dgw/FI/Notification` | aa-core | aa-iop-gw | `FIU` | `/FI/Notification` | FI notification to an FIU (as Customer-AA) |
| `POST` | `/aa-dgw/Consent/Notification` | aa-core | aa-iop-gw | `FIU` | `/Consent/Notification` | Consent notification to an FIU (as Customer-AA) |
| `POST` | `/aa-dgw/User/discover` | aa-core | aa-iop-gw | `FIU` | — | **Not implemented yet:** always answered `501 NotImplemented` |
| `POST` | `/aa-sgw/Accounts/discover` | aa-core | aa-iop-gw | `FIP` | `/Accounts/discover` | Account discovery at a FIP (as Origin-AA) |
| `POST` | `/aa-sgw/Accounts/link` | aa-core | aa-iop-gw | `FIP` | `/Accounts/link` | Account linking |
| `POST` | `/aa-sgw/Accounts/link/verify` | aa-core | aa-iop-gw | `FIP` | `/Accounts/link/verify` | Account link verification |
| `POST` | `/aa-sgw/Accounts/delink` | aa-core | aa-iop-gw | `FIP` | `/Accounts/delink` | Account delinking |
| `POST` | `/aa-sgw/Consent` | aa-core | aa-iop-gw | `FIP` | `/Consent` | Consent artefact to the FIP |
| `POST` | `/aa-sgw/FI/request` | aa-core | aa-iop-gw | `FIP` | `/FI/request` | FI data request |
| `POST` | `/aa-sgw/FI/fetch` | aa-core | aa-iop-gw | `FIP` | `/FI/fetch` | FI data fetch |
| `POST` | `/aa-sgw/Consent/Notification` | aa-core | aa-iop-gw | `FIP` | `/Consent/Notification` | Consent notification to the FIP |
| `GET` | `/aa-sgw/Heartbeat` | aa-core | aa-iop-gw | `FIP` | `/Heartbeat` | Heartbeat towards the FIP (no body) |

`/aa-dgw/*` sends to an **FIU** (the aa-core acts as Customer-AA); `/aa-sgw/*` sends to a **FIP** (the aa-core acts as Origin-AA). The account APIs use the plural `/aa-sgw/Accounts/...`.

### 3.4 Request headers

| Header | Mandatory | Value |
|---|---|---|
| `Authorization` | Yes, if the aa-iop-gw is configured with an internal API token | `Bearer <internal API token>`. Without it (or with a wrong one) the call is refused with `401`. |
| `Target-Entity` | Yes | The final recipient, as compact JSON: `{"type":"<AA\|FIU\|FIP>","id":"<entity id>"}`. The type must match the API (section 3.3). The Target must be marked interop ready in the Central Registry. |
| `Correlation-Id` | Yes | The flow's correlation id, in standard UUID format (see section 1). It is carried in the IOP message and returned on every response. A missing value, or one that is not a UUID, is refused with `400 InvalidRequest`. |
| `x-jws-signature` | No | The aa-core's own detached JWS (RS256 or PS256, base64url-encoded payload) over the request body, made with one of the AA's registered signing keys. If omitted, the aa-iop-gw signs. |
| `Preferred-Hop` | No | The entity id of the AA the core prefers as the route. Used first only if it is an eligible route (section 3.11); otherwise ignored. |
| `Http-Retries` | No | How many times to retry the same route when it does not answer (no connection, or a timeout). An error answer from the route, `502`/`503`/`504` included, is not retried on that route. **`0` means: do not retry.** Default `2`; capped by the gateway (by default at `3`). Waits 200 ms, doubling up to 2 s, between retries. |
| `Route-Retries` | No | How many **other** routes to try after the first route fails (section 3.7). **`0` means: do not try another route.** Default `2`; capped by the gateway (by default at `2`). |

No other header is needed. `Content-Type` is not required.

### 3.5 Request body

- The request body is **exactly the same payload** the AA would send to a directly connected
  participant in the matching Direct API call (column "Same payload as the Direct API" in section 3.3).
- Example: `POST /aa-sgw/Accounts/discover` carries exactly the payload the AA would send in the Direct API `/Accounts/discover` call to a FIP it is directly connected to.
- The body must contain `txnid`; `ver` is taken from it.
- A Heartbeat (`GET`) has no body.
- Retries and further routes resend the **same payload, with the same `txnid` in the payload**.
  A duplicate delivery is still possible, so every Target **must** de-duplicate on the payload's
  `txnid` (section 4.5).

### 3.6 Response body

What the core receives depends on what comes back from the Connected-AA / Inter-AA. Section 3.7 shows how each answer is handled.

| Outcome | Status | Body |
|---|---|---|
| The Target answered (success or error) | The Target's status | **Exactly the same payload** the Target returns in the matching Direct API call, as the Target signed it (decrypted by the gateway). |
| The Target answered an error without a payload | The Target's status (passed on by the Connected-AA / Inter-AA) | Empty. |
| Every route failed | `503` | An `ErrorResponse` with `errorCode` `AllRoutesUnavailable` (section 3.9). |
| The aa-iop-gw refused the call | 400, 401, 404, 405, 413, 500, 501, 502, 503 or 504 | An `ErrorResponse` (section 3.9). |

### 3.7 How the gateway handles an error from the Connected-AA / Inter-AA

This applies only when the Connected-AA / Inter-AA answers with an error (status `4xx` or `5xx`). Success
answers (`2xx`, `3xx`) are opened and passed on as in section 3.6.

| Payload from the Connected-AA / Inter-AA | `iopError` in the payload | `errorCode` in the payload | What the aa-iop-gw does | Status to the core | Body to the core | `IOP-Gw-Error` |
|---|---|---|---|---|---|---|
| Yes | Yes | Any | Answers the core | The Connected-AA / Inter-AA's status | The Target's error payload (decrypted), with the Target's signature | Not set |
| Yes | No | `IopUpstreamError` | Answers the core | The Connected-AA / Inter-AA's status | Empty | Not set |
| Yes | No | Anything else | Tries another route (see below); if every route fails, answers the core | `503` | Generated: `errorCode` `AllRoutesUnavailable` | `true` |
| No | No | None | Tries another route (see below); if every route fails, answers the core | `503` | Generated: `errorCode` `AllRoutesUnavailable` | `true` |

- **Another route** is tried within the limits of section 3.11: up to `Route-Retries`
  other routes. The same route is first retried (up to `Http-Retries` times) only when it
  did not answer at all; an error answer, `502`, `503` or `504` included, moves to the next
  route at once.
- When the Connected-AA / Inter-AA does not answer at all (no connection, or a timeout), it is handled like the
  last row.
- `IopUpstreamError` without `iopError` means the Connected-AA / Inter-AA reached the Target, but the Target
  answered an error without a payload. Another route would reach the same Target, so the
  gateway does not try one.

### 3.8 Response headers

| Header | Present | Value |
|---|---|---|
| `x-jws-signature` | When the Target answered with a payload | **The Target's** detached JWS over the body. Never present on an empty body or on an error generated by the gateway. |
| `Correlation-Id` | Always (when the request carried one) | The value the core sent. |
| `Forwarding-Hop` | When the answer came through a Connected-AA / Inter-AA | The entity id of the Connected-AA / Inter-AA that carried the call. Not present when every route failed. |
| `IOP-Gw-Error` | Only on errors generated by the aa-iop-gw | `true`. The body is then the gateway's `ErrorResponse` (section 3.9). Without this header, an error came from the Target, through the Connected-AA / Inter-AA. |
| `Allow` | On `405` | The method the API accepts. |

No `Content-Type` is sent.

### 3.9 Error codes

Errors generated by the aa-iop-gw itself carry `IOP-Gw-Error: true` and have this body (not signed):

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
| `404` | `InvalidURI` | The API is not available for the AA |
| `405` | `InvalidRequest` | Wrong HTTP method (see `Allow`) |
| `413` | `InvalidRequest` | The request body is too large |
| `500` | `InternalError` | The gateway cannot sign the payload or encrypt it for the Target (for example, no encryption key published for the Target) |
| `501` | `NotImplemented` | `User/discover` (not implemented yet) |
| `502` | `BadGateway` | The AIG is not available; the answer of the Connected-AA / Inter-AA has an invalid signature, cannot be decrypted, or is malformed |
| `502` | `SignatureDoesNotMatch` | The Target's signature on the reply does not verify |
| `503` | `AllRoutesUnavailable` | Every route failed: no Connected-AA / Inter-AA answered, or each answered an error that is not from the Target (section 3.7) |
| `503` | `InternalError` | The gateway is not ready yet: registry, keys or linkedAAs not loaded, or access token unavailable |
| `504` | `GatewayTimeout` | The core's request was cancelled while the gateway waited to retry |

### 3.10 Error examples

**1. The aa-iop-gw rejects the call** — for example, `POST /aa-dgw/FI/Notification` with a Target (`fiu-test-001`) that is
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

**2. The Connected-AA rejects the call** — for example, the Connected-AA (`aa-test-003`) answers `400`
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

**3. The Target returns an error without a body** — for example, `POST /aa-sgw/FI/request` and the Target
(`fip-test-001`) answers `500` with no payload. The Inter-AA (`aa-test-004`) answers `IopUpstreamError`
without `iopError`. The core receives the status with an **empty body**. This answer is final:
the gateway does not retry it or try another route.

```http
HTTP/1.1 500 Internal Server Error
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94
Forwarding-Hop: aa-test-004
```

**4. The Target returns an error** — for example, `POST /aa-sgw/FI/request` and the Target (`fip-test-001`) answers `400`
with an error payload. The core receives **the Target's own error payload**, exactly as the
Target signed it, with the Target's status and signature. Its content is defined by the Target.

```http
HTTP/1.1 400 Bad Request
x-jws-signature: <the Target's detached JWS over the body>
Correlation-Id: 9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94
Forwarding-Hop: aa-test-004

{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-07T11:33:34.509Z",
  "errorCode": "InvalidRequest",
  "errorMsg": "FI request is invalid for the consent"
}
```

### 3.11 How the route is chosen

The aa-core does not need to choose a route. The aa-iop-gw does it as follows.

**Which AAs can be a route** — an AA is eligible only if **all** of these hold:

- It is in the AA's **linkedAAs** (section 6).
- The **AIG** says it can reach the Target. The aa-iop-gw uses the FIU graph (`GET /v1/aig/fiu`: an FIU's Connected-AAs) and the FIP graph (`GET /v1/aig/fip`: a FIP's Inter-AAs). It loads the AIG from the
  Central Registry at start-up and every 12 hours, with its own access token, and keeps a copy.
- It is marked interop ready in the Central Registry.
- It is not the Target itself, Heartbeat included.

The **Target** must also be marked interop ready in the Central Registry; otherwise the call is
refused with `400 InvalidRequest` before any route is chosen.

**In which order the routes are tried:**

1. The core's `Preferred-Hop`, if it is eligible.
2. The gateway's **hop-preference policy** (`hopPreference.connectedAAs` (FIU Targets) or `hopPreference.interAAs` (FIP Targets)), in the configured order.
3. The other eligible AAs, in **random order** (this spreads the load across them).

**How many routes and retries:** the first route, plus up to `Route-Retries` other routes.

| Connected-AA / Inter-AA's answer | Retry the same route | Try the next route |
|---|---|---|
| No answer (no connection, or a timeout) | Yes, up to `Http-Retries` | Yes, up to `Route-Retries` |
| Any error not from the Target, `502`/`503`/`504` included (for example `400 InvalidRoute`\*) | No | Yes, up to `Route-Retries` |
| An error with `iopError`, or with `IopUpstreamError` | No | No (the answer goes to the core, section 3.7) |
| Success | No | No |

"Not from the Target" means: no `iopError` in the payload, and `errorCode` is not
`IopUpstreamError` (section 3.7).

\* `InvalidRoute` is the code the IOP Gateway uses when, as a hop, it cannot route to the Target. **It is not yet confirmed as a ReBIT IOP error code.**

### 3.12 Retries

The aa-iop-gw retries a call from the aa-core as follows.

| | |
|---|---|
| Sends to | A Connected-AA / Inter-AA (`/iop`), chosen as in section 3.11 |
| Retries the same route | `Http-Retries` header: default 2, capped by the gateway (by default at 3) |
| … when | The Connected-AA / Inter-AA does not answer (no connection, or a timeout). An error answer from the Connected-AA / Inter-AA, `502`/`503`/`504` included, is never retried on the same route |
| Tries another route | `Route-Retries` header: default 2, capped by the gateway (by default at 2). After the retries when the Connected-AA / Inter-AA does not answer; at once on any error from the Connected-AA / Inter-AA that is not from the Target (for example `503` or `400 InvalidRoute`) |
| Never retries | Success; an answer with `iopError` (the Target's error); `IopUpstreamError` without `iopError` |
| Wait between attempts | 200 ms, doubling, at most 2 s |
| Most sends per call (defaults) | (1 + 2 routes) × (1 + 2 retries) = 9 |
| When all attempts fail | The aa-core gets `503 AllRoutesUnavailable` with `IOP-Gw-Error: true` |

**Received in response to an `/iop/*` API from the Connected-AA / Inter-AA**

| StatusCode | ErrorCode | IopError | Inference | RetryHttp | RetryRoute |
|---|---|---|---|---|---|
| — (no response) | — | — | The Connected-AA / Inter-AA could not be reached, or did not answer in time | Yes, up to `Http-Retries` | Yes, after the retries |
| `2xx`, `3xx` | — | — | Success: the Target's answer. The aa-core gets the Target's payload, status and signature | No | No |
| Any `4xx`/`5xx` | Any | Present | The Target answered with an error. The aa-core gets the Target's error payload, status and signature | No | No |
| `4xx` | `IopUpstreamError` | Absent | The Target answered `4xx` without a payload. The aa-core gets the same status with an empty body | No | No |
| `5xx` | `IopUpstreamError` | Absent | The Target failed (`5xx` without a payload), or the Connected-AA / Inter-AA could not reach it (`502`) or got no answer in time (`504`). Every route leads to the same Target. The aa-core gets the same status with an empty body | No | No |
| `502`, `503`, `504` | Other than `IopUpstreamError`, or none | Absent | The Connected-AA / Inter-AA itself is unavailable | No | Yes, at once |
| `400` | `InvalidRoute`\* | Absent | The Connected-AA / Inter-AA cannot route to the Target | No | Yes, at once |
| Any other `4xx`/`5xx` | Other than `IopUpstreamError`, or none | Absent | The Connected-AA / Inter-AA refused the call, or failed | No | Yes, at once |

- **StatusCode:** the HTTP status code of the Connected-AA / Inter-AA's response.
- **ErrorCode:** the `errorCode` set by the Connected-AA / Inter-AA.
- **IopError:** the `iopError` field set by the Target and forwarded by the Connected-AA / Inter-AA.
- **RetryHttp:** whether the same route is retried. **RetryRoute:** whether a different route is tried.
- When every route has failed, the aa-core gets `503 AllRoutesUnavailable` with `IOP-Gw-Error: true`.

\* See the note in section 3.11.

1. **Errors from beyond the Connected-AA / Inter-AA are final.** `IopUpstreamError` without `iopError` means the
   Target could not be reached, or answered an error without a payload. Every route leads to the
   same Target, so the aa-iop-gw neither retries nor tries another route.
2. **Every resend carries the same payload and `correlationId`.** The payload's `txnid` stays the
   same; the IOP request's own `txnid` is the same on retries of one route and new for each
   route. Every Target, including the aa-core, **must** de-duplicate on the payload's `txnid`.
3. **Fit within the aa-core's own timeout.** One call can take up to
   (1 + `Route-Retries`) × (1 + `Http-Retries`) × (forwarding timeout + 2 s): about 4.8 minutes
   with the defaults (3 × 3 × 32 s), and about 6.4 minutes at the gateway's caps (3 × 4 × 32 s).
   Choose `Http-Retries` and `Route-Retries` so that this fits the aa-core's HTTP client timeout
   for the internal APIs; for example, with a 60 s timeout, send `Http-Retries: 0` and
   `Route-Retries: 0` (one attempt, at most 32 s).

## 4. Receiving messages from the aa-iop-gw

### 4.1 Who calls

| Caller | Callee | Connection |
|---|---|---|
| aa-iop-gw | aa-core | `<aa-core base URL>/aa-core/<api>`, as set in the gateway configuration (HTTPS or plain HTTP). Expose these endpoints only to the aa-iop-gw. |

| Message comes from | `Initiator-Entity` |
|---|---|
| An FIU, delivered by its Connected-AA | `{"type":"FIU","id":"<FIU id>"}` |
| A FIP, delivered by its Inter-AA | `{"type":"FIP","id":"<FIP id>"}` |

### 4.2 How it works

For IOP calls addressed to the AA, the aa-iop-gw:

1. **Checks the calling AA** (its api-key and its signature on the message).
2. **Decrypts** the payload.
3. **Checks the Initiator's signature** on the payload.
4. **Calls the aa-core** with the plaintext payload (section 4.3).
5. **Signs and encrypts the aa-core's response** for the Initiator and returns it through the
   route.

### 4.3 APIs the aa-core must expose

| Method | Path | Caller | Callee | Same payload as the Direct API | Called for |
|---|---|---|---|---|---|
| `POST` | `/aa-core/Consent` | aa-iop-gw | aa-core | `/Consent` | Consent request from an FIU (the aa-core is the Customer-AA) |
| `POST` | `/aa-core/Consent/handle` | aa-iop-gw | aa-core | `/Consent/handle` | Consent handle status from an FIU |
| `POST` | `/aa-core/Consent/fetch` | aa-iop-gw | aa-core | `/Consent/fetch` | Consent fetch from an FIU |
| `POST` | `/aa-core/FI/request` | aa-iop-gw | aa-core | `/FI/request` | FI request from an FIU |
| `POST` | `/aa-core/FI/fetch` | aa-iop-gw | aa-core | `/FI/fetch` | FI fetch from an FIU |
| `POST` | `/aa-core/Consent/Notification` | aa-iop-gw | aa-core | `/Consent/Notification` | Consent notification from an FIU, or from a FIP (the aa-core is the Origin-AA) |
| `POST` | `/aa-core/FI/Notification` | aa-iop-gw | aa-core | `/FI/Notification` | FI notification from a FIP |
| `POST` | `/aa-core/Account/link/Notification` | aa-iop-gw | aa-core | `/Account/link/Notification` | Account link notification from a FIP |
| `GET` | `/aa-core/Heartbeat` | aa-iop-gw | aa-core | `/Heartbeat` | Heartbeat |

### 4.4 Request headers the aa-core receives

| Header | Mandatory | Value |
|---|---|---|
| `Authorization` | Yes, if the gateway is configured with a token for calls to the core | `Bearer <token>`. If a token is configured, the aa-core should reject calls without it or with a different value. |
| `Initiator-Entity` | Yes | The Initiator, as compact JSON `{"type":"…","id":"…"}`. |
| `Correlation-Id` | Yes | The flow's correlation id, copied unchanged from the IOP message (the gateway never creates one). |
| `Forwarding-Hop` | Yes | The entity id of the AA that delivered the call. |
| `x-jws-signature` | Yes, when there is a body | The Initiator's detached JWS over the body. Already checked by the gateway; the core may check it again and store it for non-repudiation. |

The role api-key header of the calling AA and `Content-Type` are **not** sent to the core.

### 4.5 Request body

- The body is **exactly the same payload** the Initiator would send in the matching Direct API call
  (column "Same payload as the Direct API" in section 4.3): the exact bytes the Initiator signed.
- Example: `POST /aa-core/Consent` carries exactly the payload an FIU sends in the Direct API `/Consent` call to an AA.
- **Duplicates.** The same message can arrive more than once, with the same `txnid` in the
  payload, because gateways retry and try other routes. The aa-core **must** de-duplicate on the
  payload's `txnid`: a repeated `txnid` must not be processed again (for example, return the
  earlier response).
- A Heartbeat (`GET /aa-core/Heartbeat`) has no body and no `x-jws-signature`.

### 4.6 Response

- The response body is **exactly the same payload** the AA returns in the matching Direct API call.
- Use the appropriate HTTP status. A status of 300 or above reaches the Initiator as an error.
- Respond within the gateway's configured core timeout (30 seconds by default).
- Heartbeat: return the status as JSON (for example `{"status":"UP"}`).

**Response headers**

| Header | Mandatory | Value |
|---|---|---|
| `Correlation-Id` | Yes | The value received in the request, unchanged. |
| `x-jws-signature` | No | The aa-core's own detached JWS (RS256 or PS256, base64url-encoded payload) over the response body, made with one of the AA's registered signing keys. If omitted, the gateway signs. |

`Content-Type` is not required.

**If the aa-iop-gw cannot use the response**, the Initiator receives this error instead:

| Status | `errorCode` | When |
|---|---|---|
| `502` | `InternalError` | The aa-core is unreachable, or its response is unreadable or larger than the gateway's limit |
| `502` | `InternalError` | The response has no `Correlation-Id`, or a different value |
| `500` | `InternalError` | The gateway cannot sign or encrypt the response for the Initiator |

## 5. Key provisioning

The AA's private **signing** keys (to sign messages and replies) and **decryption** keys (to
decrypt incoming messages) reach the aa-iop-gw in one of two ways, chosen in the gateway
configuration separately for each key type:

- **From the aa-core** (production): the aa-iop-gw pulls them (section 5.1), and the aa-core can push
  them (section 5.2).
- **Key files** mounted on the gateway: **for testing only** (section 8.1).

### 5.1 Key pull

| Caller | Callee | Connection |
|---|---|---|
| aa-iop-gw | aa-core | **HTTPS only.** The key base URL is set in the gateway configuration and can differ from the other core endpoints. |

| Method | Path | Caller | Callee | Returns |
|---|---|---|---|---|
| `GET` | `/aa-core/keys/signing` | aa-iop-gw | aa-core | The signing key set |
| `GET` | `/aa-core/keys/decryption` | aa-iop-gw | aa-core | The decryption key set |

- **Request headers:** only `Authorization: Bearer <key-fetch token>` (set in the gateway
  configuration). The aa-core must reject requests without it.
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
| aa-core | aa-iop-gw | **HTTPS only.** The aa-iop-gw's plain-HTTP listener, if any, refuses key push with `403`. |

| Method | Path | Caller | Callee | Use |
|---|---|---|---|---|
| `POST` | `/aa-dgw/keys/signing` | aa-core | aa-iop-gw | Replace the signing key set |
| `POST` | `/aa-dgw/keys/decryption` | aa-core | aa-iop-gw | Replace the decryption key set |
| `POST` | `/aa-sgw/keys/signing` | aa-core | aa-iop-gw | Replace the signing key set |
| `POST` | `/aa-sgw/keys/decryption` | aa-core | aa-iop-gw | Replace the decryption key set |

- The aa-core can replace a key set at once, without waiting for the next pull.
- **Request headers:** only `Authorization: Bearer <internal API token>`, when one is configured.
- **Request body:** the same as the pull response (section 5.1).
- **Response headers:** none. Replies, success or error, are not signed.
- These endpoints exist only for a key type the gateway takes from the aa-core (otherwise `404`).
- The next scheduled pull replaces the set again, so the aa-core's `GET` endpoints must return the
  same set.

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | The key set is invalid (empty, duplicate or missing `kid`, a key that is not RSA of at least 2048 bits, missing or invalid `active` / `applied` / `expiry`); the current set is kept |
| `401` | `InvalidSecurity` | The internal API token is missing or wrong (when one is configured) |
| `403` | `InvalidSecurity` | Sent over plain HTTP: key push is accepted only over HTTPS |
| `404` | `InvalidURI` | The gateway does not take this key type from the aa-core, or the path is not for the AA |
| `405` | `InvalidRequest` | Not `POST` |
| `413` | `InvalidRequest` | The request body is too large |

**Examples**

Request: `POST /aa-dgw/keys/signing` with a current key and the next one.

```http
POST /aa-dgw/keys/signing
Authorization: Bearer <internal API token>

{
  "keys": [
    {
      "kid": "aa-test-001-sig-2026-10",
      "privateKey": "-----BEGIN PRIVATE KEY-----\n<base64 key data>\n-----END PRIVATE KEY-----\n",
      "active": true,
      "applied": "2026-10-01T00:00:00Z",
      "expiry": "2026-12-01T00:00:00Z"
    },
    {
      "kid": "aa-test-001-sig-2026-12",
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
    {"kid": "aa-test-001-sig-2026-10", "active": true, "applied": "2026-10-01T00:00:00Z", "expiry": "2026-12-01T00:00:00Z", "usable": true},
    {"kid": "aa-test-001-sig-2026-12", "active": true, "applied": "2026-12-01T00:00:00Z", "expiry": null, "usable": false}
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
  "errorMsg": "key list: duplicate kid \"aa-test-001-sig-2026-10\""
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

- The aa-iop-gw keeps the keys **in memory only**. They are never written to its persistent cache,
  to disk, or to any temporary storage. After a restart it pulls them again.
- **Key pull and key push work only over HTTPS.** The gateway refuses an `http://` key URL at
  start-up, and its plain-HTTP listener refuses key push.
- The aa-core must check the key-fetch token, serve the key endpoints only to the aa-iop-gw, and never
  log key material.

## 6. Linked AAs (linkedAAs)

The aa-iop-gw uses as routes only the AAs the AA is linked to. The list reaches the gateway in one
of two ways, chosen in the gateway configuration:

- **From the aa-core** (production): the aa-iop-gw pulls the list, and the aa-core can push it. Both
  may use HTTP or HTTPS.
- **In the gateway configuration:** **for testing only** (section 8.1).

### 6.1 Pull

| Method | Path | Caller | Callee | Returns |
|---|---|---|---|---|
| `GET` | `/aa-core/linkedAAs` | aa-iop-gw | aa-core | The list of linked AAs |

- **Request headers:** only `Authorization: Bearer <token>` (set in the gateway configuration).
- **When:** at start-up, then every hour by default, and every 30 seconds while the gateway has
  no list. The gateway keeps the list in memory and in its persistent cache, so a restart can
  use the last list even if the aa-core is down.
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
| `POST` | `/aa-dgw/linkedAAs` | aa-core | aa-iop-gw | Replace the list |
| `POST` | `/aa-sgw/linkedAAs` | aa-core | aa-iop-gw | Replace the list |

- **Request headers:** only `Authorization: Bearer <internal API token>`, when one is configured.
- **Request body:** the same as the pull response.
- **Response:** `200` with the new list, no response headers. Errors: `400` (empty list or
  repeated id; the current list is kept), `401` (token), `405` (not `POST`), `413` (too large).
- The endpoint exists only when the gateway takes the list from the aa-core (otherwise `404`).

```http
POST /aa-dgw/linkedAAs
Authorization: Bearer <internal API token>

{
  "linkedAAs": [
    "aa-test-002",
    "aa-test-003"
  ]
}
```

## 7. Security notes

- The aa-iop-gw's internal APIs always run over HTTPS. A plain-HTTP listener can be added for the
  message APIs; use it only on a trusted network segment, since messages then travel
  unencrypted. Key push is never accepted there.
- If the aa-iop-gw is configured with an internal API token, the aa-core must send it on every call
  and keep it secret. Without a token, anyone who can reach the internal APIs can send messages
  as the AA: restrict network access to them.
- Expose the `/aa-core/*` endpoints only to the aa-iop-gw, and configure a token for calls to the core
  so the aa-core can check `Authorization` on every call.
- Key endpoints: HTTPS only, check the key-fetch token, serve them only to the aa-iop-gw, never log
  key material.

## 8. Configuring the aa-iop-gw before start-up

### 8.1 Production and testing

Wherever the aa-iop-gw can take something either from an API or from its configuration, **use the
API in production**. The configuration alternative is **for testing only**.

| What | Production: from the API | Testing only: from the configuration |
|---|---|---|
| Participants, their keys and interop flags | The Central Registry | A list of entities with public key files |
| Which AAs can reach a Target (AIG) | The Central Registry's AIG APIs | A graph in the configuration |
| Linked AAs | The aa-core (section 6) | A list in the configuration |
| The AA's signing and decryption keys | The aa-core (section 5) | Key files mounted on the gateway |
| Public keys of the api-key token issuer | The issuer's key URL (JWKS) | Public key files |
| The AA's api-key towards other AAs | The Sahamati token service | A fixed api-key |

### 8.2 Production configuration

This is a production configuration for the aa-iop-gw: everything comes from the APIs. Replace the
ids, URLs and file paths with the AA's own; the Central Registry, token service and issuer URLs
are provided by Sahamati. All values shown are illustrative.

```yaml
mode: AA
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
  id: aa-test-001                       # the AA's entity id in the Central Registry
  signingKey:                          # from the aa-core (section 5)
    source: api
    token: "${IOPGW_KEYS_TOKEN}"
  decryptionKeys:                      # from the aa-core (section 5)
    source: api
    token: "${IOPGW_KEYS_TOKEN}"

# Access token from the Sahamati token service
tokenService:
  baseUrl: https://iam.example.invalid/iam/v1
  path: /entity/token/generate
  credentialsFile: /etc/iopgw/secrets/credentials.json

# The aa-core
core:
  baseUrl: http://aa-core.internal:8080        # message calls (http or https)
  keysBaseUrl: https://aa-core.internal:8443   # key pull (https only)
  pathPrefix: /aa-core
  token: "${IOPGW_CORE_TOKEN}"                   # sent to the aa-core on every call
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
fiuAigPath: /v1/aig/fiu                 # an FIU's connected-AAs
fipAigPath: /v1/aig/fip                 # a FIP's inter-AAs

# Internal APIs (/aa-dgw and /aa-sgw) for the aa-core
gwApi:
  listenAddr: "10.0.0.10:9443"         # internal interface only; always HTTPS
  tls:
    certFile: /etc/iopgw/tls/internal.crt
    keyFile: /etc/iopgw/tls/internal.key
  token: "${IOPGW_GWAPI_TOKEN}"      # the aa-core sends it as Authorization: Bearer
  maxRetries: 3                        # cap on Http-Retries
  maxRouteRetries: 2                   # cap on Route-Retries

# Linked AAs: from the aa-core (section 6)
linkedAAs:
  source: api
  token: "${IOPGW_LINKED_TOKEN}"

hopPreference:
  connectedAAs: [aa-test-002]          # for FIU Targets, tried first in this order
  interAAs: [aa-test-003]              # for FIP Targets, tried first in this order

forwarding:
  timeoutSeconds: 30
  httpRetries: 2                       # as a hop: retries towards the Target

cache:
  dir: /var/lib/iopgw/cache
```

### 8.3 Local testing configuration

**For local testing only.** Here every item that production takes from an API is set in the
configuration file instead (section 8.1):

- **Participants and their public keys** (`cr.source: config`, `entities`) instead of the Central
  Registry.
- **The AIG** (`aigSource: config`, `aig`) instead of the AIG API.
- **Linked AAs** (`linkedAAs.source: config`, `linkedAAs.aas`) instead of `GET /aa-core/linkedAAs`.
- **The AA's signing and decryption keys** (`source: file`) instead of the aa-core's key endpoints.
- **Api-keys** (`apiKey.mode: static`, `self.outboundApiKey`) instead of the token service and its
  issuer.
- **Routes preferred** (`hopPreference`), as in production.

Key files, peer public keys and TLS files are read from `./local/`. The api-keys and the internal
API token are environment variables: `IOPGW_OUTBOUND_API_KEY`, `IOPGW_GWAPI_TOKEN` and one
`IOPGW_TEST_..._API_KEY` per calling participant. All ids, addresses and values are illustrative.

```yaml
# LOCAL TESTING ONLY: everything below comes from this file, not from the APIs.
mode: AA
logging:
  level: DEBUG
  audit: true
  statsIntervalSeconds: 60

listenAddr: "127.0.0.1:8443"           # /iop listener (HTTPS)
tls:
  certFile: ./local/tls/server.crt
  keyFile: ./local/tls/server.key

self:
  id: aa-test-001
  signingKey:                          # key file instead of the aa-core's key API
    source: file
    kid: aa-test-001-sig
    file: ./local/keys/aa-test-001-sig.pem
    active: true
    applied: "2026-11-01"
  decryptionKeys:                      # key files instead of the aa-core's key API
    source: file
    keys:
      - { kid: aa-test-001-enc, file: ./local/keys/aa-test-001-enc.pem, active: true, applied: "2026-11-01" }
  outboundApiKey: "${IOPGW_OUTBOUND_API_KEY}"   # fixed api-key towards other AAs (no token service)

core:
  baseUrl: http://127.0.0.1:8080       # the aa-core running locally
  pathPrefix: /aa-core
  timeoutSeconds: 30

apiKey:                                # fixed api-keys instead of the token issuer
  mode: static
  static:
    "${IOPGW_TEST_AA_002_API_KEY}": aa-test-002   # api-keys other participants send to this gateway
    "${IOPGW_TEST_AA_003_API_KEY}": aa-test-003
    "${IOPGW_TEST_FIU_001_API_KEY}": fiu-test-001
    "${IOPGW_TEST_FIP_001_API_KEY}": fip-test-001

jws:
  algorithm: RS256

cr:
  source: config                       # participants from this file, not the Central Registry
entities:
  - id: aa-test-002                       # Connected-AA: route to FIUs
    type: AA
    baseUrl: https://127.0.0.1:9002
    signingPublicKeys:
      - { kid: aa-test-002-sig, file: ./local/peers/aa-test-002-sig.pub.pem }
    encryptionPublicKeys:
      - { kid: aa-test-002-enc, file: ./local/peers/aa-test-002-enc.pub.pem }
  - id: aa-test-003                       # Inter-AA: route to FIPs
    type: AA
    baseUrl: https://127.0.0.1:9003
    signingPublicKeys:
      - { kid: aa-test-003-sig, file: ./local/peers/aa-test-003-sig.pub.pem }
    encryptionPublicKeys:
      - { kid: aa-test-003-enc, file: ./local/peers/aa-test-003-enc.pub.pem }
  - id: fiu-test-001                       # an FIU Target (reached through aa-test-002)
    type: FIU
    signingPublicKeys:
      - { kid: fiu-test-001-sig, file: ./local/peers/fiu-test-001-sig.pub.pem }
    encryptionPublicKeys:
      - { kid: fiu-test-001-enc, file: ./local/peers/fiu-test-001-enc.pub.pem }
  - id: fip-test-001                       # a FIP Target (reached through aa-test-003)
    type: FIP
    signingPublicKeys:
      - { kid: fip-test-001-sig, file: ./local/peers/fip-test-001-sig.pub.pem }
    encryptionPublicKeys:
      - { kid: fip-test-001-enc, file: ./local/peers/fip-test-001-enc.pub.pem }

aigSource: config                      # AIG graph from this file, not the AIG API
aig:
  fiu:                                 # per FIU: its Connected-AAs
    - fiu-test-001: [aa-test-002]
  fip:                                 # per FIP: its Inter-AAs
    - fip-test-001: [aa-test-003]

gwApi:                                 # internal APIs (/aa-dgw and /aa-sgw) for the aa-core
  listenAddr: "127.0.0.1:8444"         # always HTTPS
  httpListenAddr: "127.0.0.1:8081"     # plain HTTP for local calls (no key push)
  tls:
    certFile: ./local/tls/internal.crt
    keyFile: ./local/tls/internal.key
  token: "${IOPGW_GWAPI_TOKEN}"
  maxRetries: 3
  maxRouteRetries: 2

linkedAAs:
  source: config                       # list from this file, not the aa-core's API
  aas: [aa-test-002, aa-test-003]

hopPreference:
  connectedAAs: [aa-test-002]
  interAAs: [aa-test-003]

forwarding:
  timeoutSeconds: 30
  httpRetries: 2                       # as a hop: retries towards the Target

cache:
  dir: ./local/cache
```

### 8.4 What the AA provides (production)

| Item | What it is | Who uses it |
|---|---|---|
| `IOPGW_GWAPI_TOKEN` | Internal API token | The aa-core sends it on every call to the internal APIs |
| `IOPGW_CORE_TOKEN` | Token for calls to the aa-core | The aa-iop-gw sends it on every `/aa-core/*` call; the aa-core checks it |
| `IOPGW_KEYS_TOKEN` | Key-fetch token | The aa-iop-gw sends it on key pull; the aa-core checks it |
| `IOPGW_LINKED_TOKEN` | Linked-AAs token | The aa-iop-gw sends it on `GET /aa-core/linkedAAs`; the aa-core checks it |
| TLS certificate and key (public) | For the `/iop` listener | Other AAs calling the aa-iop-gw |
| TLS certificate and key (internal) | For the internal APIs | The aa-core |
| Credentials file | The AA's entity credentials for the Sahamati token service | The aa-iop-gw, to get its access token |

- The four tokens are given to the aa-iop-gw as environment variables; it does not start if one is
  empty. Keep them secret, and give each the same value on the aa-core's side.
- `hopPreference` lists the AA's preferred routes, tried first in that order (section 3.11).
- `gwApi.maxRetries` and `gwApi.maxRouteRetries` cap `Http-Retries` and `Route-Retries`.
- `logging.audit` writes one JSON log record tagged `IOPGW_AUDIT` per request and per response
  (headers, lengths, ids, status and error code; never the body), and
  `logging.statsIntervalSeconds` one record tagged `IOPGW_STATS` per interval with
  `|`-separated counts. Both can be fetched from the gateway's logs by their tag.

## 9. To do

- User discovery
