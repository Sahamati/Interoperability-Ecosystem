# FIP PRD — Interoperability for FIPs

|  |  |
|---|---|
| **Audience** | FIP application teams that build AA Interoperability into their existing FIP application |
| **Version** | Draft 1.2, 2026-11-10 |
| **Published by** | Sahamati |
| **Based on** | AA_Interop_1_0_0 (ReBIT AA Interoperability specification) |

All identifiers, URLs and values in examples are illustrative.

## Implementation of Interoperability APIs

### 1.1 Overview

Today a FIP can serve an AA only if the AA is directly connected to it. AA Interoperability (IOP)
lets the FIP also serve an AA that is not directly connected to it (the **Origin-AA**). The
Origin-AA sends its requests to an AA directly connected to the FIP (the **Inter-AA**), and the
Inter-AA carries them to the FIP. The FIP's replies and notifications go back the same way.

This section describes what a FIP must build into its **own FIP application** to do this:

- receiving `/iop/*` requests from the Origin-AA through an Inter-AA, and answering them;
- sending `/iop/*` notifications to the Origin-AA through an Inter-AA, and reading the replies;
- the IOP security for both: api-keys, signatures, end-to-end encryption;
- choosing the Inter-AA, retrying, and handling errors;
- the keys, registry data and tokens this needs.

The payloads are **exactly those of the Direct APIs** the FIP already uses. IOP adds a signed,
encrypted envelope around them and a route through an Inter-AA. Account, consent and FI business
logic does not change.

#### 1.1.1 Goals

| # | Goal |
|---|---|
| G1 | The FIP can serve account discovery, linking, consent and FI requests from, and send notifications to, an Origin-AA it is not directly connected to. |
| G2 | The FIP application implements every IOP security check: role api-key, sender identity, the Inter-AA's signature, the end-to-end encryption, and the Origin-AA's own signature. |
| G3 | Delivery is resilient: if one Inter-AA fails, another eligible one is tried. |
| G4 | Fail closed: anything outside the cryptographic profile, the wrong role, or an unknown path is refused. |
| G5 | No regulated data is exposed: request and response bodies are never logged, and secrets are never stored in configuration files or code. |

#### 1.1.2 Out of scope

| Item | Where |
|---|---|
| Account, consent and FI business logic | Unchanged: the FIP application's existing logic |
| Protection against replay beyond signatures and `txnid` de-duplication | Not covered in this release |

### 1.2 Terminology

| Term | Meaning |
|---|---|
| FIP application | The FIP's own application. In this section it includes the new IOP handlers. |
| Direct APIs | The existing ReBIT APIs as of today (for example `/Accounts/discover`, `/FI/request`, `/FI/Notification`), which participants call on each other when they are directly connected. IOP carries exactly the same payloads. |
| IOP APIs | The `/iop/*` APIs of AA_Interop_1_0_0. |
| Origin-AA | The AA that serves the customer and sends requests to the FIP. It is the **Initiator** of the requests the FIP receives and the **Target** of the notifications the FIP sends. |
| Inter-AA | An AA directly connected to the FIP. It carries `/iop/*` messages between the FIP and other AAs. Also called the route or hop. |
| Target | The participant that finally receives a message. |
| Initiator | The participant that created a message. |
| Route (hop) | The Inter-AA that carries one message. |
| linkedAAs | The AAs the FIP is linked to (has an agreement with). Only these are used as Inter-AAs. |
| Central Registry (CR) | Sahamati's registry of participants: ids, base URLs, public keys and the `interop` (interop ready) flag. |
| AIG | AA Interoperability Graph, published by the Central Registry: which AAs are linked to which AAs. |
| Interop ready | A participant whose `interop` flag in the Central Registry is `true`. |
| Correlation-Id (`correlationId`) | The id of one flow, in **standard UUID format** (RFC 4122, for example `9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94`). The Initiator creates it; it stays the same on every message of the flow. |
| `txnid` | Two different ids. **Payload `txnid`**: the id of one message, as in the Direct APIs; it is the same on every resend, end to end. **Envelope `txnid`**: the id of one transaction between two participants on one leg (for example the FIP and the Inter-AA); it is the same on retries to the same participant, and new for each route and for each leg. |
| Envelope | The JSON body of an `/iop/*` request or response: `ver`, `timestamp`, `txnid`, `correlationId`, `Target` or `Initiator`, and `encryptedData` (none on a heartbeat). `encryptedData` carries the request, and on a reply the response or the error alike: the HTTP status tells them apart. The Initiator sets `Target` and sends it to the hop; the hop replaces it with `Initiator` when it forwards to the Target. The receiver reads only the field its leg needs (`Target` at the hop, `Initiator` at the Target); if the other one is also present, it is ignored. |
| Inner JWS | The Initiator's (or Target's) compact JWS over the Direct API payload, carried encrypted inside `encryptedData`. |
| Outer signature | The detached JWS in the `x-jws-signature` header, over the whole envelope, made by the participant that sends it on that leg. |
| Access token | The FIP's token from the Sahamati token service. It is the FIP's role api-key towards Inter-AAs and its bearer token for the Central Registry and the AIG. |

### 1.3 Changes needed in the FIP application

"Yes" means needed in production.

| # | Change in the FIP application | Needed | Section |
|---|---|---|---|
| 1 | Register as interop ready in the Central Registry, with the FIP's `/iop` base URL, signature public keys and **encryption public keys**. | Yes | 1.5.1 |
| 2 | Keep the list of linkedAAs (the Inter-AAs the FIP may use). | Yes | 1.5.2 |
| 3 | Load and refresh the Central Registry AA list and the AIG, and keep a cached copy. | Yes | 1.6 |
| 4 | Get and refresh the FIP's access token from the Sahamati token service. | Yes | 1.6.4 |
| 5 | Serve the `/iop/*` request APIs (account discovery and linking, consent, FI, heartbeat) for Inter-AAs, with all security checks. | Yes | 1.7 |
| 6 | Answer requests with a signed, encrypted reply for the Origin-AA. | Yes | 1.7.5 |
| 7 | De-duplicate incoming messages on the payload's `txnid`. | Yes | 1.7.4 |
| 8 | Decide per AA: Direct APIs (AA directly connected) or IOP APIs (not directly connected), for the notifications the FIP sends. | Yes | 1.4 |
| 9 | Keep the `correlationId` of the flow on every notification. | Yes | 1.8.2 |
| 10 | Build `/iop/*` notifications: inner JWS, encryption for the Origin-AA, envelope, outer signature, role api-key `fip_api_key`. | Yes | 1.8 |
| 11 | Choose an Inter-AA from the AIG and linkedAAs; retry and fail over to another Inter-AA. | Yes | 1.9, 1.10 |
| 12 | Read replies: check the Inter-AA's signature, decrypt, check the Origin-AA's signature, and handle every error case. | Yes | 1.8.6, 1.11 |
| 13 | Manage signing and decryption key sets with validity dates, and rotate them in the right order. | Yes | 1.12 |
| 14 | Enforce the cryptographic profile and size limits. | Yes | 1.13 |
| 15 | Capture audit records and stats, as required by the FIP's regulatory or internal policy mandates. | Recommended | 1.14 |

### 1.4 When to use the IOP APIs

| Situation | What the FIP application does |
|---|---|
| The AA is **directly connected** to the FIP | Serves and calls the AA's Direct APIs, as today. |
| An AA that is not directly connected sends a request | It arrives on the FIP's `/iop/*` endpoints through an Inter-AA (section 1.7). |
| The FIP sends a notification to an Origin-AA that is **not directly connected**, and is interop ready | Calls the IOP API (`/iop/*`) on an Inter-AA, with the Origin-AA as `Target` (section 1.8). |
| The Origin-AA is not directly connected, and is **not** interop ready | Cannot reach it. The notification is not sent. |

### 1.5 Prerequisites

#### 1.5.1 Central Registry

The FIP's entry in the Central Registry must have:

| Item | Why |
|---|---|
| `interop: true` | Other participants send to, and accept messages from, interop-ready participants only. |
| `baseurl` | Inter-AAs send `/iop/*` requests to `<baseurl>/iop/<api>`. |
| Signature public keys (`keys.signature`) | Inter-AAs and Origin-AAs verify the FIP's signatures. Publish the public key of **every** signing key the FIP may use (section 1.12). |
| Encryption public keys (`keys.encryption`) | Origin-AAs encrypt requests and replies for the FIP. |

#### 1.5.2 linkedAAs

The FIP keeps the list of AAs it is linked to. An Inter-AA is used only if it is in this list. The
list must not be empty and must not repeat an id. When it changes, the new list is used for the
next message.

#### 1.5.3 Credentials

The FIP's entity credentials for the Sahamati token service are kept in secure storage, never in
code or in configuration files (section 1.6.4).

### 1.6 Reference data

The FIP application loads this data in the background and serves every lookup from memory. It
**never calls the Central Registry or the AIG per message.**

| Data | Source | Refresh | On failure |
|---|---|---|---|
| AAs: ids, base URLs, public keys, `interop` flag | Central Registry `GET /v2/entityInfo/AA` | Every 6 hours | Keep the previous list; retry after 5 minutes |
| Which AAs are linked to which AAs | AIG `GET /v1/aig/aa` | Every 6 hours | Keep the previous graph; retry after 5 minutes |
| linkedAAs | The FIP's own list (section 1.5.2) | When it changes | Keep the current list |
| Access token | Sahamati token service | Before it expires | Keep the current token until it expires; retry at most every 10 seconds |

Keep a cached copy of the Central Registry AA list, the AIG and the access token, so that a restart
can serve while a source is down. At start-up, the FIP application uses the cached copy and does
not fetch the Central Registry AA list or the AIG; it fetches them at start-up only when there is no
cached copy (for example, the first start). Never cache private keys (section 1.12).

#### 1.6.1 Central Registry AA list

- Call `GET <CR base URL>/v2/entityInfo/AA` with `Authorization: Bearer <access token>`. The FIP
  needs only AAs: the Inter-AAs and the Origin-AAs. It does not fetch the FIU or FIP lists.
- The response is a top-level JSON array; each element's `entityinfo` gives one participant:
  `id`, `baseurl`, `interop`, `keys.signature` (or `certificate` when that list is empty) and
  `keys.encryption`.
- Use only RSA keys of at least 2048 bits with a `kid`. Skip other keys.
- `interop` absent or not `true` means **not interop ready**.
- The FIP application uses the new list only if it is fetched and read successfully; otherwise it
  keeps the list it already has and tries again after 5 minutes.
- A response that is an empty array (`[]`), `null`, or not a JSON array counts as a failed fetch.

#### 1.6.2 AIG (AA graph)

- Call `GET <AIG base URL>/v1/aig/aa` with `Authorization: Bearer <access token>`.
- Response: `{"aa": [{"id": "<aa id>", "peer-AA": [{"id": "<aa id>", "verified": …, "attr": …}]}]}`.
  It lists only AAs and the AAs each is linked to (no FIUs or FIPs).
- Two AAs are linked if either lists the other (both directions count). `verified` does not change
  the route order; `attr` is not used.

#### 1.6.3 What the FIP uses from this data

| Need | Data |
|---|---|
| Is the Origin-AA interop ready? | Central Registry `interop` |
| Which Inter-AAs can reach the Origin-AA? | AIG, linkedAAs, Central Registry `interop` and `baseurl` |
| Encrypt for the Origin-AA | Origin-AA's `keys.encryption` (one chosen at random per message) |
| Verify the Inter-AA's and the Origin-AA's signatures | Their `keys.signature`, matched by `kid` |

#### 1.6.4 Access token

- Get the token with `POST <token service base URL>/entity/token/generate`, form fields `id`
  (the FIP's entity id) and `secret` (its entity secret).
- Response: `{"accessToken", "expiresIn", …}`. Errors: `{"errorCode", "errorMsg"}`.
- Get a new token when less than 1 hour of its lifetime remains, or at half its lifetime if it
  lives shorter than that.
- Read the secret from secure storage each time, so that it can be rotated without a restart.
- Never log the token or the secret.

### 1.7 Receiving IOP requests (FIP as Target)

#### 1.7.1 APIs the FIP must serve

The FIP serves these at `<FIP baseurl>/iop/<api>`. The caller is always an Inter-AA; the
`Initiator` is the Origin-AA.

| IOP API | Method | Same payload as the Direct API | Called for |
|---|---|---|---|
| `/iop/Accounts/discover` | `POST` | `/Accounts/discover` | Account discovery |
| `/iop/Accounts/link` | `POST` | `/Accounts/link` | Account linking |
| `/iop/Accounts/link/verify` | `POST` | `/Accounts/link/verify` | Account link verification |
| `/iop/Accounts/link/reverify` | `POST` | `/Accounts/link/reverify` | Account link re-verification |
| `/iop/Accounts/delink` | `POST` | `/Accounts/delink` | Account delinking |
| `/iop/Consent` | `POST` | `/Consent` | Consent artefact |
| `/iop/FI/request` | `POST` | `/FI/request` | FI data request |
| `/iop/FI/fetch` | `POST` | `/FI/fetch` | FI data fetch |
| `/iop/Consent/Notification` | `POST` | `/Consent/Notification` | Consent status notification |
| `/iop/Heartbeat` | `POST` | — (no encrypted payload) | Heartbeat from the Origin-AA |

Any other `/iop/*` path is answered `404 InvalidURI`; another method, `405`.

#### 1.7.2 Request headers received

| Header | Value |
|---|---|
| `inter_aa_api_key` | The Inter-AA's api-key: a token from the Sahamati token service |
| `x-jws-signature` | The Inter-AA's detached JWS over the envelope |

#### 1.7.3 Checks, in this order

| # | Check | If it fails |
|---|---|---|
| 1 | The path is one of section 1.7.1, with `POST` | `404 InvalidURI` / `405 InvalidRequest` |
| 2 | The body is within the size limit (2 MiB by default) | `413 InvalidRequest` |
| 3 | Exactly one role api-key header is present, and it is `inter_aa_api_key` | None or more than one: `401 InvalidSecurity`. Another key: `403 InvalidSecurity` |
| 4 | The api-key is a valid token: signature (RS256) with the issuer's public keys (from its JWKS URL) | `401 InvalidSecurity` |
| 5 | The sender is an AA registered in the Central Registry | `401 InvalidSecurity` / `403 InvalidSecurity` |
| 6 | `x-jws-signature` is present and verifies over the exact received bytes with the sender's signature keys, matched by `kid` | `401 InvalidSecurity` (missing) / `401 SignatureDoesNotMatch` |
| 7 | The body is a JSON object with `txnid` and a `correlationId` in standard UUID format | `400 InvalidRequest` |
| 8 | The envelope has `Initiator` (a `Target`, if present, is ignored); `Initiator.type` is `AA`, and the Initiator is registered | `400 InvalidRequest` |
| 9 | The Initiator has an encryption key in the Central Registry (needed for the reply) | `500 InternalError` |
| 10 | Except for `/iop/Heartbeat`: `encryptedData` is a compact JWE that decrypts with one of the FIP's usable decryption keys, matched by `kid`, and contains a compact JWS. A heartbeat has no `encryptedData` | `400 InvalidRequest` |
| 11 | Except for `/iop/Heartbeat`: the inner JWS verifies with the Initiator's signature keys | `401 SignatureDoesNotMatch`; the request is **not** processed |

Only then is the payload passed to the FIP's existing logic. Refresh the issuer's public keys at
start-up, every hour, and when a token names an unknown `kid` (at most once a minute).

#### 1.7.4 Duplicates

The same request can arrive more than once, because Inter-AAs and Origin-AAs retry and use other
routes. The envelope `txnid` can differ between copies; the payload's `txnid` does not. The FIP
**must** de-duplicate on the **payload's** `txnid`: a repeated payload `txnid` is not processed
again, and the earlier response is returned.

The FIP may also de-duplicate on the combination of `timestamp` and `txnid`, both from the inner
payload (not the envelope). Both stay the same on every copy of a request, because the Origin-AA
signed the payload once.

#### 1.7.5 Reply

1. The FIP's logic produces the response: exactly the payload of the Direct API response, and an
   HTTP status. For a heartbeat, the FIP's status, for example `{"status": "UP"}`.
2. **Sign** it (inner JWS) with one of the FIP's usable signing keys.
3. **Encrypt** the compact JWS for the **Initiator** (the Origin-AA), with one of its encryption
   keys.
4. **Build the reply envelope**:

   | Field | Value |
   |---|---|
   | `ver` | The request's `ver` |
   | `timestamp` | Now, UTC |
   | `txnid` | The request's `txnid` |
   | `correlationId` | The request's `correlationId`, unchanged |
   | `encryptedData` | The compact JWE, for a success and an error alike: the HTTP status tells them apart |

5. **Sign the envelope** (detached JWS in `x-jws-signature`) and return it with the status.

Errors from the checks in section 1.7.3 are not encrypted: they are a plain `ErrorResponse`,
signed with `x-jws-signature`:

```json
{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-09T10:15:00.000Z",
  "errorCode": "SignatureDoesNotMatch",
  "errorMsg": "Initiator signature does not verify"
}
```

`errorMsg` must never contain payload content, keys or token values.

#### 1.7.6 Error codes the FIP returns on `/iop/*`

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | Body not a valid envelope (no `txnid`, no or non-UUID `correlationId`, `Initiator` missing); Initiator not an AA or not registered; `encryptedData` not a compact JWE, not decryptable, or without a compact JWS inside; `encryptedData` on a heartbeat |
| `401` | `InvalidSecurity` | No role api-key header or more than one; invalid api-key; sender not registered; `x-jws-signature` missing |
| `401` | `SignatureDoesNotMatch` | `x-jws-signature` or the Initiator's inner signature does not verify |
| `403` | `InvalidSecurity` | A role api-key other than `inter_aa_api_key`, or the sender is not an AA |
| `404` | `InvalidURI` | Unknown `/iop` path |
| `405` | `InvalidRequest` | Wrong HTTP method |
| `413` | `InvalidRequest` | Body too large |
| `500` | `InternalError` | No encryption key for the Initiator; unable to sign or encrypt the reply |
| `503` | `InternalError` | Central Registry data, decryption keys or issuer keys not loaded yet |

### 1.8 Sending IOP notifications (FIP as Initiator)

#### 1.8.1 APIs

The FIP sends these to an Inter-AA, at `POST <Inter-AA baseurl>/iop/<api>`. The `Target` is always
the Origin-AA (`type` `AA`).

| IOP API | Same payload as the Direct API | Use |
|---|---|---|
| `POST /iop/Consent/Notification` | `/Consent/Notification` | Consent status notification to the Origin-AA |
| `POST /iop/FI/Notification` | `/FI/Notification` | FI status notification to the Origin-AA |
| `POST /iop/Account/link/Notification` | `/Account/link/Notification` | Account link notification to the Origin-AA |
| `POST /iop/Heartbeat` | — (no encrypted payload) | Heartbeat towards the Origin-AA |

#### 1.8.2 Correlation id

- Every `/iop/*` message carries a non-empty `correlationId` in standard UUID format.
- A notification about a flow keeps that flow's `correlationId`, retries included. The FIP creates
  a new one only when it starts a new flow (for example a heartbeat).
- When the FIP answers a request, it uses the `correlationId` it received.
- Participants refuse a message without a `correlationId`, or with one that is not a UUID, with
  `400 InvalidRequest`.

#### 1.8.3 Building the request

For each notification, the FIP application:

1. **Builds the payload**: exactly the payload of the matching Direct API call (section 1.8.1). It
   must contain `txnid`.
2. **Signs the payload** (inner JWS): a compact JWS over the payload bytes, with one of the FIP's
   usable signing keys, its `kid` in the protected header (section 1.13).
3. **Encrypts** the compact JWS for the Origin-AA: compact JWE, `RSA-OAEP-256` / `A256GCM`, with
   one of the Origin-AA's encryption keys, its `kid` in the JWE header.
4. **Builds the envelope**:

   | Field | Value |
   |---|---|
   | `ver` | The payload's `ver` |
   | `timestamp` | Now, UTC, for example `2026-11-09T10:15:00.000Z` |
   | `txnid` | The id of this transaction between the FIP and the Inter-AA, created by the FIP (UUID): the same on retries to that Inter-AA, a new one for each other Inter-AA tried. It is **not** the inner payload's `txnid`, which stays inside the encrypted payload for the Origin-AA. The Inter-AA's reply carries the same `txnid` |
   | `correlationId` | The flow's correlation id |
   | `Target` | `{"type": "AA", "id": "<Origin-AA id>"}` |
   | `encryptedData` | The compact JWE |

5. **Signs the envelope** (outer signature): a detached JWS over the exact envelope bytes, in
   `x-jws-signature`.
6. **Chooses an Inter-AA** (section 1.9) and sends the request.

#### 1.8.4 Request headers

| Header | Mandatory | Value |
|---|---|---|
| `fip_api_key` | Yes | The FIP's access token (section 1.6.4). It is the FIP's role api-key towards an Inter-AA. Send **no other** role api-key header. |
| `x-jws-signature` | Yes | The detached JWS over the envelope (step 5). |
| `Content-Type` | Yes | `application/json` |

#### 1.8.5 Example request

```http
POST /iop/FI/Notification
fip_api_key: <the FIP's access token>
x-jws-signature: <detached JWS over the body>
Content-Type: application/json

{
  "ver": "2.0.0",
  "timestamp": "2026-11-09T10:15:00.000Z",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
  "Target": {"type": "AA", "id": "aa-test-002"},
  "encryptedData": "<compact JWE>"
}
```

#### 1.8.6 Reading the reply

1. **Check the Inter-AA's signature**: `x-jws-signature` on the reply must verify over the exact
   reply bytes with the Inter-AA's signature keys. If it does not, the reply is not used
   (section 1.11).
2. If the reply has `encryptedData` (the Origin-AA's response or error; the HTTP status tells them
   apart):
   - **decrypt** it with the FIP's usable decryption keys, matched by the JWE `kid`;
   - **check the Origin-AA's signature**: the decrypted content must be a compact JWS that
     verifies with the Origin-AA's signature keys;
   - **use the payload**: it is exactly the Origin-AA's Direct API response (or error), with the
     reply's HTTP status.
3. Otherwise, handle it as in section 1.11.

Keep the Origin-AA's inner JWS with the payload where the FIP needs it for non-repudiation, as for
a Direct API response.

#### 1.8.7 Heartbeat

- `POST /iop/Heartbeat` has **no** `encryptedData`. As for every `/iop/*` request, the FIP sets
  `Target` (the Origin-AA) and sends it to the Inter-AA. The Inter-AA replaces it with `Initiator`
  (the FIP) when it forwards the heartbeat to the Origin-AA.

  ```json
  {
    "ver": "1.0.0",
    "timestamp": "2026-11-09T10:15:00.000Z",
    "txnid": "5c7e9a1b-2d4f-4a6c-8e0b-1f3a5c7e9b2d",
    "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
    "Target": {"type": "AA", "id": "aa-test-002"}
  }
  ```

- Only the outer signature is used; there is no inner JWS.
- The FIP creates a new `txnid` for each heartbeat.
- The Target is never the Inter-AA itself: to check a directly connected AA, the FIP uses the
  Direct API `GET /Heartbeat`.
- The reply is read as in section 1.8.6.

### 1.9 Choosing the Inter-AA (route)

#### 1.9.1 Before choosing

The Origin-AA must be registered in the Central Registry as an `AA` and be interop ready.
Otherwise the request is not sent.

#### 1.9.2 Eligible Inter-AAs

An AA is eligible only if **all** of these hold:

| # | Condition |
|---|---|
| 1 | It is in the FIP's linkedAAs. |
| 2 | The AIG links it to the Origin-AA, in either direction. |
| 3 | It is interop ready in the Central Registry. |
| 4 | It has a `baseurl` in the Central Registry. |
| 5 | It is not the Origin-AA itself. This applies to `/iop/Heartbeat` too: a directly connected AA is checked with the Direct API `GET /Heartbeat`. |

If no AA is eligible, the request cannot be sent.

### 1.10 Retries and failover

#### 1.10.1 Rules

1. **Every resend carries the same payload and `correlationId`.** A retry to the same Inter-AA
   resends the same envelope (same envelope `txnid`); another Inter-AA gets a new envelope with a
   new envelope `txnid`. An Origin-AA can therefore receive a message twice, and must
   de-duplicate on the payload's `txnid`.
2. **Errors from beyond the Inter-AA are final.** A reply with `encryptedData`, or with `errorCode`
   `IopDownstreamError`, is the Origin-AA's answer, or says that the Origin-AA could not be reached.
   Another Inter-AA would reach the same Origin-AA.
3. **Any other error from the Inter-AA means: try the next route.** An error answer without
   `encryptedData` and with another `errorCode` (for example `400 InvalidRoute`, when the Inter-AA
   cannot route to the Origin-AA) comes from the Inter-AA itself. The FIP tries the next eligible
   Inter-AA.
4. **The Inter-AA may retry too.** It may resend to the Origin-AA when the Origin-AA does not
   answer or answers `502`/`503`/`504` without `encryptedData`, and then answers `IopDownstreamError`. The
   FIP's timeout per attempt should allow for this; otherwise the FIP may resend while the
   Inter-AA is still retrying.
5. **When every route fails**, the notification has failed: the FIP application reports "all
   routes unavailable" to the flow, and may send it again later (with a new `txnid`).

### 1.11 Outcomes of a request

| Outcome | What the FIP application gets |
|---|---|
| Success | The Origin-AA's Direct API response, its status and its inner JWS (section 1.8.6). |
| The Origin-AA's error (`encryptedData` with a `4xx`/`5xx` status) | The Origin-AA's Direct API error payload, its status and its inner JWS. |
| The Origin-AA's error without a payload (`IopDownstreamError` without `encryptedData`) | The status only. |
| Every route failed | "All routes unavailable" (section 1.10.1). |
| Not sent | The Origin-AA is not registered or not interop ready; no eligible Inter-AA; reference data, keys or the access token not available; the payload has no `txnid`; signing or encryption failed. |
| The reply cannot be trusted | The Inter-AA's signature does not verify; `encryptedData` cannot be decrypted; the decrypted content is not a compact JWS; the Origin-AA's signature does not verify. The reply is **not used**, and the event is logged. |

A reply that cannot be trusted is not retried automatically: the message may already have been
processed by the Origin-AA. The flow decides what to do next.

### 1.12 Keys

#### 1.12.1 Key sets

The FIP keeps two sets of RSA private keys (at least 2048 bits):

| Set | Used for | How a key is chosen |
|---|---|---|
| Signing keys | Inner JWS and outer `x-jws-signature`, on requests, replies and errors | One usable key **at random** per signature, its `kid` in the header |
| Decryption keys | Decrypting `encryptedData` | Every usable key, matched by the JWE `kid` |

Each key has:

| Field | Meaning |
|---|---|
| `kid` | Unique in the set; the `kid` under which its public key is published in the Central Registry |
| `active` | `true` to allow use; `false` to keep the key listed but unused |
| `applied` | From when the key may be used |
| `expiry` | Until when it may be used (none = no expiry) |

A key is **usable** while `active`, from `applied` until `expiry`. Check it at every use, so that
rotations can be scheduled in advance. Keep at least one usable key in each set at all times:
without one, the FIP cannot sign (and so cannot send or answer anything) or cannot decrypt.

#### 1.12.2 Rotation order

| Key type | Order |
|---|---|
| Signing | 1. Publish the new public key in the Central Registry. 2. Wait for participants to pick it up (their refresh interval, 6 hours by default). 3. Add the new private key to the set. 4. Set `expiry` (or `active: false`) on the old key. |
| Decryption | 1. Add the new private key to the set first. 2. Publish the new public encryption key in the Central Registry. 3. Keep the old private key until participants have switched (at least their refresh interval). 4. Then set its `expiry` (or `active: false`). |

#### 1.12.3 Protection

- Keep private keys in secure storage, as the FIP's key-management policy requires.
- Never write private keys to logs, caches or temporary files, and never return them in an API.
- Log only `kid`, `active`, `applied`, `expiry` and whether a key is usable.

### 1.13 Cryptographic profile and limits

| Item | Requirement |
|---|---|
| JWS | `RS256` or `PS256`, with base64url-encoded payloads. Detached JWS (`header..signature`) for `x-jws-signature`; compact JWS for the inner JWS. Refuse `alg: none`, HMAC algorithms, `b64: false` and `crit`. |
| JWE | Compact, `RSA-OAEP-256` / `A256GCM` only. Refuse `zip`. |
| RSA keys | At least 2048 bits, with a `kid`. |
| Signature input | The exact bytes sent or received. Never re-serialise JSON before verifying. |
| Inbound body | At most 2 MiB by default (`413` above). |
| Replies from Inter-AAs | At most 64 MiB; larger is treated as no answer. |
| Redirects | Never followed. |
| Timeouts | 30 s per attempt towards an Inter-AA by default. |
| Transport | HTTPS. The role api-key header names contain underscores: any proxy in front of the FIP's `/iop` endpoints must pass them (for nginx, `underscores_in_headers on;`). |

### 1.14 Audit records and stats

The FIP application should capture audit records and stats for its IOP requests and responses, as
required by its regulatory or internal policy mandates.

### 1.15 Non-functional requirements

| Area | Requirement |
|---|---|
| Data protection | Request and response bodies are never logged. Logs carry only ids, paths, status, lengths and latency. Test data uses synthetic ids and generated keys only. |
| Secrets | The entity secret, access tokens and private keys are kept in secure storage, never in code, configuration files or version control, and never logged. |
| Fail closed | Unknown paths, wrong roles, unregistered or not interop-ready participants, and anything outside the cryptographic profile are refused. |
| Availability of reference data | Cached Central Registry AA list, AIG and access token let the FIP keep working while a source is down. |
| Performance | Targets to be agreed. |

### 1.16 Production and testing

Production uses the live sources. Local alternatives are **for testing only**.

| What | Production | Testing only |
|---|---|---|
| Participants, keys and interop flags | Central Registry | A local list with public key files |
| Which AAs are linked to which | AIG API | A local graph |
| The FIP's signing and decryption keys | The FIP's secure key storage | Key files |
| Api-key checking of Inter-AAs | Token issuer's JWKS | Fixed test api-keys |
| The FIP's role api-key | Sahamati token service | A fixed test api-key |

### 1.17 Uploading encryption public keys

*To be written.* How the FIP uploads its encryption public keys to the Central Registry (see
section 1.5.1 for why they are needed, and section 1.12.2 for the rotation order).

### 1.18 Marking as interop-ready

*To be written.* How the FIP is marked interop ready (`interop: true`) in the Central Registry
(see section 1.5.1).

### 1.19 Error handling

*To be written.* (See section 1.7.6 for the error codes the FIP returns on `/iop/*`, and section
1.11 for the outcomes of a notification.)

### 1.20 AA Interoperability Graph (AIG) APIs to look up

*To be written.* (See section 1.6.2 for how the FIP reads the AIG.)

### 1.21 Acceptance criteria

Each item must be covered by automated tests with synthetic participants.

| # | Criterion |
|---|---|
| AC-1 | End to end: Origin-AA → Inter-AA → FIP for each API in section 1.7.1. The FIP's logic gets the Origin-AA's payload, and the Origin-AA gets the FIP's reply, decrypted and verified. |
| AC-2 | A FIP error reaches the Origin-AA as `encryptedData` (encrypted for the Origin-AA), with its status. |
| AC-3 | Request rejections: tampered body, missing signature, unknown or invalid api-key, a role key other than `inter_aa_api_key`, two role keys, sender not an AA, `Initiator` missing from the envelope, missing or non-UUID `correlationId`, `encryptedData` on a heartbeat, unknown path, wrong method, oversized body. |
| AC-4 | A spoofed Initiator (inner JWS not from the Initiator) is refused with `401 SignatureDoesNotMatch` and the request is not processed. |
| AC-5 | A repeated payload `txnid` (or, where the FIP uses it, a repeated combination of payload `timestamp` and `txnid`) is not processed again and gets the earlier response, even when the envelope `txnid` differs. |
| AC-6 | Heartbeat received: answered with an encrypted, signed status for the Origin-AA. |
| AC-7 | End to end: FIP → Inter-AA → Origin-AA for each API in section 1.8.1. The FIP gets the Origin-AA's payload, status and inner JWS. |
| AC-8 | An Origin-AA error without a payload gives the FIP the status only, with no retry and no other route. |
| AC-9 | Route choice: only AAs that are in linkedAAs, linked to the Origin-AA in the AIG, interop ready and with a `baseurl` are used. |
| AC-10 | An Origin-AA that is not interop ready, or no eligible Inter-AA, stops the notification before anything is sent. |
| AC-11 | Replies with a wrong Inter-AA signature, a payload that cannot be decrypted, or a wrong Origin-AA signature are not used. |
| AC-12 | Keys: signatures use only usable keys, at random; keys join at `applied` and drop at `expiry`; decryption tries keys by `kid`; key material never appears in logs or errors. |
| AC-13 | Cryptographic profile: RS256 and PS256 round trips work; `alg: none`, HMAC, `b64: false`, `crit`, `zip` and a `kid` mismatch are refused. |
| AC-14 | Reference data: lookups make no calls to the Central Registry or the AIG; a failed refresh keeps the previous data; a cached copy is served after a restart with the source down. |

### 1.22 Items to be confirmed

| Item | Status |
|---|---|
| Role api-key header names (`fip_api_key`, `inter_aa_api_key`) and `Initiator{type: AA}` on the Inter-AA → FIP leg | Subject to the final ReBIT specification for role api-key names |
| The account APIs: `/iop/Accounts/discover`, `/iop/Accounts/link`, `/iop/Accounts/link/verify`, `/iop/Accounts/link/reverify`, `/iop/Accounts/delink` and `/iop/Account/link/Notification` (plural and singular as in the Direct APIs) | Subject to the final ReBIT specification |
| `ver` of the Heartbeat envelope, which has no payload to take it from | `1.0.0` used; subject to the final ReBIT specification |
