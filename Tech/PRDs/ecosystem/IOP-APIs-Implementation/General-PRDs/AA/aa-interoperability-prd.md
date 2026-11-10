# AA PRD — Interoperability for AAs

|  |  |
|---|---|
| **Audience** | AA application teams that build AA Interoperability into their existing AA application |
| **Version** | Draft 1.10, 2026-11-10 |
| **Published by** | Sahamati |
| **Based on** | AA_Interop_1_0_0 (ReBIT AA Interoperability specification) |

All identifiers, URLs and values in examples are illustrative.

## Implementation of Interoperability APIs

### 1.1 Overview

Today an AA works only with the FIUs and FIPs it is directly connected to. AA Interoperability
(IOP) lets FIUs, AAs and FIPs that are not directly connected reach each other through an AA that
is. An AA takes part in IOP in **three roles**:

| Role | When | What the AA does |
|---|---|---|
| **Initiator** | The AA serves a customer and must reach an FIU or a FIP it is not directly connected to | As **Customer-AA**, it sends notifications to an FIU through the FIU's **Connected-AA**. As **Origin-AA**, it sends account, consent and FI requests to a FIP through the FIP's **Inter-AA** (section 1.7). |
| **Target** | An FIU or a FIP that is not directly connected to the AA sends it a message | It receives consent, FI and user discovery requests from an FIU through the FIU's Connected-AA, and notifications from a FIP through the FIP's Inter-AA, and answers them (section 1.11). |
| **Hop** | The AA is directly connected to an FIU or a FIP, and another AA must reach it (or the other way round) | As **Connected-AA** of an FIU, or **Inter-AA** of a FIP, it carries `/iop/*` messages between that FIU or FIP and other AAs, without reading their content (section 1.12). |

This section describes what an AA must build into its **own AA application** for these roles:

- sending `/iop/*` requests through a Connected-AA or Inter-AA, and reading the replies;
- receiving `/iop/*` requests through a Connected-AA or Inter-AA, and answering them;
- carrying `/iop/*` messages as a hop between other participants;
- the IOP security for all three: api-keys, signatures, end-to-end encryption;
- choosing the route, retrying, and handling errors;
- the keys, registry data and tokens this needs.

The payloads are **exactly those of the Direct APIs** the AA already uses. IOP adds a signed,
encrypted envelope around them and a route through a hop. Consent, account and FI business logic
does not change.

#### 1.1.1 Goals

| # | Goal |
|---|---|
| G1 | The AA can serve its customers with FIUs and FIPs it is not directly connected to. |
| G2 | The AA can carry messages, as a hop, for the FIUs and FIPs it is directly connected to. |
| G3 | The AA application implements every IOP security check: role api-key, sender identity, the hop's signature, the end-to-end encryption, and the Initiator's or Target's own signature. As a hop, it never decrypts the content. |
| G4 | Delivery is resilient: if one route fails, another eligible one is tried; as a hop, an unavailable Target may be retried. |
| G5 | Fail closed: anything outside the cryptographic profile, the wrong role, or an unknown path is refused. |
| G6 | No regulated data is exposed: request and response bodies are never logged, and secrets are never stored in configuration files or code. |

#### 1.1.2 Out of scope

| Item | Where |
|---|---|
| Consent, account and FI business logic | Unchanged: the AA application's existing logic |
| Protection against replay beyond signatures and `txnid` de-duplication | Not covered in this release |

### 1.2 Terminology

| Term | Meaning |
|---|---|
| AA application | The AA's own application. In this section it includes the new IOP handlers. |
| Direct APIs | The existing ReBIT APIs as of today (for example `/Consent`, `/FI/request`, `/Accounts/discover`, `/FI/Notification`), which participants call on each other when they are directly connected. IOP carries exactly the same payloads. |
| IOP APIs | The `/iop/*` APIs of AA_Interop_1_0_0. |
| Customer-AA | The AA that holds the customer's account and consent, in a flow with an FIU it is not directly connected to. |
| Origin-AA | The AA that serves the customer and sends requests to a FIP it is not directly connected to. |
| Connected-AA | An AA directly connected to an FIU. It carries `/iop/*` messages between that FIU and other AAs. |
| Inter-AA | An AA directly connected to a FIP. It carries `/iop/*` messages between that FIP and other AAs. |
| Target | The participant that finally receives a message. |
| Initiator | The participant that created a message. |
| Hop (route) | The Connected-AA or Inter-AA that carries one message. |
| Leg | One HTTP call between two participants: Initiator → hop, or hop → Target. |
| linkedAAs | The AAs this AA is linked to (has an agreement with). Only these are used as routes when this AA is the Initiator, and only these are reached as Targets when this AA is a hop. |
| Central Registry (CR) | Sahamati's registry of participants: ids, base URLs, public keys and the `interop` (interop ready) flag. |
| AIG | AA Interoperability Graph, published by the Central Registry: which AAs are the Connected-AAs of each FIU and the Inter-AAs of each FIP. |
| Interop ready | A participant whose `interop` flag in the Central Registry is `true`. |
| Correlation-Id (`correlationId`) | The id of one flow, in **standard UUID format** (RFC 4122, for example `9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94`). The Initiator creates it; it stays the same on every message of the flow, and a hop copies it unchanged. |
| `txnid` | Two different ids. **Payload `txnid`**: the id of one message, as in the Direct APIs; it is the same on every resend, end to end. **Envelope `txnid`**: the id of one transaction between two participants on one leg; it is the same on retries to the same participant, and new for each route and for each leg. |
| Envelope | The JSON body of an `/iop/*` request or response: `ver`, `timestamp`, `txnid`, `correlationId`, `Target` or `Initiator`, and `encryptedPayload` (none on a heartbeat). `encryptedPayload` carries the request, and on a reply the response or the error alike: the HTTP status tells them apart. The Initiator sets `Target` and sends it to the hop; the hop replaces it with `Initiator` when it forwards to the Target. The receiver reads only the field its leg needs (`Target` at the hop, `Initiator` at the Target); if the other one is also present, it is ignored. |
| Inner JWS | The Initiator's (or Target's) compact JWS over the Direct API payload, carried encrypted inside `encryptedPayload`. A hop cannot read it. |
| Outer signature | The detached JWS in the `x-jws-signature` header, over the whole envelope, made by the participant that sends it on that leg. |
| Role api-key | The header that carries the sender's api-key on an `/iop` call. Its name tells the receiver the leg (section 1.12.1). |
| Access token | The AA's token from the Sahamati token service (`/entity/token/generate`). It is the AA's api-key on Direct API calls, and its bearer token for the Central Registry and the AIG. |
| IopToken | The AA's IOP token from the Sahamati token service (`/entity/iopToken/generate`). It is the AA's role api-key on every `/iop` call it sends (section 1.6.5). |
| User Hash List | The AA's list of hashed user handles and mobile numbers of the customers whose attested handles it holds, used to answer user discovery (section 1.18.3). |

### 1.3 Changes needed in the AA application

"Yes" means needed in production.

| # | Change in the AA application | Needed | Section |
|---|---|---|---|
| 1 | Register as interop ready in the Central Registry, with the AA's `/iop` base URL, signature public keys and **encryption public keys**. | Yes | 1.5.1 |
| 2 | Keep the list of linkedAAs (the AAs this AA may use as routes). | Yes | 1.5.2 |
| 3 | Load and refresh the Central Registry entity lists (AA, FIU, FIP) and the AIG, and keep a cached copy. | Yes | 1.6 |
| 4 | Get and refresh the AA's access token and IopToken from the Sahamati token service, and use the IopToken on every `/iop` call. | Yes | 1.6.4, 1.6.5 |
| 5 | Decide per FIU or FIP: Direct APIs (directly connected) or IOP APIs (not directly connected). | Yes | 1.4 |
| 6 | Create a `correlationId` (UUID) for each new flow, and keep it on every message of that flow. | Yes | 1.7.2 |
| 7 | Build `/iop/*` requests: inner JWS, encryption for the Target, envelope, outer signature, role api-key `x-cust_aa_api_key` (to an FIU) or `x-orig_aa_api_key` (to a FIP). | Yes | 1.7 |
| 8 | Choose the route from the AIG and linkedAAs; retry and fail over to another route. | Yes | 1.8, 1.9 |
| 9 | Read replies: check the hop's signature, decrypt, check the Target's signature, and handle every error case. | Yes | 1.7.6, 1.10 |
| 10 | Serve the `/iop/*` APIs for FIUs (through their Connected-AA) and FIPs (through their Inter-AA), with all security checks, and answer with a signed, encrypted reply. | Yes | 1.11 |
| 11 | De-duplicate incoming messages on the payload's `txnid`. | Yes | 1.11.4 |
| 12 | Carry `/iop/*` messages as a hop: check the sender, rebuild and sign the envelope, forward to the Target, retry an unavailable Target, and answer the sender. | Yes | 1.12 |
| 13 | Manage signing and decryption key sets with validity dates, and rotate them in the right order. | Yes | 1.13 |
| 14 | Enforce the cryptographic profile and size limits. | Yes | 1.14 |
| 15 | Capture audit records and stats, as required by the AA's regulatory or internal policy mandates. | Recommended | 1.15 |
| 16 | Serve user discovery: the Direct API `/User/discover` for linked FIUs, and `/iop/User/discover` as Customer-AA and as Connected-AA. | Yes | 1.18 |
| 17 | Keep the User Hash List and answer user discovery from it. | Yes | 1.18.3 |

### 1.4 When to use the IOP APIs

| Situation | What the AA application does |
|---|---|
| The FIU or FIP is **directly connected** to the AA | Calls and serves its Direct APIs, as today. |
| An FIU is **not directly connected**, and is interop ready | Sends `/iop/*` notifications to one of the FIU's Connected-AAs, with the FIU as `Target` (section 1.7). |
| A FIP is **not directly connected**, and is interop ready | Sends `/iop/*` requests to one of the FIP's Inter-AAs, with the FIP as `Target` (section 1.7). |
| The FIU or FIP is not directly connected, and is **not** interop ready | Cannot reach it. The flow is not started. |
| An FIU or FIP that is not directly connected sends a message to the AA | It arrives on the AA's `/iop/*` endpoints through a Connected-AA or Inter-AA (section 1.11). |
| Another AA, or an FIU or FIP directly connected to this AA, sends a message for someone else | The AA carries it as a hop (section 1.12). |

### 1.5 Prerequisites

#### 1.5.1 Central Registry

The AA's entry in the Central Registry must have:

| Item | Why |
|---|---|
| `interop: true` | Other participants send to, route through, and accept messages from interop-ready participants only. |
| `baseurl` | Other participants send `/iop/*` calls to `<baseurl>/iop/<api>`. |
| Signature public keys (`keys.signature`) | Hops and Targets verify the AA's signatures. Publish the public key of **every** signing key the AA may use (section 1.13). |
| Encryption public keys (`keys.encryption`) | FIUs and FIPs encrypt requests and replies for the AA. |

Each key in `keys.signature` and `keys.encryption` is published with an optional validity window, as
`{"key": <JWK>, "validFrom", "validTo"}`. Other participants use a key only between its `validFrom`
and `validTo`, so the window must cover the whole time the key is in use (section 1.13.2).

The AA's links to the FIUs and FIPs it is directly connected to must also be published in the AIG,
so that other AAs choose it as a hop (section 1.22).

#### 1.5.2 linkedAAs

The AA keeps the list of AAs it is linked to. The list is used in two ways:

| Role | Use of linkedAAs |
|---|---|
| Initiator | A route is used only if it is in this list (section 1.8.2). |
| Hop | An AA Target (Customer-AA or Origin-AA) is forwarded to only if it is in this list (section 1.12.3). |

The list must not be empty and must not repeat an id. When it changes, the new list is used for the
next message.

#### 1.5.3 Credentials

The AA's entity credentials for the Sahamati token service are kept in secure storage, never in
code or in configuration files (section 1.6.4).

### 1.6 Reference data

The AA application loads this data in the background and serves every lookup from memory. It
**never calls the Central Registry or the AIG per message.**

| Data | Source | Refresh | On failure |
|---|---|---|---|
| AAs, FIUs and FIPs: ids, base URLs, public keys, `interop` flag | Central Registry `GET /v2/entityInfo/AA`, `/FIU` and `/FIP` | Every 6 hours | Keep the previous lists; retry after 5 minutes |
| The Connected-AAs of each FIU, and the Inter-AAs of each FIP | AIG `GET /v1/aig/fiu` and `GET /v1/aig/fip` | Every 6 hours | Keep the previous graphs; retry after 5 minutes |
| linkedAAs | The AA's own list (section 1.5.2) | When it changes | Keep the current list |
| Access token | Sahamati token service | Before it expires | Keep the current token until it expires; retry at most every 10 seconds |
| IopToken | Sahamati token service | Before it expires | Keep the current token until it expires; retry at most every 10 seconds |

Keep a cached copy of the Central Registry lists, the AIG, the access token and the IopToken, so
that a restart can serve while a source is down. At start-up, the AA application uses the cached
copy and does not fetch the Central Registry lists or the AIG; it fetches them at start-up only when
there is no cached copy (for example, the first start). Never cache private keys (section 1.13).

#### 1.6.1 Central Registry entity lists

- Call `GET <CR base URL>/v2/entityInfo/<type>` for each of `AA`, `FIU` and `FIP`, with
  `Authorization: Bearer <access token>`. The AA needs all three: it sends to, receives from and
  routes for all three types.
- Each response is a top-level JSON array; each element's `entityinfo` gives one participant: `id`,
  `baseurl`, `interop`, `keys.signature` (or `certificate` when that list is empty) and
  `keys.encryption`. The type is the list it is in.
- Use only RSA keys of at least 2048 bits with a `kid`. Skip other keys.
- Each item of `keys.signature` and `keys.encryption` is `{"key": <JWK>, "validFrom", "validTo"}`.
  `validFrom` and `validTo` are optional RFC 3339 timestamps with a time zone, for example
  `2026-11-01T00:00:00Z` or `2026-11-01T05:30:00+05:30`; absent or empty means no limit. Use a key,
  to verify a signature or to encrypt, only while the current time is between its `validFrom` and
  `validTo`, both included. Check this every time a key is used, not only when the lists load, so
  that a key comes into use and goes out of use on time. Skip a key whose `validFrom` or `validTo`
  is not an RFC 3339 timestamp (a date alone included), or whose `validTo` is before its
  `validFrom`. `certificate` has no `validFrom` or `validTo`.
- `interop` absent or not `true` means **not interop ready**.
- The AA application uses the new lists only if all three are fetched and read successfully;
  otherwise it keeps the lists it already has and tries again after 5 minutes.
- A response that is an empty array (`[]`), `null`, or not a JSON array counts as a failed fetch.

#### 1.6.2 AIG (FIU and FIP graphs)

- Call, with `Authorization: Bearer <access token>`:
  - `GET <AIG base URL>/v1/aig/fiu`: `{"fiu": [{"id": "<FIU id>", "connected-AA": [{"id": "<AA id>", "verified": …, "attr": …}]}]}`;
  - `GET <AIG base URL>/v1/aig/fip`: `{"fip": [{"id": "<FIP id>", "inter-AA": [{"id": "<AA id>", "verified": …, "attr": …}]}]}`.
- An AA listed for an FIU is one of its Connected-AAs; an AA listed for a FIP is one of its
  Inter-AAs. The AA may choose to use `verified` or not, for example to prefer verified routes;
  `attr` is not used.
- The AA application uses the new graphs only if both are fetched and read successfully.

#### 1.6.3 What the AA uses from this data

| Need | Data |
|---|---|
| Is the Target (FIU or FIP) interop ready? | Central Registry `interop` |
| Which routes can reach the Target? | AIG, linkedAAs, Central Registry `interop` and `baseurl` |
| Encrypt for the Target (as Initiator) or the Initiator (as Target) | Its `keys.encryption` within their `validFrom` and `validTo` (one chosen at random per message) |
| Verify any participant's signature | Its `keys.signature` within their `validFrom` and `validTo`, matched by `kid` |
| Where to forward, as a hop | The Target's `baseurl` |

#### 1.6.4 Access token

- Get the token with `POST <token service base URL>/entity/token/generate`, form fields `id`
  (the AA's entity id) and `secret` (its entity secret).
- Response: `{"accessToken", "expiresIn", …}`. Errors: `{"errorCode", "errorMsg"}`.
- Get a new token when less than 1 hour of its lifetime remains, or at half its lifetime if it
  lives shorter than that.
- Read the secret from secure storage each time, so that it can be rotated without a restart.
- Never log the token or the secret.

#### 1.6.5 IopToken

The AA holds two tokens from the Sahamati token service, and uses each for its own calls:

| Token | Get it with | Use it for |
|---|---|---|
| Access token (section 1.6.4) | `POST <token service base URL>/entity/token/generate` | Direct API calls to participants the AA is directly connected to; the bearer token for the Central Registry and the AIG |
| IopToken | `POST <token service base URL>/entity/iopToken/generate` | The role api-key on every `/iop` call the AA sends |

- The token service base URL is, for example, `https://token-generation-url/iam/v1`, so the IopToken
  is generated with `POST https://token-generation-url/iam/v1/entity/iopToken/generate`.
- The form fields (`id`, `secret`), the response, the refresh rules and the secrecy rules are those
  of the access token (section 1.6.4). Each token is refreshed on its own.
- Use the **IopToken**, not the access token, whenever the AA acts as Connected-AA, Customer-AA,
  Origin-AA or Inter-AA: in `x-cust_aa_api_key` and `x-orig_aa_api_key` as Initiator (section
  1.7.4), and in `x-conn_aa_api_key` and `x-inter_aa_api_key` as hop (section 1.12.4).
- Use the access token on Direct API calls.
- **Verification procedure:** *To be published.* (How an AA that receives a role api-key checks that
  it is an IopToken.) Until then, received api-keys are checked as in sections 1.11.3 and 1.12.3.

### 1.7 Sending IOP requests (AA as Initiator)

#### 1.7.1 APIs

**To an FIU (the AA as Customer-AA).** Sent to one of the FIU's Connected-AAs, at
`POST <Connected-AA baseurl>/iop/<api>`, with `Target` `{"type": "FIU", ...}` and the role api-key
`x-cust_aa_api_key`.

| IOP API | Encrypted payload of the Direct API | Use |
|---|---|---|
| `POST /iop/Consent/Notification` | `/Consent/Notification` | Consent status notification to the FIU |
| `POST /iop/FI/Notification` | `/FI/Notification` | FI status notification to the FIU |

**To a FIP (the AA as Origin-AA).** Sent to one of the FIP's Inter-AAs, at
`POST <Inter-AA baseurl>/iop/<api>`, with `Target` `{"type": "FIP", ...}` and the role api-key
`x-orig_aa_api_key`.

| IOP API | Encrypted payload of the Direct API | Use |
|---|---|---|
| `POST /iop/Accounts/discover` | `/Accounts/discover` | Account discovery |
| `POST /iop/Accounts/link` | `/Accounts/link` | Account linking |
| `POST /iop/Accounts/link/verify` | `/Accounts/link/verify` | Account link verification |
| `POST /iop/Accounts/link/reverify` | `/Accounts/link/reverify` | Account link re-verification |
| `POST /iop/Accounts/delink` | `/Accounts/delink` | Account delinking |
| `POST /iop/Consent` | `/Consent` | Consent artefact to the FIP |
| `POST /iop/FI/request` | `/FI/request` | FI data request |
| `POST /iop/FI/fetch` | `/FI/fetch` | FI data fetch |
| `POST /iop/Consent/Notification` | `/Consent/Notification` | Consent status notification to the FIP |
| `POST /iop/Heartbeat` | — (no encrypted payload) | Heartbeat towards the FIP |

#### 1.7.2 Correlation id

- Every `/iop/*` message carries a non-empty `correlationId` in standard UUID format.
- The AA creates it when it starts a flow, and keeps it on every message of that flow, retries
  included.
- When the AA answers a request, it uses the `correlationId` it received.
- Participants refuse a message without a `correlationId`, or with one that is not a UUID, with
  `400 InvalidRequest`.

#### 1.7.3 Building the request

For each request, the AA application:

1. **Builds the payload**: exactly the payload of the matching Direct API call (section 1.7.1). It
   must contain `txnid`.
2. **Signs the payload** (inner JWS): a compact JWS over the payload bytes, with one of the AA's
   usable signing keys, its `kid` in the protected header (section 1.14).
3. **Encrypts** the compact JWS for the Target: compact JWE, `RSA-OAEP-256` / `A256GCM`, with one
   of the Target's encryption keys, its `kid` in the JWE header.
4. **Builds the envelope**:

   | Field | Value |
   |---|---|
   | `ver` | The payload's `ver` |
   | `timestamp` | Now, UTC, for example `2026-11-09T10:15:00.000Z` |
   | `txnid` | The id of this transaction between the AA and the route, created by the AA (UUID): the same on retries to that route, a new one for each other route tried. It is **not** the inner payload's `txnid`, which stays inside the encrypted payload for the Target. The route's reply carries the same `txnid` |
   | `correlationId` | The flow's correlation id |
   | `Target` | `{"type": "FIU", "id": "<FIU id>"}` or `{"type": "FIP", "id": "<FIP id>"}` |
   | `encryptedPayload` | The compact JWE |

5. **Signs the envelope** (outer signature): a detached JWS over the exact envelope bytes, in
   `x-jws-signature`.
6. **Chooses a route** (section 1.8) and sends the request.

#### 1.7.4 Request headers

| Header | Mandatory | Value |
|---|---|---|
| `x-cust_aa_api_key` (to an FIU's Connected-AA) or `x-orig_aa_api_key` (to a FIP's Inter-AA) | Yes | The AA's IopToken (section 1.6.5). Send **no other** role api-key header. |
| `x-jws-signature` | Yes | The detached JWS over the envelope (step 5). |
| `Content-Type` | Yes | `application/json` |

#### 1.7.5 Example request

```http
POST /iop/FI/request
x-orig_aa_api_key: <the AA's IopToken>
x-jws-signature: <detached JWS over the body>
Content-Type: application/json

{
  "ver": "2.0.0",
  "timestamp": "2026-11-09T10:15:00.000Z",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
  "Target": {"type": "FIP", "id": "fip-test-001"},
  "encryptedPayload": "<compact JWE>"
}
```

#### 1.7.6 Reading the reply

1. **Check the route's signature**: `x-jws-signature` on the reply must verify over the exact reply
   bytes with the route's signature keys. If it does not, the reply is not used (section 1.10).
2. If the reply has `encryptedPayload` (the Target's response or error; the HTTP status tells them
   apart):
   - **decrypt** it with the AA's usable decryption keys, matched by the JWE `kid`;
   - **check the Target's signature**: the decrypted content must be a compact JWS that verifies
     with the Target's signature keys;
   - **use the payload**: it is exactly the Target's Direct API response (or error), with the
     reply's HTTP status.
3. Otherwise, handle it as in section 1.10.

Keep the Target's inner JWS with the payload where the AA needs it for non-repudiation, as for a
Direct API response.

#### 1.7.7 Heartbeat

- The AA sends `/iop/Heartbeat` to FIPs only: FIUs do not receive heartbeats.
- `POST /iop/Heartbeat` has **no** `encryptedPayload`. As for every `/iop/*` request, the AA sets
  `Target` (the FIP) and sends it to the Inter-AA. The Inter-AA replaces it with `Initiator` (the
  AA) when it forwards the heartbeat to the FIP.

  ```json
  {
    "ver": "1.0.0",
    "timestamp": "2026-11-09T10:15:00.000Z",
    "txnid": "5c7e9a1b-2d4f-4a6c-8e0b-1f3a5c7e9b2d",
    "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
    "Target": {"type": "FIP", "id": "fip-test-001"}
  }
  ```

- Only the outer signature is used; there is no inner JWS.
- The AA creates a new `txnid` for each heartbeat.
- `/iop/Heartbeat` is only for a FIP that is not directly connected: a directly connected FIP is
  checked with the Direct API `GET /Heartbeat`.
- The reply is read as in section 1.7.6.

### 1.8 Choosing the route

#### 1.8.1 Before choosing

The Target must be registered in the Central Registry as an `FIU` or `FIP` (matching the API) and
be interop ready. Otherwise the request is not sent.

#### 1.8.2 Eligible routes

An AA is eligible only if **all** of these hold:

| # | Condition |
|---|---|
| 1 | It is in this AA's linkedAAs. |
| 2 | The AIG lists it as a Connected-AA of the Target FIU, or an Inter-AA of the Target FIP. |
| 3 | It is interop ready in the Central Registry. |
| 4 | It has a `baseurl` in the Central Registry. |
| 5 | It is not this AA itself: if this AA is directly connected to the Target, it uses the Direct APIs. |

If no AA is eligible, the request cannot be sent.

### 1.9 Retries and failover

#### 1.9.1 Rules

1. **Every resend carries the same payload and `correlationId`.** A retry to the same route resends
   the same envelope (same envelope `txnid`); another route gets a new envelope with a new envelope
   `txnid`. A Target can therefore receive a message twice, and must de-duplicate on the payload's
   `txnid`.
2. **Errors from beyond the route are final.** Another route would reach the same Target.
3. **The route may retry too.** It may resend to the Target when the Target does not answer or
   answers `502`/`503`/`504` without `encryptedPayload`, and then answers `IopDownstreamError` (section
   1.12.5). The AA's timeout per attempt should allow for this; otherwise the AA may resend while
   the route is still retrying.
4. **When every route fails**, the request has failed: the AA application reports "all routes
   unavailable" to the flow, and may start it again later (with a new `txnid`).

### 1.10 Outcomes of a request

| Outcome | What the AA application gets |
|---|---|
| Success | The Target's Direct API response, its status and its inner JWS (section 1.7.6). |
| The Target's error (`encryptedPayload` with a `4xx`/`5xx` status) | The Target's Direct API error payload, its status and its inner JWS. |
| The Target's error without a payload (`IopDownstreamError` without `encryptedPayload`) | The status only. |
| Every route failed | "All routes unavailable" (section 1.9.1). |
| Not sent | The Target is not registered or not interop ready; no eligible route; reference data, keys or the IopToken not available; the payload has no `txnid`; signing or encryption failed. |
| The reply cannot be trusted | The route's signature does not verify; `encryptedPayload` cannot be decrypted; the decrypted content is not a compact JWS; the Target's signature does not verify. The reply is **not used**, and the event is logged. |

A reply that cannot be trusted is not retried automatically: the message may already have been
processed by the Target. The flow decides what to do next.

### 1.11 Receiving IOP requests (AA as Target)

#### 1.11.1 APIs the AA must serve

The AA serves these at `<AA baseurl>/iop/<api>`.

**From an FIU (the AA as Customer-AA).** The caller is the FIU's Connected-AA, with
`x-conn_aa_api_key`; the `Initiator` is the FIU (`type` `FIU`).

| IOP API | Method | Encrypted payload of the Direct API | Called for |
|---|---|---|---|
| `/iop/Consent` | `POST` | `/Consent` | Consent request |
| `/iop/Consent/handle` | `POST` | `/Consent/handle` | Consent handle status |
| `/iop/Consent/fetch` | `POST` | `/Consent/fetch` | Consent artefact fetch |
| `/iop/FI/request` | `POST` | `/FI/request` | FI data request |
| `/iop/FI/fetch` | `POST` | `/FI/fetch` | FI data fetch |
| `/iop/Consent/Notification` | `POST` | `/Consent/Notification` | Consent status notification |
| `/iop/User/discover` | `POST` | `/User/discover` | User discovery (section 1.18) |
| `/iop/Heartbeat` | `POST` | — (no encrypted payload) | Heartbeat from the FIU |

**From a FIP (the AA as Origin-AA).** The caller is the FIP's Inter-AA, with
`x-inter_aa_api_key`; the `Initiator` is the FIP (`type` `FIP`).

| IOP API | Method | Encrypted payload of the Direct API | Called for |
|---|---|---|---|
| `/iop/Consent/Notification` | `POST` | `/Consent/Notification` | Consent status notification |
| `/iop/FI/Notification` | `POST` | `/FI/Notification` | FI status notification |
| `/iop/Account/link/Notification` | `POST` | `/Account/link/Notification` | Account link notification |
| `/iop/Heartbeat` | `POST` | — (no encrypted payload) | Heartbeat from the FIP |

The same paths also serve the hop role, with other role api-keys (section 1.12.2). Any other
`/iop/*` path is answered `404 InvalidURI`; another method, `405`.

#### 1.11.2 Request headers received

| Header | Value |
|---|---|
| `x-conn_aa_api_key` or `x-inter_aa_api_key` | The calling Connected-AA's or Inter-AA's api-key: its IopToken from the Sahamati token service (section 1.6.5) |
| `x-jws-signature` | The caller's detached JWS over the envelope |

#### 1.11.3 Checks, in this order

| # | Check | If it fails |
|---|---|---|
| 1 | The path is an `/iop` path the AA serves, with `POST` | `404 InvalidURI` / `405 InvalidRequest` |
| 2 | The body is within the size limit (2 MiB by default) | `413 InvalidRequest` |
| 3 | Exactly one role api-key header is present, and the path accepts it (section 1.12.2) | None or more than one: `401 InvalidSecurity`. Not accepted on the path: `403 InvalidSecurity` |
| 4 | The api-key is a valid token: signature (RS256) with the issuer's public keys (from its JWKS URL) | `401 InvalidSecurity` |
| 5 | The sender is an AA registered in the Central Registry | `401 InvalidSecurity` / `403 InvalidSecurity` |
| 6 | `x-jws-signature` is present and verifies over the exact received bytes with the sender's signature keys, matched by `kid` | `401 InvalidSecurity` (missing) / `401 SignatureDoesNotMatch` |
| 7 | The body is a JSON object with `txnid` and a `correlationId` in standard UUID format | `400 InvalidRequest` |
| 8 | The envelope has `Initiator` (a `Target`, if present, is ignored); `Initiator.type` is `FIU` with `x-conn_aa_api_key` and `FIP` with `x-inter_aa_api_key`; the Initiator is registered | `400 InvalidRequest` |
| 9 | The Initiator has an encryption key in the Central Registry (needed for the reply) | `500 InternalError` |
| 10 | Except for `/iop/Heartbeat`: `encryptedPayload` is a compact JWE that decrypts with one of the AA's usable decryption keys, matched by `kid`, and contains a compact JWS. A heartbeat has no `encryptedPayload` | `400 InvalidRequest` |
| 11 | Except for `/iop/Heartbeat`: the inner JWS verifies with the Initiator's signature keys | `401 SignatureDoesNotMatch`; the request is **not** processed |

Only then is the payload passed to the AA's existing logic. Refresh the issuer's public keys at
start-up, every hour, and when a token names an unknown `kid` (at most once a minute).

#### 1.11.4 Duplicates

The same request can arrive more than once, because hops and Initiators retry and use other
routes. The envelope `txnid` can differ between copies; the payload's `txnid` does not. The AA
**must** de-duplicate on the **payload's** `txnid`: a repeated payload `txnid` is not processed
again, and the earlier response is returned.

The AA may also de-duplicate on the combination of `timestamp` and `txnid`, both from the inner
payload (not the envelope). Both stay the same on every copy of a request, because the Initiator
signed the payload once.

#### 1.11.5 Reply

1. The AA's logic produces the response: exactly the payload of the Direct API response, and an
   HTTP status. For a heartbeat, the AA's status, for example `{"status": "UP"}`.
2. **Sign** it (inner JWS) with one of the AA's usable signing keys.
3. **Encrypt** the compact JWS for the **Initiator** (the FIU or FIP), with one of its encryption
   keys.
4. **Build the reply envelope**:

   | Field | Value |
   |---|---|
   | `ver` | The request's `ver` |
   | `timestamp` | Now, UTC |
   | `txnid` | The request's `txnid` |
   | `correlationId` | The request's `correlationId`, unchanged |
   | `encryptedPayload` | The compact JWE, for a success and an error alike: the HTTP status tells them apart |
   | `errorSource` | On an error reply (status `400` or above) only: `{"type": "AA", "id": "<this AA's id>"}`. The AA sets it, so that the Initiator knows where the error came from |

5. **Sign the envelope** (detached JWS in `x-jws-signature`) and return it with the status.

Errors from the checks in section 1.11.3 are not encrypted: they are a plain
`ErrorResponse` with `errorSource`, signed with `x-jws-signature`:

```json
{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-09T10:15:00.000Z",
  "errorCode": "SignatureDoesNotMatch",
  "errorMsg": "Initiator signature does not verify",
  "errorSource": {"type": "AA", "id": "aa-test-001"}
}
```

`errorMsg` must never contain payload content, keys or token values.

#### 1.11.6 Error codes the AA returns as Target

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | Body not a valid envelope (no `txnid`, no or non-UUID `correlationId`, `Initiator` missing); Initiator of the wrong type for the key, or not registered; `encryptedPayload` not a compact JWE, not decryptable, or without a compact JWS inside; `encryptedPayload` on a heartbeat |
| `401` | `InvalidSecurity` | No role api-key header or more than one; invalid api-key; sender not registered; `x-jws-signature` missing |
| `401` | `SignatureDoesNotMatch` | `x-jws-signature` or the Initiator's inner signature does not verify |
| `403` | `InvalidSecurity` | A role api-key the path does not accept, or a sender whose type does not own the key |
| `404` | `InvalidURI` | Unknown `/iop` path |
| `405` | `InvalidRequest` | Wrong HTTP method |
| `413` | `InvalidRequest` | Body too large |
| `500` | `InternalError` | No encryption key for the Initiator; unable to sign or encrypt the reply |
| `503` | `InternalError` | Central Registry data, decryption keys or issuer keys not loaded yet |

### 1.12 Carrying IOP requests (AA as hop)

As a hop, the AA carries a message between a participant it is directly connected to and another
AA. It **never decrypts** `encryptedPayload`, and **never delivers** a carried message to
its own application logic.

#### 1.12.1 Roles by api-key

The role api-key on the incoming call tells the AA its role on that leg:

| Incoming role api-key | Leg | Envelope | The AA | Outgoing role api-key |
|---|---|---|---|---|
| `client_api_key` | FIU → its Connected-AA | `Target{AA}` (the Customer-AA) | Forwards (hop) | `x-conn_aa_api_key` |
| `x-cust_aa_api_key` | Customer-AA → the FIU's Connected-AA | `Target{FIU}` | Forwards (hop) | `x-conn_aa_api_key` |
| `x-orig_aa_api_key` | Origin-AA → the FIP's Inter-AA | `Target{FIP}` | Forwards (hop) | `x-inter_aa_api_key` |
| `fip_api_key` | FIP → its Inter-AA | `Target{AA}` (the Origin-AA) | Forwards (hop) | `x-inter_aa_api_key` |
| `x-conn_aa_api_key` | Connected-AA → this AA as Customer-AA | `Initiator{FIU}` | Is the Target (section 1.11) | — |
| `x-inter_aa_api_key` | Inter-AA → this AA as Origin-AA | `Initiator{FIP}` | Is the Target (section 1.11) | — |

The sender's type must own the key: `client_api_key` only from an FIU, `fip_api_key` only from a
FIP, and the other keys only from an AA.

#### 1.12.2 Paths and the role api-keys each accepts

| Path | As Target | As hop |
|---|---|---|
| `/iop/Accounts/discover`, `/iop/Accounts/link`, `/iop/Accounts/link/verify`, `/iop/Accounts/link/reverify`, `/iop/Accounts/delink` | — | `x-orig_aa_api_key` |
| `/iop/Account/link/Notification` | `x-inter_aa_api_key` | `fip_api_key` |
| `/iop/Consent`, `/iop/FI/request`, `/iop/FI/fetch` | `x-conn_aa_api_key` | `client_api_key`, `x-orig_aa_api_key` |
| `/iop/Consent/handle`, `/iop/Consent/fetch`, `/iop/User/discover` | `x-conn_aa_api_key` | `client_api_key` |
| `/iop/Consent/Notification` | `x-conn_aa_api_key`, `x-inter_aa_api_key` | `client_api_key`, `x-cust_aa_api_key`, `x-orig_aa_api_key`, `fip_api_key` |
| `/iop/FI/Notification` | `x-inter_aa_api_key` | `x-cust_aa_api_key`, `fip_api_key` |
| `/iop/Heartbeat` | `x-conn_aa_api_key`, `x-inter_aa_api_key` | `client_api_key`, `x-orig_aa_api_key`, `fip_api_key`, and `x-cust_aa_api_key` (but a heartbeat to an FIU is refused, section 1.12.3) |

#### 1.12.3 Checks, in this order

| # | Check | If it fails |
|---|---|---|
| 1 | The path is an `/iop` path the AA serves, with `POST` | `404 InvalidURI` / `405 InvalidRequest` |
| 2 | The body is within the size limit (2 MiB by default) | `413 InvalidRequest` |
| 3 | Exactly one role api-key header is present, and the path accepts it (section 1.12.2) | None or more than one: `401 InvalidSecurity`. Not accepted on the path: `403 InvalidSecurity` |
| 4 | The api-key is a valid token: signature (RS256) with the issuer's public keys (from its JWKS URL) | `401 InvalidSecurity` |
| 5 | The sender is registered in the Central Registry, and its type owns the key (section 1.12.1) | `401 InvalidSecurity` / `403 InvalidSecurity` |
| 6 | `x-jws-signature` is present and verifies over the exact received bytes with the sender's signature keys, matched by `kid` | `401 InvalidSecurity` (missing) / `401 SignatureDoesNotMatch` |
| 7 | The body is a JSON object with `txnid` and a `correlationId` in standard UUID format | `400 InvalidRequest` |
| 8 | The envelope has `Target` (an `Initiator`, if present, is ignored), and `Target.type` matches the leg (section 1.12.1) | `400 InvalidRequest` |
| 9 | The Target is not this AA, `/iop/Heartbeat` included: a directly connected participant uses the Direct APIs | `400 InvalidRequest` |
| 10 | The Target is registered in the Central Registry with that type and a `baseurl` | `400 InvalidRoute`\* |
| 11 | The Target is linked to this AA (see below) | `400 InvalidRoute`\*; the Target is not called. AIG not loaded (FIU or FIP Target), or linkedAAs not loaded (AA Target): `503 InternalError` |
| 12 | A heartbeat's Target is not an FIU: FIUs do not receive heartbeats | `400 InvalidRequest` |
| 13 | Except for `/iop/Heartbeat`: `encryptedPayload` is shaped like a compact JWE (five parts). A heartbeat has no `encryptedPayload` | `400 InvalidRequest` |

A Target is linked to this AA when:

| Target | Linked when |
|---|---|
| FIU | The AIG lists this AA as one of the FIU's Connected-AAs. |
| FIP | The AIG lists this AA as one of the FIP's Inter-AAs. |
| AA (Customer-AA or Origin-AA) | It is in this AA's linkedAAs (section 1.5.2). |

\* `InvalidRoute` tells the sender that this AA cannot route to the Target, so that the sender
tries another route. It is not yet confirmed as a ReBIT IOP error code (section 1.25).

#### 1.12.4 Forwarding

1. **Build a new envelope**:

   | Field | Value |
   |---|---|
   | `ver` | Copied from the request |
   | `timestamp` | Now, UTC |
   | `txnid` | A new UUID for this leg (this AA → the Target), the same on every retry of section 1.12.5 |
   | `correlationId` | Copied unchanged |
   | `Initiator` | The sender, as authenticated by its api-key: `{"type": "<sender type>", "id": "<sender id>"}`. Never taken from the incoming envelope |
   | `encryptedPayload` | Copied unchanged. A heartbeat has none |

2. **Sign** it (detached JWS in `x-jws-signature`) with one of the AA's usable signing keys.
3. **Send** it with `POST <Target baseurl><path>`, with the outgoing role api-key of the leg
   (section 1.12.1) carrying the AA's IopToken (section 1.6.5), `x-jws-signature` and
   `Content-Type: application/json`.
4. **Check the Target's signature** on its response (`x-jws-signature`, over the exact response
   bytes). If it does not verify, answer the sender `502 IopDownstreamError`.

#### 1.12.5 Retries towards the Target

The AA may resend the same envelope to the Target only when the Target does not answer, or answers
`502`, `503` or `504` without `encryptedPayload`; never when the Target's application has answered. The number of retries and the wait between them are the AA's
choice.

| Status from the Target | `encryptedPayload` | Retry allowed | What the sender gets (after the last attempt, if any) |
|---|---|---|---|
| No answer (connection failure) | — | Yes | `502`, `errorCode` `IopDownstreamError`, no `encryptedPayload` |
| No answer (timeout) | — | Yes | `504`, `errorCode` `IopDownstreamError`, no `encryptedPayload` |
| `502`, `503`, `504` | No | Yes | The same status, `errorCode` `IopDownstreamError`, `errorMsg` "No error payload received" |
| `502`, `503`, `504` | Yes | No | The same status, `errorCode` `IopDownstreamError`, the Target's `encryptedPayload` copied unchanged |
| Any other `4xx`/`5xx` | Yes | No | The same status, `errorCode` `IopDownstreamError`, the Target's `encryptedPayload` copied unchanged |
| Any other `4xx`/`5xx` | No | No | The same status, `errorCode` `IopDownstreamError`, `errorMsg` "No error payload received" |
| `2xx`, `3xx` | — | No | The Target's response, signed by this AA |
| Unreadable, too large, or wrongly signed | — | No | `502`, `errorCode` `IopDownstreamError` |

**Timeouts must nest.** The sender waits a limited time for each attempt (30 s by default). Keep
all of this AA's attempts towards the Target within that time. Otherwise the sender may give up and
resend while this AA is still retrying, and the Target receives the message more than once.

#### 1.12.6 Answering the sender

- **Success (`2xx`, `3xx`)**: the Target's response body, with its `txnid` set to the `txnid` of
  the sender's request (the sender's leg), signed by this AA, with the Target's status.
- **Error (`4xx`, `5xx`)**: this body, signed by this AA, with the Target's status:

  ```json
  {
    "ver": "2.0.0",
    "txnid": "<the sender's envelope txnid>",
    "timestamp": "2026-11-09T10:15:00.000Z",
    "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
    "errorCode": "IopDownstreamError",
    "errorMsg": "Target responded with HTTP 400",
    "encryptedPayload": "<the Target's encryptedPayload, copied unchanged>",
    "errorSource": {"type": "FIP", "id": "fip-test-001"}
  }
  ```

  | Field | Value |
  |---|---|
  | `encryptedPayload` | The Target's `encryptedPayload`, copied unchanged. Without one from the Target, it is left out and `errorMsg` is "No error payload received". |
  | `errorSource` | The Target's `errorSource` object, copied unchanged, when the Target's response envelope contains one. Otherwise it is left out. |

- **No usable answer**: `502` or `504` `IopDownstreamError`, as in section 1.12.5.

The sender treats every `IopDownstreamError` as final: another route would reach the same Target.

#### 1.12.7 Error codes the AA returns as hop

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | Body not a valid envelope (no `txnid`, no or non-UUID `correlationId`, `Target` missing); Target of the wrong type for the leg; Target is this AA; heartbeat to an FIU; `encryptedPayload` not shaped like a compact JWE; `encryptedPayload` on a heartbeat |
| `400` | `InvalidRoute` | The Target is not registered in the Central Registry with that type, has no `baseurl`, or is not linked to this AA (section 1.12.3). The Target is not called |
| `401` | `InvalidSecurity` | No role api-key header or more than one; invalid api-key; sender not registered; `x-jws-signature` missing |
| `401` | `SignatureDoesNotMatch` | `x-jws-signature` does not verify |
| `403` | `InvalidSecurity` | A role api-key the path does not accept, or a sender whose type does not own the key |
| `404` | `InvalidURI` | Unknown `/iop` path |
| `405` | `InvalidRequest` | Wrong HTTP method |
| `413` | `InvalidRequest` | Body too large |
| The Target's status | `IopDownstreamError` | The Target answered an error (section 1.12.6) |
| `502` | `IopDownstreamError` | The Target is unreachable, or its response is unreadable, too large or wrongly signed |
| `504` | `IopDownstreamError` | The Target did not answer in time |
| `500` | `InternalError` | Unable to sign or build the envelope |
| `503` | `InternalError` | Central Registry data, the AIG, linkedAAs or issuer keys not loaded yet; IopToken unavailable |

### 1.13 Keys

#### 1.13.1 Key sets

The AA keeps two sets of RSA private keys (at least 2048 bits):

| Set | Used for | How a key is chosen |
|---|---|---|
| Signing keys | Inner JWS and outer `x-jws-signature`, on requests, replies, forwarded envelopes and errors | One usable key **at random** per signature, its `kid` in the header |
| Decryption keys | Decrypting `encryptedPayload` addressed to this AA (never as a hop) | Every usable key, matched by the JWE `kid` |

Each key has:

| Field | Meaning |
|---|---|
| `kid` | Unique in the set; the `kid` under which its public key is published in the Central Registry |
| `active` | `true` to allow use; `false` to keep the key listed but unused |
| `applied` | From when the key may be used |
| `expiry` | Until when it may be used (none = no expiry) |

A key is **usable** while `active`, from `applied` until `expiry`. Check it at every use, so that
rotations can be scheduled in advance. Keep at least one usable key in each set at all times:
without one, the AA cannot sign (and so cannot send, answer or forward anything) or cannot
decrypt.

#### 1.13.2 Rotation order

| Key type | Order |
|---|---|
| Signing | 1. Publish the new public key in the Central Registry. 2. Wait for participants to pick it up (their refresh interval, 6 hours by default). 3. Add the new private key to the set. 4. Set `expiry` (or `active: false`) on the old key. |
| Decryption | 1. Add the new private key to the set first. 2. Publish the new public encryption key in the Central Registry. 3. Keep the old private key until participants have switched (at least their refresh interval). 4. Then set its `expiry` (or `active: false`). |

Set the `validFrom` and `validTo` of the published public keys to match the private keys. A public
signing key's window must cover every time its private key may sign. A public encryption key's
`validTo` must come before its private decryption key is removed. A new public key can be published
ahead of time with a future `validFrom`: participants begin to use it at its `validFrom`, without
waiting for their next refresh.

#### 1.13.3 Protection

- Keep private keys in secure storage, as the AA's key-management policy requires.
- Never write private keys to logs, caches or temporary files, and never return them in an API.
- Log only `kid`, `active`, `applied`, `expiry` and whether a key is usable.

### 1.14 Cryptographic profile and limits

| Item | Requirement |
|---|---|
| JWS | `RS256` only, for both `x-jws-signature` and the inner JWS. `x-jws-signature` is a detached JWS with an unencoded payload (RFC 7797): protected header `{"alg", "kid", "b64": false, "crit": ["b64"]}`, signed over `BASE64URL(header) + "." + <the exact body bytes>`, sent as `header..signature`. The inner JWS inside `encryptedPayload` is a compact JWS with a base64url-encoded payload (RFC 7515). Refuse any other algorithm (`PS256`, `alg: none`, HMAC); an `x-jws-signature` without `"b64": false` and `"crit": ["b64"]`; and an inner JWS with `b64: false` or `crit`. |
| JWE | Compact, `RSA-OAEP-256` / `A256GCM` only. Refuse `zip`. |
| RSA keys | At least 2048 bits, with a `kid`. |
| Signature input | The exact bytes sent or received. Never re-serialise JSON before verifying. |
| Inbound body | At most 2 MiB by default (`413` above). |
| Responses from routes and Targets | At most 64 MiB; larger is treated as no answer. |
| Redirects | Never followed. |
| Timeouts | 30 s per attempt towards a route by default; towards a Target, as a hop, see section 1.12.5. |
| Transport | HTTPS. The role api-key header names contain underscores: any proxy in front of the AA's `/iop` endpoints must pass them (for nginx, `underscores_in_headers on;`). |

### 1.15 Audit records and stats

The AA application should capture audit records and stats for its IOP requests and responses, as
Initiator, Target and hop, as required by its regulatory or internal policy mandates.

### 1.16 Non-functional requirements

| Area | Requirement |
|---|---|
| Data protection | Request and response bodies are never logged. Logs carry only ids, paths, status, lengths and latency. As a hop, the AA never decrypts the content it carries. Test data uses synthetic ids and generated keys only. |
| Secrets | The entity secret, the access token, the IopToken and private keys are kept in secure storage, never in code, configuration files or version control, and never logged. |
| Fail closed | Unknown paths, wrong roles, unregistered or not interop-ready participants, and anything outside the cryptographic profile are refused. |
| Availability of reference data | Cached Central Registry lists, AIG, access token and IopToken let the AA keep working while a source is down. |
| Performance | Targets to be agreed, for the hop role in particular. |

### 1.17 Production and testing

Production uses the live sources. Local alternatives are **for testing only**.

| What | Production | Testing only |
|---|---|---|
| Participants, keys and interop flags | Central Registry | A local list with public key files |
| Connected-AAs of FIUs and Inter-AAs of FIPs | AIG API | A local graph |
| The AA's signing and decryption keys | The AA's secure key storage | Key files |
| Api-key checking of callers | Token issuer's JWKS | Fixed test api-keys |
| The AA's role api-key (IopToken) and access token | Sahamati token service | A fixed test api-key |

### 1.18 User discovery

An FIU discovers which AAs hold a user by sending the same discovery request to every AA it can
reach, in parallel: the Direct API `/User/discover` to the AAs it is linked to, and
`/iop/User/discover` through a Connected-AA to the other interop-ready AAs. The AA takes part in
user discovery in these ways:

| Role | API | Caller and role api-key | What the AA does |
|---|---|---|---|
| Customer-AA (Target) | `POST /iop/User/discover` | The FIU's Connected-AA, with `x-conn_aa_api_key`; `Initiator` is the FIU | Checks the request as in section 1.11.3, decrypts it, looks up the user and answers a `CustDiscoveryResponse` encrypted for the FIU (section 1.11.5) |
| Connected-AA (hop) | `POST /iop/User/discover` | An FIU directly connected to this AA, with `client_api_key`; `Target` is an AA | Checks the request as in section 1.12.3, including the route check (the Target AA is in linkedAAs), and forwards it to the Target with `x-conn_aa_api_key` (sections 1.12.4 to 1.12.6). It never decrypts the content |

The AA also serves the Direct API `POST /User/discover` for the FIUs linked to it, with
`client_api_key` and `x-jws-signature`, and the same payloads in plain form.

#### 1.18.1 Payloads

**Request (`CustDiscoveryRequest`)**: the payload inside `encryptedPayload` on `/iop/User/discover`,
and the body of the Direct API `/User/discover`.

| Field | Value |
|---|---|
| `ver`, `timestamp`, `txnid`, `correlationId` | As in the other Direct APIs. The FIU sends a new `txnid` to each AA and the same `correlationId` to all |
| `customer.vuaHash` | SHA-256 of the VUA as it is, base64url-encoded without padding (User Discovery Hashing Guide, `user-discovery-hashing-guide.md`) |
| `customer.mobileHash` | SHA-256 of the mobile number normalised to `+91` followed by 10 digits, base64url-encoded without padding (User Discovery Hashing Guide) |

At least one of `vuaHash` and `mobileHash` is present.

**Response (`CustDiscoveryResponse`)**: the AA's answer.

| Field | Value |
|---|---|
| `ver`, `timestamp` | As in the other Direct APIs |
| `txnid`, `correlationId` | Those of the request |
| `status` | `User Found` when the AA holds a user that matches the hashes; `User Not Found` otherwise |
| `customerDiscoveryResponse` | One entry per customer address found: `customerAddress`, `maskedMobile`, `vuaAttestation` (section 1.18.3) |

```json
{
  "ver": "2.0.0",
  "timestamp": "2026-11-09T10:15:01.000Z",
  "txnid": "6d1f3b8a-2c4e-4f7a-9b0d-3e5c7a9f1b24",
  "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
  "status": "User Found",
  "customerDiscoveryResponse": [
    {
      "customerAddress": "customer-test-001@aa-test-002",
      "maskedMobile": "XXXXXXXXXX",
      "vuaAttestation": "<VUA attestation>"
    }
  ]
}
```

For `vuaAttestation`, see section 1.23 (VUA attestation procedure and verification).

#### 1.18.2 Rules

- As Customer-AA, `/iop/User/discover` follows every rule of section 1.11: checks, duplicates on
  the payload's `txnid`, and the signed, encrypted reply with the request's `txnid` and
  `correlationId`.
- As Connected-AA, it follows every rule of section 1.12: the new envelope with `Initiator` set to
  the FIU, the `correlationId` and `encryptedPayload` copied unchanged, retries towards the Target, and
  `400 InvalidRoute` for a Target AA that is not in linkedAAs.
- Only the role api-keys of section 1.12.2 are accepted on `/iop/User/discover`; any other key is
  refused with `403 InvalidSecurity` (section 1.25).
- The request and the answer carry hashed and masked customer data: they are never logged
  (section 1.16).

#### 1.18.3 User Hash List

The AA keeps a **User Hash List**: the hash of the user handle (VUA) and the hash of the mobile
number of every customer whose attested handle is held by the AA. The hashes are made as in the
request (section 1.18.1).

| Entry | Value |
|---|---|
| VUA hash | SHA-256 of the VUA as it is, base64url-encoded without padding (User Discovery Hashing Guide, `user-discovery-hashing-guide.md`) |
| Mobile hash | SHA-256 of the customer's mobile number normalised to `+91` followed by 10 digits, base64url-encoded without padding (User Discovery Hashing Guide) |
| VUA | The customer address (user handle) |
| `linkRefNumber` | The link reference number of the attested handle |
| Attestation | The VUA attestation (section 1.23) |

On a user discovery request (the Direct API `/User/discover`, or `/iop/User/discover` as
Customer-AA), the AA:

1. Looks up the request's `customer.vuaHash` and `customer.mobileHash` in the User Hash List.
   When the request carries both, a match on either one is enough.
2. If found, answers `User Found`, with one entry in `customerDiscoveryResponse` per handle found:
   the VUA (`customerAddress`), `maskedMobile` and the attestation (`vuaAttestation`).
3. If not found, answers `User Not Found`, with an empty `customerDiscoveryResponse`.

Keep the list current: add an entry when a customer's attested handle is held by the AA. The list
holds hashed data and links to customer records: keep it in secure storage, and never log it
(section 1.16).

### 1.19 Uploading encryption public keys

*To be written.* How the AA uploads its encryption public keys to the Central Registry (see
section 1.5.1 for why they are needed, and section 1.13.2 for the rotation order).

### 1.20 Marking as interop-ready

*To be written.* How the AA is marked interop ready (`interop: true`) in the Central Registry
(see section 1.5.1).

### 1.21 Error handling

*To be written.* (See section 1.10 for the outcomes of a request, section 1.11.6 for the error
codes the AA returns as Target, and section 1.12.7 for those it returns as hop.)

### 1.22 AA Interoperability Graph (AIG) APIs to look up and update links

*To be written.* (See section 1.6.2 for how the AA reads the AIG, and section 1.5.1 for why its
own links must be published.)

### 1.23 VUA attestation procedure and verification

*To be written.*

### 1.24 Acceptance criteria

Each item must be covered by automated tests with synthetic participants.

| # | Criterion |
|---|---|
| AC-1 | As Initiator, end to end: AA → the FIU's Connected-AA → FIU, and AA → the FIP's Inter-AA → FIP, for each API in section 1.7.1. The AA gets the Target's payload, status and inner JWS. |
| AC-2 | As Initiator: a Target error without a payload gives the AA the status only, with no retry and no other route. |
| AC-3 | As Initiator: only AAs that are in linkedAAs, listed for the Target in the AIG, interop ready, with a `baseurl`, and not this AA are used as routes. A Target that is not interop ready, or no eligible route, stops the request before anything is sent. |
| AC-4 | As Initiator: replies with a wrong route signature, a payload that cannot be decrypted, or a wrong Target signature are not used. |
| AC-5 | As Target, end to end: FIU → Connected-AA → this AA, and FIP → Inter-AA → this AA, for each API in section 1.11.1. The AA's logic gets the Initiator's payload, and the Initiator gets the reply, decrypted and verified. |
| AC-6 | As Target, rejections: tampered body, missing signature, unknown or invalid api-key, a key the path does not accept, two role keys, an Initiator of the wrong type for the key, `Initiator` missing, missing or non-UUID `correlationId`, `encryptedPayload` on a heartbeat, unknown path, wrong method, oversized body. A spoofed Initiator (inner JWS not from the Initiator) is refused with `401 SignatureDoesNotMatch` and not processed. |
| AC-7 | As Target: a repeated payload `txnid` (or, where the AA uses it, a repeated combination of payload `timestamp` and `txnid`) is not processed again and gets the earlier response, even when the envelope `txnid` differs. |
| AC-8 | As hop, end to end for each leg of section 1.12.1: the Target receives the new envelope with `Initiator` set to the sender, a new `txnid`, the `correlationId` and `encryptedPayload` unchanged, signed by this AA; the sender gets the Target's reply, signed by this AA, with its own `txnid`. A false `Initiator` in the incoming envelope is ignored. |
| AC-9 | As hop: `/iop/Accounts/link/reverify` received with `x-orig_aa_api_key` reaches the FIP with `x-inter_aa_api_key`. |
| AC-10 | As hop, rejections: a key the path does not accept, a sender type that does not own the key, `Target` missing or of the wrong type, Target is this AA (heartbeat included), heartbeat to an FIU, `encryptedPayload` not shaped like a JWE; an unregistered Target, or a Target not linked to this AA, gets `400 InvalidRoute` and is not called. The hop never decrypts the content and never calls its own application logic. |
| AC-11 | As hop, retries: a Target that answers `503` without a payload and then succeeds is delivered on a retry; a `503` with `encryptedPayload` is not retried; an unreachable Target gives `502 IopDownstreamError` after any retries. |
| AC-12 | As hop: a Target error with `encryptedPayload` reaches the sender as `IopDownstreamError` with that `encryptedPayload` unchanged, and with the Target's `errorSource` unchanged when present; without `encryptedPayload`, as `IopDownstreamError` with "No error payload received". |
| AC-13 | Keys: signatures use only usable keys, at random; keys join at `applied` and drop at `expiry`; decryption tries keys by `kid`; key material never appears in logs or errors. |
| AC-14 | Cryptographic profile: RS256 round trips work, and a `PS256` signature is refused; `x-jws-signature` is accepted only as RFC 7797 (`b64: false`, `crit: ["b64"]`), and a standard detached JWS there is refused; `alg: none`, HMAC, `b64: false` or `crit` in the inner JWS, `zip` and a `kid` mismatch are refused. |
| AC-15 | Reference data: lookups make no calls to the Central Registry or the AIG; a failed refresh keeps the previous data; a cached copy is served after a restart with the source down. |
| AC-16 | User discovery: as Customer-AA, `/iop/User/discover` with `x-conn_aa_api_key` and `Initiator{FIU}` is answered with a `CustDiscoveryResponse` that decrypts and verifies at the FIU. As Connected-AA, `/iop/User/discover` with `client_api_key` from an FIU is forwarded with `x-conn_aa_api_key` to a Target AA in linkedAAs; a Target AA not in linkedAAs gets `400 InvalidRoute` and is not called. `x-orig_aa_api_key` on this path is refused with `403 InvalidSecurity`. The Direct API `/User/discover` answers a linked FIU with a signed `CustDiscoveryResponse`. |
| AC-17 | Central Registry key windows: a key is used only between its `validFrom` and `validTo`, both included; `validFrom` and `validTo` are RFC 3339 timestamps, and a date alone is skipped; a key whose `validTo` has passed is used neither to verify nor to encrypt; a key with a future `validFrom` comes into use at its `validFrom` without a refresh; a key with `validTo` before `validFrom` is skipped. |
| AC-18 | IopToken: every `/iop` call the AA sends, as Initiator and as hop, carries the IopToken from `/entity/iopToken/generate` as its role api-key; Direct API calls carry the access token; the Central Registry and the AIG are called with the access token. |
| AC-19 | User Hash List: a request whose `vuaHash` or `mobileHash` is in the list is answered `User Found` with the VUA and attestation, and a match on one hash is enough when both are sent; a request with neither in the list is answered `User Not Found`. |

### 1.25 Items to be confirmed

| Item | Status |
|---|---|
| Role api-key header names (`client_api_key`, `fip_api_key`, `x-conn_aa_api_key`, `x-cust_aa_api_key`, `x-orig_aa_api_key`, `x-inter_aa_api_key`) and `Initiator{type: AA}` on the hop → FIU and hop → FIP legs | Subject to the final ReBIT specification for role api-key names |
| `fip_api_key` on `/iop/Consent/Notification` (FIP → Inter-AA) | Accepted, as FIPs send consent notifications; subject to the final ReBIT specification |
| `InvalidRoute` as the error code of a hop that cannot route to the Target | Not yet a ReBIT IOP error code; subject to the final ReBIT specification |
| User discovery APIs (Direct API `/User/discover`, `/iop/User/discover`) and their payloads (`CustDiscoveryRequest`, `CustDiscoveryResponse`) | Proposed by Sahamati in the AA_Interop_1_0_0 "Proposed-1" draft; subject to ReBIT approval |
| The account APIs: `/iop/Accounts/discover`, `/iop/Accounts/link`, `/iop/Accounts/link/verify`, `/iop/Accounts/link/reverify`, `/iop/Accounts/delink` and `/iop/Account/link/Notification` (plural and singular as in the Direct APIs) | Subject to the final ReBIT specification |
| `ver` of the Heartbeat envelope, which has no payload to take it from | `1.0.0` used; subject to the final ReBIT specification |
| IopToken verification procedure (how a received role api-key is checked to be an IopToken) | To be published |
