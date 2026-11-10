# FIU PRD — Interoperability for FIUs

|  |  |
|---|---|
| **Audience** | FIU application teams that build AA Interoperability into their existing FIU application |
| **Version** | Draft 1.8, 2026-11-10 |
| **Published by** | Sahamati |
| **Based on** | AA_Interop_1_0_0 (ReBIT AA Interoperability specification) |

All identifiers, URLs and values in examples are illustrative.

## Contents

| Section | Title | Status |
|---|---|---|
| 1 | Implementation of Interoperability APIs | Draft |
| 2 | Redirection Mechanism for Interoperability | To be written |
| 3 | Customer's UX options | To be written |

---

## Section 1: Implementation of Interoperability APIs

### 1.1 Overview

Today an FIU can serve a customer only through an AA it is directly connected to. AA
Interoperability (IOP) lets the FIU also serve a customer whose AA (the **Customer-AA**) is not
directly connected to it. The FIU sends the request to an AA it is connected to (the
**Connected-AA**), and the Connected-AA carries it to the Customer-AA. Notifications from the
Customer-AA come back the same way.

This section describes what an FIU must build into its **own FIU application** to do this:

- sending `/iop/*` requests to the Customer-AA through a Connected-AA, and reading the replies;
- receiving `/iop/*` notifications from the Customer-AA through a Connected-AA, and answering
  them;
- the IOP security for both: api-keys, signatures, end-to-end encryption;
- choosing the Connected-AA, retrying, and handling errors;
- discovering which AAs hold a user, across linked and other AAs (section 1.17);
- the keys, registry data, tokens and logs this needs.

The payloads are **exactly those of the Direct APIs** the FIU already uses. IOP adds a signed,
encrypted envelope around them and a route through a Connected-AA. Consent and FI business logic
does not change.

#### 1.1.1 Goals

| # | Goal |
|---|---|
| G1 | The FIU can discover a user at, request consent and FI data from, and receive notifications from, a Customer-AA it is not directly connected to. |
| G2 | The FIU application implements every IOP security check: role api-key, sender identity, the Connected-AA's signature, the end-to-end encryption, and the Customer-AA's own signature. |
| G3 | Delivery is resilient: if one Connected-AA fails, another eligible one is tried. |
| G4 | Fail closed: anything outside the cryptographic profile, the wrong role, or an unknown path is refused. |
| G5 | No regulated data is exposed: request and response bodies are never logged, and secrets are never stored in configuration files or code. |

#### 1.1.2 Out of scope for Section 1

| Item | Where |
|---|---|
| Redirecting the customer for interoperability flows | Section 2 of this document |
| The customer's UX options | Section 3 of this document |
| Consent and FI business logic | Unchanged: the FIU application's existing logic |
| Protection against replay beyond signatures and `txnid` de-duplication | Not covered in this release |

### 1.2 Terminology

| Term | Meaning |
|---|---|
| FIU application | The FIU's own application. In this section it includes the new IOP handlers. |
| Direct APIs | The existing ReBIT APIs as of today (for example `/Consent`, `/FI/request`, `/FI/Notification`), which participants call on each other when they are directly connected. IOP carries exactly the same payloads. |
| IOP APIs | The `/iop/*` APIs of AA_Interop_1_0_0. |
| Customer-AA | The AA that holds the customer's account and consent. It is the **Target** of the FIU's requests and the **Initiator** of the notifications the FIU receives. |
| Connected-AA | An AA directly connected to the FIU. It carries `/iop/*` messages between the FIU and other AAs. Also called the route or hop. |
| Target | The participant that finally receives a message. |
| Initiator | The participant that created a message. |
| Route (hop) | The Connected-AA that carries one message. |
| linkedAAs | The AAs the FIU is linked to (has an agreement with). Only these are used as Connected-AAs. |
| Central Registry (CR) | Sahamati's registry of participants: ids, base URLs, public keys and the `interop` (interop ready) flag. |
| AIG | AA Interoperability Graph, published by the Central Registry: which AAs are linked to which AAs. |
| Interop ready | A participant whose `interop` flag in the Central Registry is `true`. |
| Correlation-Id (`correlationId`) | The id of one flow, in **standard UUID format** (RFC 4122, for example `9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94`). The Initiator creates it; it stays the same on every message of the flow. |
| `txnid` | Two different ids. **Payload `txnid`**: the id of one message, as in the Direct APIs; it is the same on every resend, end to end. **Envelope `txnid`**: the id of one transaction between two participants on one leg (for example the FIU and the Connected-AA); it is the same on retries to the same participant, and new for each route and for each leg. |
| Envelope | The JSON body of an `/iop/*` request or response: `ver`, `timestamp`, `txnid`, `correlationId`, `Target` or `Initiator`, and `encryptedData` (none on a heartbeat). `encryptedData` carries the request, and on a reply the response or the error alike: the HTTP status tells them apart. The Initiator sets `Target` and sends it to the hop; the hop replaces it with `Initiator` when it forwards to the Target. The receiver reads only the field its leg needs (`Target` at the hop, `Initiator` at the Target); if the other one is also present, it is ignored. |
| Inner JWS | The Initiator's (or Target's) compact JWS over the Direct API payload, carried encrypted inside `encryptedData`. |
| Outer signature | The detached JWS in the `x-jws-signature` header, over the whole envelope, made by the participant that sends it on that leg. |
| Access token | The FIU's token from the Sahamati token service (`/entity/token/generate`). It is the FIU's api-key on Direct API calls and its bearer token for the Central Registry and the AIG. |
| IopToken | The FIU's IOP token from the Sahamati token service (`/entity/iopToken/generate`). It is the FIU's role api-key on every `/iop` call it sends to Connected-AAs (section 1.6.5). |

### 1.3 Changes needed in the FIU application

"Yes" means needed in production.

| # | Change in the FIU application | Needed | Section |
|---|---|---|---|
| 1 | Register as interop ready in the Central Registry, with the FIU's `/iop` base URL, signature public keys and **encryption public keys**. | Yes | 1.5.1 |
| 2 | Keep the list of linkedAAs (the Connected-AAs the FIU may use). | Yes | 1.5.2 |
| 3 | Load and refresh the Central Registry entity lists and the AIG, and keep a cached copy. | Yes | 1.6 |
| 4 | Get and refresh the FIU's access token and IopToken from the Sahamati token service, and use the IopToken on every `/iop` call. | Yes | 1.6.4, 1.6.5 |
| 5 | Decide per customer: Direct APIs (Customer-AA directly connected) or IOP APIs (not directly connected). | Yes | 1.4 |
| 6 | Create a `correlationId` (UUID) for each new flow, and keep it on every message of that flow. | Yes | 1.7.2 |
| 7 | Build `/iop/*` requests: inner JWS, encryption for the Customer-AA, envelope, outer signature, role api-key `client_api_key`. | Yes | 1.7 |
| 8 | Choose a Connected-AA from the AIG and linkedAAs; retry and fail over to another Connected-AA. | Yes | 1.8, 1.9 |
| 9 | Read replies: check the Connected-AA's signature, decrypt, check the Customer-AA's signature, and handle every error case. | Yes | 1.7.6, 1.10 |
| 10 | Serve `/iop/Consent/Notification` and `/iop/FI/Notification` for Connected-AAs, with all security checks. | Yes | 1.11 |
| 11 | Answer notifications with a signed, encrypted reply for the Customer-AA. | Yes | 1.11.5 |
| 12 | De-duplicate incoming messages on the payload's `txnid`. | Yes | 1.11.4 |
| 13 | Manage signing and decryption key sets with validity dates, and rotate them in the right order. | Yes | 1.12 |
| 14 | Enforce the cryptographic profile and size limits. | Yes | 1.13 |
| 15 | Capture audit records and stats, as required by the FIU's regulatory or internal policy mandates. | Recommended | 1.14 |
| 16 | Discover a user across AAs: the Direct API `/User/discover` to each linked AA and `/iop/User/discover` through a Connected-AA to each other interop-ready AA, in parallel; merge the answers. | Yes | 1.17 |

### 1.4 When to use the IOP APIs

| Situation | What the FIU application does |
|---|---|
| The Customer-AA is **directly connected** to the FIU | Calls the Customer-AA's Direct APIs, as today. |
| The Customer-AA is **not directly connected**, and is interop ready | Calls the IOP API (`/iop/*`) on a Connected-AA, with the Customer-AA as `Target` (section 1.7). |
| The Customer-AA is not directly connected, and is **not** interop ready | Cannot reach it. The flow is not started. |
| A Customer-AA that is not directly connected sends a notification | It arrives on the FIU's `/iop/*` endpoints through a Connected-AA (section 1.11). |
| The FIU needs to know which AAs hold a user | Asks every AA it can reach, with the Direct API or the IOP API, in parallel (section 1.17). |

### 1.5 Prerequisites

#### 1.5.1 Central Registry

The FIU's entry in the Central Registry must have:

| Item | Why |
|---|---|
| `interop: true` | Other participants send to, and accept messages from, interop-ready participants only. |
| `baseurl` | Connected-AAs send `/iop/*` notifications to `<baseurl>/iop/<api>`. |
| Signature public keys (`keys.signature`) | Connected-AAs and Customer-AAs verify the FIU's signatures. Publish the public key of **every** signing key the FIU may use (section 1.12). |
| Encryption public keys (`keys.encryption`) | Customer-AAs encrypt replies and notifications for the FIU. |

Each key in `keys.signature` and `keys.encryption` is published with an optional validity window, as
`{"key": <JWK>, "validFrom", "validTo"}`. Other participants use a key only between its `validFrom`
and `validTo`, so the window must cover the whole time the key is in use (section 1.12.2).

#### 1.5.2 linkedAAs

The FIU keeps the list of AAs it is linked to. A Connected-AA is used only if it is in this list.
The list must not be empty and must not repeat an id. When it changes, the new list is used for the
next message.

#### 1.5.3 Credentials

The FIU's entity credentials for the Sahamati token service are kept in secure storage, never in
code or in configuration files (section 1.6.4).

### 1.6 Reference data

The FIU application loads this data in the background and serves every lookup from memory. It
**never calls the Central Registry or the AIG per message.**

| Data | Source | Refresh | On failure |
|---|---|---|---|
| AAs: ids, base URLs, public keys, `interop` flag | Central Registry `GET /v2/entityInfo/AA` | Every 6 hours | Keep the previous list; retry after 5 minutes |
| Which AAs are linked to which AAs | AIG `GET /v1/aig/aa` | Every 6 hours | Keep the previous graph; retry after 5 minutes |
| linkedAAs | The FIU's own list (section 1.5.2) | When it changes | Keep the current list |
| Access token | Sahamati token service | Before it expires | Keep the current token until it expires; retry at most every 10 seconds |
| IopToken | Sahamati token service | Before it expires | Keep the current token until it expires; retry at most every 10 seconds |

Keep a cached copy of the Central Registry AA list, the AIG, the access token and the IopToken, so
that a restart can serve while a source is down. At start-up, the FIU application uses the cached
copy and does not fetch the Central Registry AA list or the AIG; it fetches them at start-up only
when there is no cached copy (for example, the first start). Never cache private keys (section
1.12).

#### 1.6.1 Central Registry AA list

- Call `GET <CR base URL>/v2/entityInfo/AA` with `Authorization: Bearer <access token>`. The FIU
  needs only AAs: the Connected-AAs and the Customer-AAs. It does not fetch the FIU or FIP lists.
- The response is a top-level JSON array; each element's `entityinfo` gives one participant:
  `id`, `baseurl`, `interop`, `keys.signature` (or `certificate` when that list is empty) and
  `keys.encryption`.
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
- The FIU application uses the new list only if it is fetched and read successfully; otherwise it
  keeps the list it already has and tries again after 5 minutes.
- A response that is an empty array (`[]`), `null`, or not a JSON array counts as a failed fetch.

#### 1.6.2 AIG (AA graph)

- Call `GET <AIG base URL>/v1/aig/aa` with `Authorization: Bearer <access token>`.
- Response: `{"aa": [{"id": "<aa id>", "peer-AA": [{"id": "<aa id>", "verified": …, "attr": …}]}]}`.
  It lists only AAs and the AAs each is linked to (no FIUs or FIPs).
- Two AAs are linked if either lists the other (both directions count). `verified` does not change
  the route order; `attr` is not used.

#### 1.6.3 What the FIU uses from this data

| Need | Data |
|---|---|
| Is the Customer-AA interop ready? | Central Registry `interop` |
| Which Connected-AAs can reach the Customer-AA? | AIG, linkedAAs, Central Registry `interop` and `baseurl` |
| Encrypt for the Customer-AA | Customer-AA's `keys.encryption` within their `validFrom` and `validTo` (one chosen at random per message) |
| Verify the Connected-AA's and the Customer-AA's signatures | Their `keys.signature` within their `validFrom` and `validTo`, matched by `kid` |

#### 1.6.4 Access token

- Get the token with `POST <token service base URL>/entity/token/generate`, form fields `id`
  (the FIU's entity id) and `secret` (its entity secret).
- Response: `{"accessToken", "expiresIn", …}`. Errors: `{"errorCode", "errorMsg"}`.
- Get a new token when less than 1 hour of its lifetime remains, or at half its lifetime if it
  lives shorter than that.
- Read the secret from secure storage each time, so that it can be rotated without a restart.
- Never log the token or the secret.

#### 1.6.5 IopToken

The FIU holds two tokens from the Sahamati token service, and uses each for its own calls:

| Token | Get it with | Use it for |
|---|---|---|
| Access token (section 1.6.4) | `POST <token service base URL>/entity/token/generate` | Direct API calls, such as `/User/discover` to the AAs the FIU is linked to (section 1.17.3); the bearer token for the Central Registry and the AIG |
| IopToken | `POST <token service base URL>/entity/iopToken/generate` | The role api-key `client_api_key` on every `/iop` call the FIU sends |

- The token service base URL is, for example, `https://token-generation-url/iam/v1`, so the IopToken
  is generated with `POST https://token-generation-url/iam/v1/entity/iopToken/generate`.
- The form fields (`id`, `secret`), the response, the refresh rules and the secrecy rules are those
  of the access token (section 1.6.4). Each token is refreshed on its own.
- Use the **IopToken**, not the access token, as the role api-key `client_api_key` on every `/iop`
  call to a Connected-AA (section 1.7.4).
- **Receiving.** The api-key `x-conn_aa_api_key` that the Connected-AA sends on an `/iop` call to
  the FIU is the Connected-AA's IopToken. The FIU must verify that it is a hop token (an IopToken).
  **Verification procedure:** *To be published.* Until then, the api-key is checked as in section
  1.11.3.

### 1.7 Sending IOP requests (FIU as Initiator)

#### 1.7.1 APIs

The FIU sends these to a Connected-AA, at `POST <Connected-AA baseurl>/iop/<api>`. The `Target` is
always the Customer-AA (`type` `AA`).

| IOP API | Encrypted payload of the Direct API | Use |
|---|---|---|
| `POST /iop/Consent` | `/Consent` | Consent request to the Customer-AA |
| `POST /iop/Consent/handle` | `/Consent/handle` | Consent handle status |
| `POST /iop/Consent/fetch` | `/Consent/fetch` | Fetch a consent artefact |
| `POST /iop/FI/request` | `/FI/request` | FI data request |
| `POST /iop/FI/fetch` | `/FI/fetch` | FI data fetch |
| `POST /iop/Consent/Notification` | `/Consent/Notification` | Consent status notification to the Customer-AA |
| `POST /iop/User/discover` | `/User/discover` | User discovery at an AA that is not directly connected (section 1.17) |
| `POST /iop/Heartbeat` | — (no encrypted payload) | Heartbeat towards the Customer-AA |

#### 1.7.2 Correlation id

- Every `/iop/*` message carries a non-empty `correlationId` in standard UUID format.
- The FIU creates it when it starts a flow, and keeps it on every message of that flow, retries
  included.
- When the FIU answers a notification, it uses the `correlationId` it received.
- Participants refuse a message without a `correlationId`, or with one that is not a UUID, with
  `400 InvalidRequest`.

#### 1.7.3 Building the request

For each request, the FIU application:

1. **Builds the payload**: exactly the payload of the matching Direct API call (section 1.7.1). It
   must contain `txnid`.
2. **Signs the payload** (inner JWS): a compact JWS over the payload bytes, with one of the FIU's
   usable signing keys, its `kid` in the protected header (section 1.13).
3. **Encrypts** the compact JWS for the Customer-AA: compact JWE, `RSA-OAEP-256` / `A256GCM`, with
   one of the Customer-AA's encryption keys, its `kid` in the JWE header.
4. **Builds the envelope**:

   | Field | Value |
   |---|---|
   | `ver` | The payload's `ver` |
   | `timestamp` | Now, UTC, for example `2026-11-08T10:15:00.000Z` |
   | `txnid` | The id of this transaction between the FIU and the Connected-AA, created by the FIU (UUID): the same on retries to that Connected-AA, a new one for each other Connected-AA tried. It is **not** the inner payload's `txnid`, which stays inside the encrypted payload for the Customer-AA. The Connected-AA's reply carries the same `txnid` |
   | `correlationId` | The flow's correlation id |
   | `Target` | `{"type": "AA", "id": "<Customer-AA id>"}` |
   | `encryptedData` | The compact JWE |

5. **Signs the envelope** (outer signature): a detached JWS over the exact envelope bytes, in
   `x-jws-signature`.
6. **Chooses a Connected-AA** (section 1.8) and sends the request.

#### 1.7.4 Request headers

| Header | Mandatory | Value |
|---|---|---|
| `client_api_key` | Yes | The FIU's IopToken (section 1.6.5). It is the FIU's role api-key towards a Connected-AA. Send **no other** role api-key header. |
| `x-jws-signature` | Yes | The detached JWS over the envelope (step 5). |
| `Content-Type` | Yes | `application/json` |

#### 1.7.5 Example request

```http
POST /iop/FI/request
client_api_key: <the FIU's IopToken>
x-jws-signature: <detached JWS over the body>
Content-Type: application/json

{
  "ver": "2.0.0",
  "timestamp": "2026-11-08T10:15:00.000Z",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
  "Target": {"type": "AA", "id": "aa-test-002"},
  "encryptedData": "<compact JWE>"
}
```

#### 1.7.6 Reading the reply

1. **Check the Connected-AA's signature**: `x-jws-signature` on the reply must verify over the
   exact reply bytes with the Connected-AA's signature keys. If it does not, the reply is not used
   (section 1.10).
2. If the reply has `encryptedData` (the Customer-AA's response or error; the HTTP status tells them
   apart):
   - **decrypt** it with the FIU's usable decryption keys, matched by the JWE `kid`;
   - **check the Customer-AA's signature**: the decrypted content must be a compact JWS that
     verifies with the Customer-AA's signature keys;
   - **use the payload**: it is exactly the Customer-AA's Direct API response (or error), with
     the reply's HTTP status.
3. Otherwise, handle it as in section 1.10.

Keep the Customer-AA's inner JWS with the payload where the FIU needs it for non-repudiation, as
for a Direct API response.

#### 1.7.7 Heartbeat

- `POST /iop/Heartbeat` has **no** `encryptedData`. As for every `/iop/*` request, the FIU
  sets `Target` (the Customer-AA) and sends it to the Connected-AA. The Connected-AA replaces it with `Initiator` (the FIU) when it forwards the
  heartbeat to the Customer-AA.

  ```json
  {
    "ver": "1.0.0",
    "timestamp": "2026-11-08T10:15:00.000Z",
    "txnid": "5c7e9a1b-2d4f-4a6c-8e0b-1f3a5c7e9b2d",
    "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
    "Target": {"type": "AA", "id": "aa-test-002"}
  }
  ```

- Only the outer signature is used; there is no inner JWS.
- The FIU creates a new `txnid` for each heartbeat.
- The Target is never the Connected-AA itself: to check a directly connected AA, the FIU uses the Direct API `GET /Heartbeat`.
- The reply is read as in section 1.7.6.
- The FIU does **not** receive heartbeats: Connected-AAs refuse a heartbeat with an FIU as Target.

### 1.8 Choosing the Connected-AA (route)

#### 1.8.1 Before choosing

The Customer-AA must be registered in the Central Registry as an `AA` and be interop ready.
Otherwise the request is not sent.

#### 1.8.2 Eligible Connected-AAs

An AA is eligible only if **all** of these hold:

| # | Condition |
|---|---|
| 1 | It is in the FIU's linkedAAs. |
| 2 | The AIG links it to the Customer-AA, in either direction. |
| 3 | It is interop ready in the Central Registry. |
| 4 | It has a `baseurl` in the Central Registry. |
| 5 | It is not the Customer-AA itself. This applies to `/iop/Heartbeat` too: a directly connected AA is checked with the Direct API `GET /Heartbeat`. |

If no AA is eligible, the request cannot be sent.

### 1.9 Retries and failover

#### 1.9.1 Rules

1. **Every resend carries the same payload and `correlationId`.** A retry to the same Connected-AA
   resends the same envelope (same envelope `txnid`); another Connected-AA gets a new envelope with
   a new envelope `txnid`. A Customer-AA can therefore receive a message twice, and must
   de-duplicate on the payload's `txnid`.
2. **Errors from beyond the Connected-AA are final.** A reply with `encryptedData`, or with
   `errorCode` `IopDownstreamError`, is the Customer-AA's answer, or says that the Customer-AA could
   not be reached. Another Connected-AA would reach the same Customer-AA.
3. **Any other error from the Connected-AA means: try the next route.** An error answer without
   `encryptedData` and with another `errorCode` (for example `400 InvalidRoute`, when the Connected-AA
   cannot route to the Customer-AA) comes from the Connected-AA itself. The FIU tries the next eligible
   Connected-AA.
4. **The Connected-AA may retry too.** It may resend to the Customer-AA when the Customer-AA does not
   answer or answers `502`/`503`/`504` without `encryptedData`, and then answers `IopDownstreamError`. The
   FIU's timeout per attempt should allow for this; otherwise the FIU may resend while the
   Connected-AA is still retrying.
5. **When every route fails**, the request has failed: the FIU application reports "all routes
   unavailable" to the flow, and may start it again later (with a new `txnid`).

### 1.10 Outcomes of a request

| Outcome | What the FIU application gets |
|---|---|
| Success | The Customer-AA's Direct API response, its status and its inner JWS (section 1.7.6). |
| The Customer-AA's error (`encryptedData` with a `4xx`/`5xx` status) | The Customer-AA's Direct API error payload, its status and its inner JWS. |
| The Customer-AA's error without a payload (`IopDownstreamError` without `encryptedData`) | The status only. |
| Every route failed | "All routes unavailable" (section 1.9.1). |
| Not sent | The Customer-AA is not registered or not interop ready; no eligible Connected-AA; reference data, keys or the IopToken not available; the payload has no `txnid`; signing or encryption failed. |
| The reply cannot be trusted | The Connected-AA's signature does not verify; `encryptedData` cannot be decrypted; the decrypted content is not a compact JWS; the Customer-AA's signature does not verify. The reply is **not used**, and the event is logged. |

A reply that cannot be trusted is not retried automatically: the message may already have been
processed by the Customer-AA. The flow decides what to do next, for example a status check with
`/iop/Consent/handle`.

### 1.11 Receiving IOP requests (FIU as Target)

#### 1.11.1 APIs the FIU must serve

The FIU serves these at `<FIU baseurl>/iop/<api>`. The caller is always a Connected-AA; the
`Initiator` is the Customer-AA.

| IOP API | Method | Encrypted payload of the Direct API | Called for |
|---|---|---|---|
| `/iop/Consent/Notification` | `POST` | `/Consent/Notification` | Consent status notification from the Customer-AA |
| `/iop/FI/Notification` | `POST` | `/FI/Notification` | FI status notification from the Customer-AA |

Any other `/iop/*` path is answered `404 InvalidURI`; another method, `405`. The FIU does not serve
`/iop/Heartbeat`.

#### 1.11.2 Request headers received

| Header | Value |
|---|---|
| `x-conn_aa_api_key` | The Connected-AA's api-key: its IopToken from the Sahamati token service (section 1.6.5) |
| `x-jws-signature` | The Connected-AA's detached JWS over the envelope |

#### 1.11.3 Checks, in this order

| # | Check | If it fails |
|---|---|---|
| 1 | The path is one of section 1.11.1, with `POST` | `404 InvalidURI` / `405 InvalidRequest` |
| 2 | The body is within the size limit (2 MiB by default) | `413 InvalidRequest` |
| 3 | Exactly one role api-key header is present, and it is `x-conn_aa_api_key` | None or more than one: `401 InvalidSecurity`. Another key: `403 InvalidSecurity` |
| 4 | The api-key is a valid token: signature (RS256) with the issuer's public keys (from its JWKS URL) | `401 InvalidSecurity` |
| 5 | The sender is an AA registered in the Central Registry | `401 InvalidSecurity` / `403 InvalidSecurity` |
| 6 | `x-jws-signature` is present and verifies over the exact received bytes with the sender's signature keys, matched by `kid` | `401 InvalidSecurity` (missing) / `401 SignatureDoesNotMatch` |
| 7 | The body is a JSON object with `txnid` and a `correlationId` in standard UUID format | `400 InvalidRequest` |
| 8 | The envelope has `Initiator` (a `Target`, if present, is ignored); `Initiator.type` is `AA`, and the Initiator is registered | `400 InvalidRequest` |
| 9 | The Initiator has an encryption key in the Central Registry (needed for the reply) | `500 InternalError` |
| 10 | `encryptedData` is a compact JWE that decrypts with one of the FIU's usable decryption keys, matched by `kid`, and contains a compact JWS | `400 InvalidRequest` |
| 11 | The inner JWS verifies with the Initiator's signature keys | `401 SignatureDoesNotMatch`; the notification is **not** processed |

Only then is the payload passed to the FIU's existing notification logic. Refresh the issuer's
public keys at start-up, every hour, and when a token names an unknown `kid` (at most once a
minute).

#### 1.11.4 Duplicates

The same notification can arrive more than once, because Connected-AAs and Customer-AAs retry and
use other routes. The envelope `txnid` can differ between copies; the payload's `txnid` does not.
The FIU **must** de-duplicate on the **payload's** `txnid`: a repeated payload `txnid` is not
processed again, and the earlier response is returned.

The FIU may also de-duplicate on the combination of `timestamp` and `txnid`, both from the inner
payload (not the envelope). Both stay the same on every copy of a notification, because the
Customer-AA signed the payload once.

#### 1.11.5 Reply

1. The FIU's logic produces the response: exactly the payload of the Direct API response, and an
   HTTP status.
2. **Sign** it (inner JWS) with one of the FIU's usable signing keys.
3. **Encrypt** the compact JWS for the **Initiator** (the Customer-AA), with one of its encryption
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

Errors from the checks in section 1.11.3 are not encrypted: they are a plain `ErrorResponse`,
signed with `x-jws-signature`:

```json
{
  "ver": "2.0.0",
  "txnid": "3f2b8c1e-7d4a-4c9e-9b1f-2a6d5e8c4b71",
  "timestamp": "2026-11-08T10:15:00.000Z",
  "errorCode": "SignatureDoesNotMatch",
  "errorMsg": "Initiator signature does not verify"
}
```

`errorMsg` must never contain payload content, keys or token values.

#### 1.11.6 Error codes the FIU returns on `/iop/*`

| Status | `errorCode` | When |
|---|---|---|
| `400` | `InvalidRequest` | Body not a valid envelope (no `txnid`, no or non-UUID `correlationId`, `Initiator` missing); Initiator not an AA or not registered; `encryptedData` not a compact JWE, not decryptable, or without a compact JWS inside |
| `401` | `InvalidSecurity` | No role api-key header or more than one; invalid api-key; sender not registered; `x-jws-signature` missing |
| `401` | `SignatureDoesNotMatch` | `x-jws-signature` or the Initiator's inner signature does not verify |
| `403` | `InvalidSecurity` | A role api-key other than `x-conn_aa_api_key`, or the sender is not an AA |
| `404` | `InvalidURI` | Unknown `/iop` path |
| `405` | `InvalidRequest` | Wrong HTTP method |
| `413` | `InvalidRequest` | Body too large |
| `500` | `InternalError` | No encryption key for the Initiator; unable to sign or encrypt the reply |
| `503` | `InternalError` | Central Registry data, decryption keys or issuer keys not loaded yet |

### 1.12 Keys

#### 1.12.1 Key sets

The FIU keeps two sets of RSA private keys (at least 2048 bits):

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
without one, the FIU cannot sign (and so cannot send or answer anything) or cannot decrypt.

#### 1.12.2 Rotation order

| Key type | Order |
|---|---|
| Signing | 1. Publish the new public key in the Central Registry. 2. Wait for participants to pick it up (their refresh interval, 6 hours by default). 3. Add the new private key to the set. 4. Set `expiry` (or `active: false`) on the old key. |
| Decryption | 1. Add the new private key to the set first. 2. Publish the new public encryption key in the Central Registry. 3. Keep the old private key until participants have switched (at least their refresh interval). 4. Then set its `expiry` (or `active: false`). |

Set the `validFrom` and `validTo` of the published public keys to match the private keys. A public
signing key's window must cover every time its private key may sign. A public encryption key's
`validTo` must come before its private decryption key is removed. A new public key can be published
ahead of time with a future `validFrom`: participants begin to use it at its `validFrom`, without
waiting for their next refresh.

#### 1.12.3 Protection

- Keep private keys in secure storage, as the FIU's key-management policy requires.
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
| Replies from Connected-AAs | At most 64 MiB; larger is treated as no answer. |
| Redirects | Never followed. |
| Timeouts | 30 s per attempt towards a Connected-AA by default. |
| Transport | HTTPS. The role api-key header names contain underscores: any proxy in front of the FIU's `/iop` endpoints must pass them (for nginx, `underscores_in_headers on;`). |

### 1.14 Audit records and stats

The FIU application should capture audit records and stats for its IOP requests and responses, as
required by its regulatory or internal policy mandates.

### 1.15 Non-functional requirements

| Area | Requirement |
|---|---|
| Data protection | Request and response bodies are never logged. Logs carry only ids, paths, status, lengths and latency. Test data uses synthetic ids and generated keys only. |
| Secrets | The entity secret, the access token, the IopToken and private keys are kept in secure storage, never in code, configuration files or version control, and never logged. |
| Fail closed | Unknown paths, wrong roles, unregistered or not interop-ready participants, and anything outside the cryptographic profile are refused. |
| Availability of reference data | Cached Central Registry AA list, AIG, access token and IopToken let the FIU keep working while a source is down. |
| Performance | Targets to be agreed. |

### 1.16 Production and testing

Production uses the live sources. Local alternatives are **for testing only**.

| What | Production | Testing only |
|---|---|---|
| Participants, keys and interop flags | Central Registry | A local list with public key files |
| Which AAs are linked to which | AIG API | A local graph |
| The FIU's signing and decryption keys | The FIU's secure key storage | Key files |
| Api-key checking of Connected-AAs | Token issuer's JWKS | Fixed test api-keys |
| The FIU's role api-key (IopToken) and access token | Sahamati token service | A fixed test api-key |

### 1.17 User discovery

User discovery tells the FIU which AAs hold a user, and under which customer addresses. The FIU
sends the same discovery request to every AA it can reach, in parallel, and merges the answers.

| API | Sent to | Used for |
|---|---|---|
| Direct API `POST /User/discover` | `<AA baseurl>/User/discover` | Each AA in the FIU's linkedAAs |
| `POST /iop/User/discover` | `<Connected-AA baseurl>/iop/User/discover`, with the AA as `Target` | Each AA that is not in linkedAAs and is interop ready |

#### 1.17.1 Payloads

**Request (`CustDiscoveryRequest`)**: the body of the Direct API `/User/discover`, and the payload
inside `encryptedData` on `/iop/User/discover`.

| Field | Value |
|---|---|
| `ver` | API version |
| `timestamp` | Now, UTC |
| `txnid` | The id of this request (UUID): a new one for each AA asked (section 1.17.3) |
| `correlationId` | The discovery flow's correlation id (UUID): the same for every AA asked |
| `customer.vuaHash` | SHA-256 of the canonicalised VUA, base64url-encoded |
| `customer.mobileHash` | SHA-256 of the mobile number in E.164 format, base64url-encoded |

At least one of `vuaHash` and `mobileHash` is present.

```json
{
  "ver": "2.0.0",
  "timestamp": "2026-11-09T10:15:00.000Z",
  "txnid": "6d1f3b8a-2c4e-4f7a-9b0d-3e5c7a9f1b24",
  "correlationId": "9a1c6e2f-4b7d-4e8a-a3c5-1f0b2d7e6c94",
  "customer": {"vuaHash": "synthetic-vua-hash", "mobileHash": "synthetic-mobile-hash"}
}
```

**Response (`CustDiscoveryResponse`)**: the AA's answer.

| Field | Value |
|---|---|
| `ver`, `timestamp` | As in the Direct APIs |
| `txnid`, `correlationId` | Those of the request |
| `status` | `User Found` or `User Not Found` |
| `customerDiscoveryResponse` | One entry per customer address found: `customerAddress`, `maskedMobile`, `vuaAttestation` |

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

For the verification of `vuaAttestation`, see section 1.22 (VUA attestation verification procedure).

#### 1.17.2 Which AAs are asked

The FIU goes through the AAs in its Central Registry AA list (the cached copy, section 1.6.1):

| AA | How it is asked |
|---|---|
| In linkedAAs | Direct API `POST <AA baseurl>/User/discover` (section 1.17.3) |
| Not in linkedAAs, interop ready | `POST /iop/User/discover` through an eligible Connected-AA, with the AA as `Target` (section 1.17.4) |
| Not in linkedAAs, not interop ready | Not asked |

#### 1.17.3 Direct API `/User/discover` (linked AAs)

- Body: the `CustDiscoveryRequest`, not encrypted, as for the other Direct APIs.
- Headers:

  | Header | Value |
  |---|---|
  | `client_api_key` | The FIU's access token (section 1.6.4), not the IopToken |
  | `x-jws-signature` | A detached JWS over the exact body, with one of the FIU's usable signing keys |
  | `Content-Type` | `application/json` |

- The answer is used only if its status is `200` and its `x-jws-signature` verifies over the exact
  response bytes with the AA's signature keys from the Central Registry.

#### 1.17.4 `/iop/User/discover` (other interop-ready AAs)

`/iop/User/discover` follows the same rules as the other IOP requests of this section:

- the `CustDiscoveryRequest` is signed (inner JWS) and encrypted for the AA in `encryptedData`
  (section 1.7.3);
- the headers are those of section 1.7.4 (`client_api_key`, `x-jws-signature`);
- the Connected-AA is chosen as in section 1.8, with retries and failover as in section 1.9;
- the reply is read as in section 1.7.6: its decrypted payload is the AA's `CustDiscoveryResponse`.

#### 1.17.5 Sending, waiting and merging

1. **One request per AA, in parallel.** Each request carries its own new `txnid` and the same
   `correlationId`. The rest of the `CustDiscoveryRequest` is the same for every AA.
2. **Wait** until every AA asked has answered, or until a configurable time has passed (for example,
   10 seconds). Answers that arrive later are ignored.
3. **Merge** the `customerDiscoveryResponse` entries of every answer whose `status` is
   `User Found`. The merged result has `status` `User Found` when it has at least one entry, and
   `User Not Found` with no entries otherwise.
4. An AA whose request fails (error, reply that cannot be trusted, all routes unavailable, no answer
   in time) adds nothing to the result. When no AA answers successfully, the discovery has failed:
   this is reported to the flow as "all routes unavailable", not as `User Not Found`.

The request and the answers carry hashed and masked customer data: they are never logged
(section 1.15).

### 1.18 Uploading encryption public keys

*To be written.* How the FIU uploads its encryption public keys to the Central Registry (see
section 1.5.1 for why they are needed, and section 1.12.2 for the rotation order).

### 1.19 Marking as interop-ready

*To be written.* How the FIU is marked interop ready (`interop: true`) in the Central Registry
(see section 1.5.1).

### 1.20 Error handling

*To be written.* (See section 1.10 for the outcomes of a request, and section 1.11.6 for the
error codes the FIU returns on `/iop/*`.)

### 1.21 AA Interoperability Graph (AIG) APIs to look up

*To be written.* (See section 1.6.2 for how the FIU reads the AIG.)

### 1.22 VUA attestation verification procedure

*To be written.*

### 1.23 Acceptance criteria

Each item must be covered by automated tests with synthetic participants.

| # | Criterion |
|---|---|
| AC-1 | End to end: FIU → Connected-AA → Customer-AA for each API in section 1.7.1. The FIU gets the Customer-AA's payload, status and inner JWS. |
| AC-2 | A Customer-AA error reaches the FIU as its decrypted error payload, with its status. |
| AC-3 | A Customer-AA error without a payload gives the FIU the status only, with no retry and no other route. |
| AC-4 | Route choice: only AAs that are in linkedAAs, linked to the Customer-AA in the AIG, interop ready and with a `baseurl` are used. |
| AC-5 | A Customer-AA that is not interop ready, or no eligible Connected-AA, stops the request before anything is sent. |
| AC-6 | Replies with a wrong Connected-AA signature, a payload that cannot be decrypted, or a wrong Customer-AA signature are not used. |
| AC-7 | Heartbeat: sent as a `POST` with `Target` and no `encryptedData`; the reply is decrypted and verified. |
| AC-8 | Notifications: `/iop/Consent/Notification` and `/iop/FI/Notification` from a Connected-AA are processed, and the reply decrypts and verifies at the Customer-AA. |
| AC-9 | Notification rejections: tampered body, missing signature, unknown or invalid api-key, a role key other than `x-conn_aa_api_key`, two role keys, sender not an AA, `Initiator` missing from the envelope, missing or non-UUID `correlationId`, unknown path, wrong method, oversized body. |
| AC-10 | A spoofed Initiator (inner JWS not from the Initiator) is refused with `401 SignatureDoesNotMatch` and the notification is not processed. |
| AC-11 | A repeated payload `txnid` (or, where the FIU uses it, a repeated combination of payload `timestamp` and `txnid`) is not processed again and gets the earlier response, even when the envelope `txnid` differs. |
| AC-12 | Keys: signatures use only usable keys, at random; keys join at `applied` and drop at `expiry`; decryption tries keys by `kid`; key material never appears in logs or errors. |
| AC-13 | Cryptographic profile: RS256 and PS256 round trips work; `alg: none`, HMAC, `b64: false`, `crit`, `zip` and a `kid` mismatch are refused. |
| AC-14 | Reference data: lookups make no calls to the Central Registry or the AIG; a failed refresh keeps the previous data; a cached copy is served after a restart with the source down. |
| AC-15 | User discovery: each linked AA gets the Direct API `/User/discover` with `client_api_key` and `x-jws-signature`; each other interop-ready AA gets `/iop/User/discover` through a Connected-AA; AAs that are not interop ready are not asked. The requests go in parallel, each with its own `txnid` and the same `correlationId`. The `customerDiscoveryResponse` entries of the `User Found` answers received within the wait time are merged; a Direct API answer that is not `200` or whose signature does not verify is not used; no successful answer gives "all routes unavailable". |
| AC-16 | Central Registry key windows: a key is used only between its `validFrom` and `validTo`, both included; `validFrom` and `validTo` are RFC 3339 timestamps, and a date alone is skipped; a key whose `validTo` has passed is used neither to verify nor to encrypt; a key with a future `validFrom` comes into use at its `validFrom` without a refresh; a key with `validTo` before `validFrom` is skipped. |
| AC-17 | IopToken: every `/iop` call the FIU sends carries the IopToken from `/entity/iopToken/generate` as `client_api_key`; the Direct API `/User/discover` carries the access token; the Central Registry and the AIG are called with the access token. The FIU verifies that `x-conn_aa_api_key` received on `/iop/*` is an IopToken, once the verification procedure is published. |

### 1.24 Items to be confirmed

| Item | Status |
|---|---|
| Role api-key header names (`client_api_key`, `x-conn_aa_api_key`) and `Initiator{type: AA}` on the Connected-AA → FIU leg | Subject to the final ReBIT specification for role api-key names |
| User discovery APIs (Direct API `/User/discover`, `/iop/User/discover`) and their payloads (`CustDiscoveryRequest`, `CustDiscoveryResponse`) | Proposed by Sahamati in the AA_Interop_1_0_0 "Proposed-1" draft; subject to ReBIT approval |
| `ver` of the Heartbeat envelope, which has no payload to take it from | `1.0.0` used; subject to the final ReBIT specification |
| IopToken verification procedure (how a received role api-key is checked to be an IopToken, a hop token) | To be published |

---

## Section 2: Redirection Mechanism for Interoperability

*To be written.*

---

## Section 3: Customer's UX options

*To be written.*
