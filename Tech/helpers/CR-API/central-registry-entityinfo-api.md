# Central Registry Entity Info API — Keys and Interop Flag

|  |  |
|---|---|
| **Audience** | AA, FIU and FIP application teams, and implementers of the IOP gateway, that read participant data from the Central Registry for AA Interoperability |
| **Version** | Draft 1.3, 2026-11-10 |
| **Published by** | Sahamati |
| **Scope** | The Central Registry call that returns participants' base URLs, signature and encryption public keys, and the `interop` flag, and how AA Interoperability reads its response |

All identifiers, URLs and values in examples are illustrative.

## 1. Terminology

| Term | Meaning |
|---|---|
| Central Registry (CR) | Sahamati's registry of participants: ids, base URLs, public keys and the `interop` flag. |
| Participant | A registered AA, FIU or FIP. |
| Interop ready | A participant whose `interop` flag in the Central Registry is `true`. |
| Access token | The caller's token from the Sahamati token service, sent as the bearer token to the Central Registry. |
| JWK | A public key in JSON Web Key format. |
| Caller | The AA, FIU or FIP application, or the IOP gateway (aa-iop-gw, fiu-iop-gw, fip-iop-gw), that reads the lists. |

## 2. Who calls

| Caller | Callee |
|---|---|
| AA application or aa-iop-gw | Central Registry |
| FIU application or fiu-iop-gw | Central Registry |
| FIP application or fip-iop-gw | Central Registry |

The caller loads the lists in the background and serves every lookup from memory. It never calls
the Central Registry per message.

## 3. API

| Method | Path | Caller | Callee |
|---|---|---|---|
| `GET` | `<CR base URL>/v2/entityInfo/<type>` | AA, FIU or FIP application, or its gateway | Central Registry |

`<type>` is `AA`, `FIU` or `FIP`. Each type is a separate call.

| Caller | Lists fetched | Why |
|---|---|---|
| AA | `AA`, `FIU` and `FIP` | An AA sends to, receives from and routes for all three types. |
| FIU | `AA` only | Every participant an FIU deals with is an AA (Connected-AA, Customer-AA). |
| FIP | `AA` only | Every participant a FIP deals with is an AA (Inter-AA, Origin-AA). |

## 4. Request

### 4.1 Request headers

| Header | Mandatory | Value |
|---|---|---|
| `Authorization` | Yes | `Bearer <access token>` |
| `Accept` | No | `application/json` |

### 4.2 Request body

None.

## 5. Response

### 5.1 Status

| Status | Meaning for the caller |
|---|---|
| `200` | The body is read as described below. |
| Any other status | Failed fetch (section 7). |

### 5.2 Response body

A **top-level JSON array**, with one element per participant of the requested type.

| Field | Used | Meaning |
|---|---|---|
| `ver` | No | Ignored. |
| `timestamp` | No | Ignored. |
| `txnid` | No | Ignored. |
| `requester` | No | Ignored. |
| `entityinfo` | Yes | The participant (section 5.3). |

The participant's type is the list it came from (`<type>` in the path), not a field in the body.

### 5.3 `entityinfo` fields

| Field | Type | Needed for | Use |
|---|---|---|---|
| `id` | string | Every participant | The participant's entity id. An element without `id` is skipped. |
| `baseurl` | string | Participants that receive `/iop/*` calls | Absolute URL. A trailing `/` is removed and `/iop/<api>` is added. A value that is not an absolute URL is ignored. |
| `interop` | boolean | Every participant | `true` = interop ready. **Absent or `false` = not interop ready.** Must be a JSON boolean, not a string. |
| `keys.signature` | array of key items (section 5.4) | Every participant that signs | Public keys that verify the participant's signatures, matched by the JWS `kid`. |
| `certificate` | JWK | Optional | Used as the only signature key when `keys.signature` is empty or absent. Ignored otherwise. It has no `validFrom` or `validTo`. |
| `keys.encryption` | array of key items (section 5.4) | Participants that receive encrypted messages | Public keys to encrypt for the participant. One is chosen at random per message. |

### 5.4 Key items

Each element of `keys.signature` and `keys.encryption` is a key with its validity window:

| Field | Type | Mandatory | Use |
|---|---|---|---|
| `key` | JWK | Yes | The public key (section 5.5). |
| `validFrom` | string | No | From when the key may be used. Absent or empty: no limit. |
| `validTo` | string | No | Until when the key may be used. Absent or empty: no limit. |

| Rule | Detail |
|---|---|
| Format of `validFrom` and `validTo` | An RFC 3339 timestamp with its time zone, for example `2026-11-01T00:00:00Z` (UTC) or `2026-11-01T05:30:00+05:30` (IST). A date alone, such as `2026-11-01`, is not accepted. |
| Window | A key is used, to verify a signature or to encrypt, only while the current time is between `validFrom` and `validTo`, both included. |
| When it is checked | Each time the key is used, not only when the lists load. A key comes into use at its `validFrom` and goes out of use at its `validTo` without a new fetch. |
| Keys outside their window | Kept in the lists, but not used. |
| Invalid window | A key whose `validFrom` or `validTo` is not an RFC 3339 timestamp, or whose `validTo` is before its `validFrom`, is skipped. |
| Bare JWK | A JWK placed directly in `keys.signature` or `keys.encryption`, without `key`, is skipped. |

### 5.5 Key (JWK) fields

| Field | Signature key | Encryption key |
|---|---|---|
| `kty` | `RSA` | `RSA` |
| `kid` | Required | Required |
| `use` | `sig` or absent | `enc` or absent |
| `alg` | `RS256`, `PS256` or absent | `RSA-OAEP-256` or absent |
| `n` | Modulus, base64url **without padding**; key of at least 2048 bits | Same |
| `e` | Exponent, base64url **without padding**; value of at least 3 | Same |

A key that does not meet these rules is skipped. The participant's other keys are still used.

### 5.6 How the data is used

| Need | Field |
|---|---|
| Is the Target interop ready? | `interop` |
| Can this AA be used as a route (hop)? | `interop` and `baseurl` (with the AIG and linkedAAs) |
| Where to send an `/iop/*` call | `baseurl` |
| Verify a participant's signature | `keys.signature` within their window (or `certificate`), matched by `kid` |
| Encrypt for a participant | `keys.encryption` within their window, one chosen at random per message |

## 6. Example

### 6.1 Request

```http
GET /v2/entityInfo/AA HTTP/1.1
Host: cr-test.example.invalid
Authorization: Bearer <access token>
Accept: application/json
```

### 6.2 Response

```json
[
  {
    "ver": "2.0.0",
    "timestamp": "2026-11-09T10:00:00.000Z",
    "txnid": "00000000-0000-4000-8000-000000000001",
    "requester": { },
    "entityinfo": {
      "id": "aa-test-002",
      "baseurl": "https://aa-test-002.example.invalid/v2",
      "interop": true,
      "certificate": {
        "kty": "RSA", "kid": "aa-test-002-cert", "use": "sig", "alg": "RS256",
        "n": "<base64url modulus>", "e": "AQAB"
      },
      "keys": {
        "signature": [
          {
            "key": { "kty": "RSA", "kid": "aa-test-002-sig-2026-10", "use": "sig", "alg": "RS256",
                     "n": "<base64url modulus>", "e": "AQAB" },
            "validFrom": "2026-10-01T00:00:00Z"
          }
        ],
        "encryption": [
          {
            "key": { "kty": "RSA", "kid": "aa-test-002-enc-2026-10", "use": "enc", "alg": "RSA-OAEP-256",
                     "n": "<base64url modulus>", "e": "AQAB" },
            "validFrom": "2026-10-01T00:00:00Z",
            "validTo": "2026-11-30T23:59:59+05:30"
          },
          {
            "key": { "kty": "RSA", "kid": "aa-test-002-enc-2026-11", "use": "enc", "alg": "RSA-OAEP-256",
                     "n": "<base64url modulus>", "e": "AQAB" },
            "validFrom": "2026-11-15T00:00:00Z"
          }
        ]
      }
    }
  }
]
```

Here `certificate` is not used, because `keys.signature` is not empty. The signature key has no
end. The first encryption key is used until 30 November 2026, 23:59:59 IST; the second from
15 November 2026, 00:00 UTC. Between those times either may be chosen. `/iop/<api>` calls to this
AA go to `https://aa-test-002.example.invalid/v2/iop/<api>`.

## 7. Failures

A fetch fails when any of these happens:

| Case | Result |
|---|---|
| Status other than `200` | Failed fetch |
| Timeout or network error | Failed fetch |
| Body is not a JSON array | Failed fetch |
| Body is `null` or `[]` | Failed fetch |
| Body cannot be read as the structure in section 5 (for example, `interop` sent as a string) | Failed fetch |

On a failed fetch:

- The caller keeps the lists it already has and tries again after 5 minutes.
- New lists are used only if **every** list the caller needs (section 3) is fetched and read
  successfully.
- Until the first successful load (or a cached copy), the caller cannot send or accept IOP
  messages.

These cases do **not** fail the fetch; only the affected item is skipped:

| Case | Result |
|---|---|
| Element without `entityinfo.id` | That element is skipped. |
| `baseurl` that is not an absolute URL | The participant has no base URL; calls cannot be sent to it. |
| A key that breaks the rules in section 5.5 | That key is skipped. |
| A key item whose `validFrom` or `validTo` is not an RFC 3339 timestamp, or `validTo` before `validFrom` (section 5.4) | That key is skipped. |

## 8. Requirements on Central Registry entries

For a participant to take part in AA Interoperability, its entry must have:

| Item | Why |
|---|---|
| `interop: true` | Others send to, route through, and accept messages from interop-ready participants only. |
| `baseurl` | Others send `/iop/*` calls to `<baseurl>/iop/<api>`. |
| `keys.signature` | Others verify its signatures. It must list the public key of **every** signing key the participant may use, with a window that covers every time that key may sign. |
| `keys.encryption` | Others encrypt requests and replies for it. A key's `validTo` must come before the participant stops being able to decrypt with it. |
