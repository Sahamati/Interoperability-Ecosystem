# PRD — Hashing Guide for User Discovery

> **Disclaimer:** Please review and verify the contents of this document against the applicable system requirements and specifications.
>
> Kindly note that this document is subject to change as development, integration, and testing progress.

|  |  |
|---|---|
| **Audience** | AA and FIU application teams that send or answer user discovery (`/User/discover`, `/iop/User/discover`) |
| **Version** | Draft 1.0, 2026-11-10 |
| **Published by** | Sahamati |
| **Based on** | AA_Interop_1_0_0 "Proposed-1": `CustDiscoveryRequest.customer.vuaHash` and `customer.mobileHash` |

All identifiers, numbers and hashes in examples are illustrative.

## 1. Why this guide

In user discovery, an FIU does not send a customer's user handle (VUA) or mobile number. It sends
their hashes, `vuaHash` and `mobileHash`, and each AA looks them up in its User Hash List. A match
is found only when the FIU and the AA compute the hash from **exactly the same text**. This guide
fixes that text, so that every FIU and every AA get the same hash for the same customer.

## 2. Who uses it

| Participant | Uses this guide to |
|---|---|
| FIU | Build `customer.vuaHash` and `customer.mobileHash` in the `CustDiscoveryRequest` |
| AA | Build the VUA hash and the mobile hash of each entry in its User Hash List |

## 3. Hash function

For both values:

1. Take the text as given in sections 4 and 5.
2. Encode it as UTF-8 bytes.
3. Compute SHA-256 over those bytes (32 bytes).
4. Encode the 32 bytes as base64url (RFC 4648, section 5) **without padding**: no trailing `=`.
   The result is always 43 characters long.

## 4. vuaHash

The VUA is hashed **as it is**. No change is made before hashing: no change of upper or lower case,
no removal of spaces, no other change.

| VUA | vuaHash |
|---|---|
| `customer123@aa-identifier` | `fjMIwrClcgKEWKwUImh4z5T0PMMtZaxOPIqsNf4P1lY` |

Because the VUA is not changed, two spellings of a VUA (for example a different case) give
different hashes.

## 5. mobileHash

### 5.1 Normalisation rules

Before hashing, the mobile number is normalised with these rules, in this order:

1. Remove spaces, dashes (`-`), brackets (`(`, `)`, `[`, `]`) and dots (`.`).
2. Remove a leading `00`, or a single leading `0` that comes before a 10-digit number.
3. If 10 digits are left, add `+91` to the front. If the number starts with `91` and is 12 digits
   long, add `+` to the front.
4. Check the result against `^\+91[6-9]\d{9}$`. Indian mobile numbers start with 6, 7, 8 or 9.

Only a number that passes step 4 is hashed. A number that does not pass is not a valid mobile
number: no `mobileHash` is made from it.

The normalised value is always `+91` followed by 10 digits, for example `+919999999999`. This
value, and nothing else, is hashed as in section 3.

### 5.2 Worked examples

| Mobile number as given | After step 1 | After step 2 | After step 3 | Step 4 | mobileHash |
|---|---|---|---|---|---|
| `9999999999` | `9999999999` | `9999999999` | `+919999999999` | Valid | `QiamVqNXBPKiYYzwfmYKb7o4rwRAp4XLHUoEfQo7nxU` |
| `09999999999` | `09999999999` | `9999999999` | `+919999999999` | Valid | `QiamVqNXBPKiYYzwfmYKb7o4rwRAp4XLHUoEfQo7nxU` |
| `0091-99999-99999` | `00919999999999` | `919999999999` | `+919999999999` | Valid | `QiamVqNXBPKiYYzwfmYKb7o4rwRAp4XLHUoEfQo7nxU` |
| `919999999999` | `919999999999` | `919999999999` | `+919999999999` | Valid | `QiamVqNXBPKiYYzwfmYKb7o4rwRAp4XLHUoEfQo7nxU` |
| `+91 99999 99999` | `+919999999999` | `+919999999999` | `+919999999999` | Valid | `QiamVqNXBPKiYYzwfmYKb7o4rwRAp4XLHUoEfQo7nxU` |
| `(+91) 99999.99999` | `+919999999999` | `+919999999999` | `+919999999999` | Valid | `QiamVqNXBPKiYYzwfmYKb7o4rwRAp4XLHUoEfQo7nxU` |
| `5999999999` | `5999999999` | `5999999999` | `+915999999999` | Not valid (starts with 5) | — |
| `999999999` | `999999999` | `999999999` | `999999999` | Not valid (9 digits) | — |

Every valid form of the same number gives the same normalised value, `+919999999999`, and so the
same hash.

## 6. Checking an implementation

An implementation is correct when it gives the hashes of sections 4 and 5.2 for those inputs. For
example, from a shell:

```sh
printf '%s' '+919999999999' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
# QiamVqNXBPKiYYzwfmYKb7o4rwRAp4XLHUoEfQo7nxU

printf '%s' 'customer123@aa-identifier' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
# fjMIwrClcgKEWKwUImh4z5T0PMMtZaxOPIqsNf4P1lY
```

`printf '%s'` is used so that no newline is added to the text before hashing.

## 7. Handling the data

- Hashes of VUAs and mobile numbers are customer data. Keep them in secure storage, and never log
  them, the request or the answer.
- Use synthetic values, such as those in this guide, in tests and examples.

## 8. Acceptance criteria

| # | Criterion |
|---|---|
| AC-1 | `customer123@aa-identifier` hashes to `fjMIwrClcgKEWKwUImh4z5T0PMMtZaxOPIqsNf4P1lY`. |
| AC-2 | Each valid input of section 5.2 normalises to `+919999999999` and hashes to `QiamVqNXBPKiYYzwfmYKb7o4rwRAp4XLHUoEfQo7nxU`. |
| AC-3 | The invalid inputs of section 5.2 produce no `mobileHash`. |
| AC-4 | Hashes are base64url without padding, 43 characters long. |
