# iopsample (Java)

Config-driven sample that calls `IopCrypto.encryptPayload` and `IopCrypto.decryptPayload`
(JWE Compact Serialization, RSA-OAEP-256 + A256GCM). JDK only, Java 17 or later.
Output is interchangeable with the Go sample: either side can decrypt what the other encrypts.

## What is encrypted

The plaintext inside the JWE is a compact JWS (RFC 7515), signed by the sender with RS256:

    BASE64URL({"alg":"RS256","kid":"<sender's signing key id>"}) . BASE64URL(payload) . BASE64URL(signature)

The signature is computed over the ASCII of the first two parts. Base64url is without padding.

- **Encrypt** (`IopCrypto.encryptPayload`): signs the payload with the sender's signing private
  key (`IopCrypto.signCompact`), then encrypts that JWS for the recipient.
- **Decrypt** (`IopCrypto.decryptPayload`): decrypts, then verifies the JWS with the sender's
  public signing key, looked up by the JWS `kid` (`IopCrypto.verifyCompact`). It returns the
  payload, the signer's `kid`, the JWS itself and the signature in detached form
  (`header..signature`). The caller still checks that the signer is the expected party:
  `Initiator.id` on a request, the `Target.id` the request was sent to on a response.

The direct API's `x-jws-signature` **cannot** be reused as the inner signature: it is RFC 7797
(`"b64": false`, `"crit": ["b64"]`, signed over the raw body). A JWS with `b64` or `crit` in its
header is rejected on decryption.

## Layout

    src/org/example/iop/IopCrypto.java   parseRecipientJwk / parseSigningJwk / signCompact / verifyCompact /
                                         encryptPayload / decryptPayload
    src/org/example/iop/IopSample.java   reads config.properties, loads keys and files, calls the functions
    config.example.properties            copy to config.properties and edit
    testdata/                            synthetic payload

## Build and run

    javac -d out src/org/example/iop/*.java
    cp config.example.properties config.properties
    # put the keys under keys/ (never commit private keys): see "Keys" below
    java -cp out org.example.iop.IopSample -config config.properties -mode roundtrip
    java -cp out org.example.iop.IopSample -config config.properties -mode encrypt   # writes jweFile
    java -cp out org.example.iop.IopSample -config config.properties -mode decrypt   # reads jweFile

Decrypt prints the five parts of the iopPayload, the decrypted plaintext (the inner JWS) with its
header, and the payload.

`IOP_PRIVATE_KEY_FILE` overrides `self.privateKeyFile`; `IOP_SIGNING_KEY_FILE` overrides
`sender.signingKeyFile`. Unknown keys in the config are rejected.

## Configuration

| Key | Used by | What it is |
|---|---|---|
| `payloadFile` | encrypt | The business payload (JSON body of the ReBIT API) |
| `jweFile` | both | Where the compact JWE is written (encrypt) or read (decrypt) |
| `sender.signingKeyFile` | encrypt | The sender's signing private key (PEM) |
| `sender.kid` | encrypt | The `kid` of that key, as registered in the CR |
| `sender.jwkFile` | decrypt | The sender's public signing JWK, as published in the CR |
| `recipient.jwkFile` | encrypt | The recipient's public encryption JWK, as published in the CR |
| `self.privateKeyFile` | decrypt | Own encryption private key (PEM) |

In this sample one person plays both sides, so the config holds both the sender's and the
recipient's keys.

## Keys

Encryption takes the recipient's **public encryption JWK** (`recipient.jwkFile`), as published in
the CR. The JWK's `kid` is copied into the protected header. It is rejected if it: is not
`kty: RSA`; has no `kid`; carries a private part (`d`); has `use` other than `enc`; has `alg`
other than `RSA-OAEP-256`; has `key_ops` without `wrapKey`; or is under 2048 bits.

Verification takes the sender's **public signing JWK** (`sender.jwkFile`), with the same checks
except `use` must be `sig`, `alg` must be `RS256` and `key_ops` must include `verify`.
`use`, `alg` and `key_ops` are optional; if present they must match.

Private keys are unencrypted PEM: `PRIVATE KEY` (PKCS#8) or `RSA PRIVATE KEY` (PKCS#1).

To make throwaway test keys:

    mkdir -p keys
    # recipient's encryption key pair
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private_key.pem
    openssl rsa -in keys/private_key.pem -pubout -out keys/enc_public_key.pem
    java -cp out org.example.iop.IopSample -mode makejwk -pem keys/enc_public_key.pem -kid aa-003-enc-2026-10 > keys/public_key.jwk.json
    # sender's signing key pair
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/signing_private_key.pem
    openssl rsa -in keys/signing_private_key.pem -pubout -out keys/signing_public_key.pem
    java -cp out org.example.iop.IopSample -mode makejwk -use sig -pem keys/signing_public_key.pem -kid fiu-4-sig-2026-10 > keys/signing_public_key.jwk.json

`makejwk` is a test helper only; in production the JWKs come from the CR.

The JSON reading in IopCrypto (JWE and JWS headers, JWK) and the display-only JSON indenter in
IopSample are minimal placeholders; use your JSON library (Jackson, Gson) in production.

All data in testdata/ is synthetic. Do not put real payloads, signatures or keys in this folder.
