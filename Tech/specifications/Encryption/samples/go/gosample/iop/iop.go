// Package iop: build and open the iop encryptedPayload. Go standard library only.
//
// The plaintext inside the JWE is a compact JWS (RFC 7515), signed by the sender with RS256:
//
//	BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)
//
// with header {"alg":"RS256","kid":"<sender's signing key id>"} and the signature computed over
// the ASCII of the first two parts. It is NOT the direct API's x-jws-signature: that one is
// RFC 7797 (b64=false, signed over the raw body) and cannot be reused here.
//
// The JWE is Compact Serialization, RSA-OAEP-256 + A256GCM, with cty "JWT".
package iop

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"strings"
)

var b64 = base64.RawURLEncoding // base64url, no padding

type jweHeader struct {
	Alg string `json:"alg"`
	Enc string `json:"enc"`
	Kid string `json:"kid"`
	Cty string `json:"cty"`
}

// jwsHeader is the inner JWS header. B64 and Crit are read only to reject them: the inner
// JWS is a standard JWS with a base64url-encoded payload.
type jwsHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	B64  *bool    `json:"b64,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// Decrypted is what the recipient gets from an encryptedPayload.
type Decrypted struct {
	Payload   []byte // the business payload, exactly as the sender built it
	SignerKid string // kid of the sender's signing key (from the inner JWS header)
	JWS       string // the decrypted plaintext: the inner compact JWS
	Signature string // the inner signature in detached form, header..signature (RFC 7515)
}

// KeyLookup returns the sender's public signing key for a kid. In production it reads the
// sender's signing keys from the CR.
type KeyLookup func(kid string) (*rsa.PublicKey, error)

// rsaJWK holds the members of an RSA public JWK (RFC 7517, RFC 7518 section 6.3).
type rsaJWK struct {
	Kty    string   `json:"kty"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	D      string   `json:"d,omitempty"` // must be absent: a public JWK carries no private part
}

// ParseRecipientJWK turns the recipient's public encryption JWK (as published in the CR)
// into an RSA public key and its kid. It rejects keys not meant for encryption.
func ParseRecipientJWK(jwk []byte) (*rsa.PublicKey, string, error) {
	return parseJWK(jwk, "enc", "RSA-OAEP-256", "wrapKey")
}

// ParseSigningJWK turns the sender's public signing JWK (as published in the CR) into an
// RSA public key and its kid. It rejects keys not meant for signatures.
func ParseSigningJWK(jwk []byte) (*rsa.PublicKey, string, error) {
	return parseJWK(jwk, "sig", "RS256", "verify")
}

func parseJWK(jwk []byte, use, alg, keyOp string) (*rsa.PublicKey, string, error) {
	var k rsaJWK
	if err := json.Unmarshal(jwk, &k); err != nil {
		return nil, "", errors.New("JWK is not valid JSON")
	}
	switch {
	case k.Kty != "RSA":
		return nil, "", errors.New(`JWK kty must be "RSA"`)
	case k.D != "":
		return nil, "", errors.New("JWK contains private key material (d); use the public JWK")
	case k.Kid == "":
		return nil, "", errors.New("JWK kid is required")
	case k.Use != "" && k.Use != use:
		return nil, "", errors.New(`JWK use must be "` + use + `"`)
	case k.Alg != "" && k.Alg != alg:
		return nil, "", errors.New(`JWK alg must be "` + alg + `"`)
	case k.KeyOps != nil && !slices.Contains(k.KeyOps, keyOp):
		return nil, "", errors.New(`JWK key_ops must include "` + keyOp + `"`)
	}
	nb, err1 := b64.DecodeString(k.N)
	eb, err2 := b64.DecodeString(k.E)
	if err1 != nil || err2 != nil || len(nb) == 0 || len(eb) == 0 || len(eb) > 4 {
		return nil, "", errors.New("JWK n or e is not valid base64url")
	}
	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)
	if n.BitLen() < 2048 {
		return nil, "", errors.New("RSA key must be at least 2048 bits")
	}
	if e.Int64() < 3 || e.Bit(0) == 0 || e.Int64() > 1<<31-1 {
		return nil, "", errors.New("JWK e is not a valid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, k.Kid, nil
}

// SignCompact signs payload as a compact JWS (RFC 7515, RS256):
//
//	BASE64URL({"alg":"RS256","kid":kid}) "." BASE64URL(payload) "." BASE64URL(signature)
func SignCompact(payload []byte, key *rsa.PrivateKey, kid string) (string, error) {
	if kid == "" {
		return "", errors.New("signing kid is required")
	}
	hdr, err := json.Marshal(jwsHeader{Alg: "RS256", Kid: kid})
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// VerifyCompact checks a compact JWS (RFC 7515, RS256) with the key keyFor returns for its
// kid, and returns the decoded payload and the kid.
func VerifyCompact(jws string, keyFor KeyLookup) ([]byte, string, error) {
	p := strings.Split(jws, ".")
	if len(p) != 3 || p[0] == "" || p[2] == "" {
		return nil, "", errors.New("not a compact JWS")
	}
	hb, err := b64.DecodeString(p[0])
	if err != nil {
		return nil, "", errors.New("bad JWS header")
	}
	var h jwsHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, "", errors.New("bad JWS header")
	}
	switch {
	case h.Alg != "RS256":
		return nil, "", errors.New(`JWS alg must be "RS256"`)
	case h.Kid == "":
		return nil, "", errors.New("JWS kid is required")
	case h.B64 != nil || len(h.Crit) > 0:
		return nil, "", errors.New("JWS must not carry b64 or crit: the inner JWS is RFC 7515")
	}
	payload, err1 := b64.DecodeString(p[1])
	sig, err2 := b64.DecodeString(p[2])
	if err1 != nil || err2 != nil {
		return nil, "", errors.New("not a compact JWS")
	}
	pub, err := keyFor(h.Kid)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, "", errors.New("JWS signature does not verify")
	}
	return payload, h.Kid, nil
}

// EncryptPayload signs payload with the sender's signing key (inner JWS, RFC 7515, RS256)
// and encrypts that JWS as a compact JWE for the recipient whose public JWK (from the CR)
// is given. The JWK's kid goes into the protected header.
func EncryptPayload(payload []byte, signingKey *rsa.PrivateKey, signingKid string, recipientJWK []byte) (string, error) {
	pub, kid, err := ParseRecipientJWK(recipientJWK)
	if err != nil {
		return "", err
	}
	plaintext, err := SignCompact(payload, signingKey, signingKid)
	if err != nil {
		return "", err
	}

	// Part 1: protected header. Its base64url form is also the AES-GCM AAD.
	hdr, err := json.Marshal(jweHeader{Alg: "RSA-OAEP-256", Enc: "A256GCM", Kid: kid, Cty: "JWT"})
	if err != nil {
		return "", err
	}
	protected := b64.EncodeToString(hdr)

	// Fresh 256-bit CEK per message.
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return "", err
	}
	defer clear(cek)

	// Part 2: CEK wrapped with RSA-OAEP-256 (OAEP with SHA-256, MGF1 with SHA-256).
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		return "", err
	}

	// Parts 3-5: AES-256-GCM with a fresh 96-bit IV.
	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, []byte(plaintext), []byte(protected))
	n := len(sealed) - gcm.Overhead() // tag is the last 16 bytes
	ciphertext, tag := sealed[:n], sealed[n:]

	return strings.Join([]string{
		protected,
		b64.EncodeToString(encKey),
		b64.EncodeToString(iv),
		b64.EncodeToString(ciphertext),
		b64.EncodeToString(tag),
	}, "."), nil
}

// DecryptPayload opens a compact JWE with the recipient's private key, then verifies the
// inner JWS with the sender's signing key (senderKey, looked up by the JWS kid). The caller
// still checks that the signer is the expected party: Initiator.id on a request, the
// Target.id the request was sent to on a response.
func DecryptPayload(compactJWE string, priv *rsa.PrivateKey, senderKey KeyLookup) (*Decrypted, error) {
	p := strings.Split(compactJWE, ".")
	if len(p) != 5 {
		return nil, errors.New("iopPayload must have five parts")
	}
	hdrJSON, err := b64.DecodeString(p[0])
	if err != nil {
		return nil, errors.New("bad protected header")
	}
	var hdr jweHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, errors.New("bad protected header")
	}
	if hdr.Alg != "RSA-OAEP-256" || hdr.Enc != "A256GCM" || hdr.Cty != "JWT" {
		return nil, errors.New("unsupported alg/enc/cty")
	}
	encKey, err1 := b64.DecodeString(p[1])
	iv, err2 := b64.DecodeString(p[2])
	ciphertext, err3 := b64.DecodeString(p[3])
	tag, err4 := b64.DecodeString(p[4])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil ||
		len(iv) != 12 || len(tag) != 16 {
		return nil, errors.New("malformed iopPayload")
	}

	cek, err := rsa.DecryptOAEP(sha256.New(), nil, priv, encKey, nil)
	if err != nil || len(cek) != 32 {
		return nil, errors.New("decryption failed") // keep generic
	}
	defer clear(cek)

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	plaintext, err := gcm.Open(nil, iv, append(ciphertext, tag...), []byte(p[0]))
	if err != nil {
		return nil, errors.New("decryption failed") // tag check failed
	}

	// The plaintext is the inner compact JWS; verify it before using the payload.
	jws := string(plaintext)
	payload, kid, err := VerifyCompact(jws, senderKey)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(jws, ".")
	return &Decrypted{Payload: payload, SignerKid: kid, JWS: jws, Signature: parts[0] + ".." + parts[2]}, nil
}
