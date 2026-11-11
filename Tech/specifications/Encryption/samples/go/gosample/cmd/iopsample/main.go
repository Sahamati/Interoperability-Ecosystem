// Command iopsample reads a business payload and the RSA keys from a JSON
// configuration file, then calls iop.EncryptPayload (sign as an RFC 7515 compact
// JWS, then encrypt) and iop.DecryptPayload (decrypt, then verify the JWS).
//
// Usage:
//
//	go run ./cmd/iopsample -config config.json -mode roundtrip
//	go run ./cmd/iopsample -config config.json -mode encrypt
//	go run ./cmd/iopsample -config config.json -mode decrypt
//	go run ./cmd/iopsample -mode makejwk -pem keys/aa-003-enc-pub.pem -kid aa-003-enc-2026-10
//	go run ./cmd/iopsample -mode makejwk -use sig -pem keys/fiu-4-sig-pub.pem -kid fiu-4-sig-2026-10
//
// makejwk is a test helper: it turns a PEM public key into a public JWK, an
// encryption JWK (-use enc, the default) or a signing JWK (-use sig). In
// production both JWKs come from the CR.
//
// The private-key paths can also be given in IOP_PRIVATE_KEY_FILE (decryption)
// and IOP_SIGNING_KEY_FILE (signing), which override the config, so the key
// locations need not be committed anywhere.
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"example.org/iopsample/iop"
)

// Config mirrors config.json.
type Config struct {
	PayloadFile string `json:"payloadFile"` // business payload (JSON body of the ReBIT API)
	JweFile     string `json:"jweFile"`     // where the compact JWE is written / read

	Sender struct {
		SigningKeyFile string `json:"signingKeyFile"` // encrypt: sender's signing private key (PEM)
		Kid            string `json:"kid"`            // encrypt: kid of that key, as registered in the CR
		JwkFile        string `json:"jwkFile"`        // decrypt: sender's public signing JWK as published in the CR
	} `json:"sender"`

	Recipient struct {
		JwkFile string `json:"jwkFile"` // recipient's public JWK as published in the CR (carries kid)
	} `json:"recipient"`

	Self struct {
		PrivateKeyFile string `json:"privateKeyFile"` // PEM, "PRIVATE KEY" (PKCS#8) or "RSA PRIVATE KEY"
	} `json:"self"`
}

func main() {
	cfgPath := flag.String("config", "config.json", "path to the configuration file")
	mode := flag.String("mode", "roundtrip", "encrypt | decrypt | roundtrip | makejwk")
	pemPath := flag.String("pem", "", "makejwk: PEM public key to convert")
	kid := flag.String("kid", "", "makejwk: kid to put in the JWK")
	use := flag.String("use", "enc", "makejwk: enc (encryption JWK) | sig (signing JWK)")
	flag.Parse()

	if *mode == "makejwk" {
		if err := makeJWK(*pemPath, *kid, *use); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	switch *mode {
	case "encrypt":
		_, err = doEncrypt(cfg)
	case "decrypt":
		_, err = doDecrypt(cfg)
	case "roundtrip":
		err = doRoundtrip(cfg)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // catch typos in key names
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if p := os.Getenv("IOP_PRIVATE_KEY_FILE"); p != "" {
		cfg.Self.PrivateKeyFile = p
	}
	if p := os.Getenv("IOP_SIGNING_KEY_FILE"); p != "" {
		cfg.Sender.SigningKeyFile = p
	}
	return &cfg, nil
}

// doEncrypt: payload + sender's signing key + recipient public key -> compact JWE.
func doEncrypt(cfg *Config) (string, error) {
	payload, err := os.ReadFile(cfg.PayloadFile)
	if err != nil {
		return "", fmt.Errorf("payload: %w", err)
	}
	signingKey, err := loadPrivateKey(cfg.Sender.SigningKeyFile)
	if err != nil {
		return "", fmt.Errorf("signing key: %w", err)
	}
	jwk, err := os.ReadFile(cfg.Recipient.JwkFile)
	if err != nil {
		return "", fmt.Errorf("recipient JWK: %w", err)
	}

	jwe, err := iop.EncryptPayload(payload, signingKey, cfg.Sender.Kid, jwk)
	if err != nil {
		return "", fmt.Errorf("encryptPayload: %w", err)
	}
	if cfg.JweFile != "" {
		if err := os.WriteFile(cfg.JweFile, []byte(jwe), 0o600); err != nil {
			return "", err
		}
	}
	fmt.Printf("iopPayload (%d chars):\n%s\n\n", len(jwe), jwe)
	return jwe, nil
}

// doDecrypt: compact JWE + own private key + sender's public signing key -> verified payload.
func doDecrypt(cfg *Config) (*iop.Decrypted, error) {
	jwe, err := os.ReadFile(cfg.JweFile)
	if err != nil {
		return nil, fmt.Errorf("jwe: %w", err)
	}
	return decryptString(cfg, strings.TrimSpace(string(jwe)))
}

func decryptString(cfg *Config, jwe string) (*iop.Decrypted, error) {
	priv, err := loadPrivateKey(cfg.Self.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	senderKey, err := senderKeyLookup(cfg.Sender.JwkFile)
	if err != nil {
		return nil, fmt.Errorf("sender JWK: %w", err)
	}
	if err := printParts(jwe); err != nil {
		return nil, err
	}
	d, err := iop.DecryptPayload(jwe, priv, senderKey)
	if err != nil {
		return nil, fmt.Errorf("decryptPayload: %w", err)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(strings.SplitN(d.JWS, ".", 2)[0])
	fmt.Println("=== Decrypted plaintext: inner JWS (RFC 7515), signature verified ===")
	fmt.Printf("%s\n\nJWS header: %s\nsigner kid: %s\n\n", d.JWS, hdr, d.SignerKid)
	fmt.Printf("payload:\n%s\n\n", prettyJSON(d.Payload))
	// Next: check that the signer is the expected party (Initiator.id on a request, the
	// Target.id the request was sent to on a response), then process the payload.
	return d, nil
}

// senderKeyLookup stands in for the CR: it returns the sender's public signing key from
// its JWK when the inner JWS kid matches, and fails otherwise.
func senderKeyLookup(jwkPath string) (iop.KeyLookup, error) {
	raw, err := os.ReadFile(jwkPath)
	if err != nil {
		return nil, err
	}
	pub, kid, err := iop.ParseSigningJWK(raw)
	if err != nil {
		return nil, err
	}
	return func(k string) (*rsa.PublicKey, error) {
		if k != kid {
			return nil, fmt.Errorf("no signing key for kid %q", k)
		}
		return pub, nil
	}, nil
}

// printParts shows the five parts of the compact JWE and their decoded sizes.
// It only splits and decodes; nothing here needs the private key.
func printParts(jwe string) error {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return fmt.Errorf("iopPayload has %d parts, want 5", len(parts))
	}
	names := []string{"Protected header", "Encrypted key", "Initialization vector", "Ciphertext", "Authentication tag"}
	fmt.Println("=== iopPayload: 5 parts ===")
	for i, part := range parts {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return fmt.Errorf("part %d (%s): not base64url: %w", i+1, names[i], err)
		}
		fmt.Printf("\nPart %d: %s (%d chars, %d bytes)\n%s\n", i+1, names[i], len(part), len(raw), part)
		if i == 0 {
			fmt.Printf("decoded: %s\n", raw)
		}
	}
	fmt.Println()
	return nil
}

// prettyJSON indents the payload for display; falls back to the raw bytes.
func prettyJSON(b []byte) []byte {
	var out bytes.Buffer
	if json.Indent(&out, b, "", "  ") != nil {
		return b
	}
	return out.Bytes()
}

func doRoundtrip(cfg *Config) error {
	jwe, err := doEncrypt(cfg)
	if err != nil {
		return err
	}
	d, err := decryptString(cfg, jwe)
	if err != nil {
		return err
	}
	origPayload, _ := os.ReadFile(cfg.PayloadFile)
	if !bytes.Equal(d.Payload, origPayload) || d.SignerKid != cfg.Sender.Kid {
		return errors.New("roundtrip mismatch")
	}
	fmt.Println("roundtrip OK: signature verified, payload byte-identical")
	return nil
}

// makeJWK prints the public JWK for a PEM public key (test helper): an encryption JWK
// (use "enc", alg RSA-OAEP-256) or a signing JWK (use "sig", alg RS256).
func makeJWK(pemPath, kid, use string) error {
	if pemPath == "" || kid == "" {
		return errors.New("makejwk needs -pem and -kid")
	}
	alg := map[string]string{"enc": "RSA-OAEP-256", "sig": "RS256"}[use]
	if alg == "" {
		return errors.New(`makejwk -use must be "enc" or "sig"`)
	}
	pub, err := loadPublicKey(pemPath)
	if err != nil {
		return err
	}
	jwk := map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": use,
		"alg": alg,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	out, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func readPEM(path string) (*pem.Block, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return block, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	switch block.Type {
	case "PUBLIC KEY": // SPKI
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
		return pub, nil
	case "RSA PUBLIC KEY": // PKCS#1
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return priv, nil
	case "RSA PRIVATE KEY": // PKCS#1
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
}
