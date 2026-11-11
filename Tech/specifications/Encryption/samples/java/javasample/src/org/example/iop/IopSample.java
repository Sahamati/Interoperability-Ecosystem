package org.example.iop;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.Set;

/**
 * Reads a business payload and the RSA keys from config.properties, then calls
 * IopCrypto.encryptPayload (sign as an RFC 7515 compact JWS, then encrypt) and
 * IopCrypto.decryptPayload (decrypt, then verify the JWS).
 *
 * <pre>
 *   java -cp out org.example.iop.IopSample -config config.properties -mode roundtrip
 *   java -cp out org.example.iop.IopSample -config config.properties -mode encrypt
 *   java -cp out org.example.iop.IopSample -config config.properties -mode decrypt
 *   java -cp out org.example.iop.IopSample -mode makejwk -pem keys/aa-003-enc-pub.pem -kid aa-003-enc-2026-10
 *   java -cp out org.example.iop.IopSample -mode makejwk -use sig -pem keys/fiu-4-sig-pub.pem -kid fiu-4-sig-2026-10
 * </pre>
 *
 * makejwk is a test helper: it turns a PEM public key into a public JWK, an encryption JWK
 * (-use enc, the default) or a signing JWK (-use sig). In production both JWKs come from the CR.
 *
 * IOP_PRIVATE_KEY_FILE overrides self.privateKeyFile and IOP_SIGNING_KEY_FILE overrides
 * sender.signingKeyFile, so the key locations need not be in the config.
 */
public final class IopSample {

    /** Values read from config.properties. */
    record Config(String payloadFile, String jweFile,
                  String senderSigningKeyFile, String senderKid, String senderJwkFile,
                  String recipientJwkFile, String selfPrivateKeyFile) {}

    private static final Set<String> KNOWN_KEYS = Set.of(
            "payloadFile", "jweFile",
            "sender.signingKeyFile", "sender.kid", "sender.jwkFile",
            "recipient.jwkFile", "self.privateKeyFile");

    public static void main(String[] args) {
        String cfgPath = "config.properties";
        String mode = "roundtrip";
        String pemPath = null, kid = null, use = "enc";
        for (int i = 0; i + 1 < args.length; i += 2) {
            switch (args[i]) {
                case "-config" -> cfgPath = args[i + 1];
                case "-mode" -> mode = args[i + 1];
                case "-pem" -> pemPath = args[i + 1];
                case "-kid" -> kid = args[i + 1];
                case "-use" -> use = args[i + 1];
                default -> fail("unknown flag " + args[i]);
            }
        }
        try {
            if (mode.equals("makejwk")) {
                makeJwk(pemPath, kid, use);
                return;
            }
            Config cfg = loadConfig(Path.of(cfgPath));
            switch (mode) {
                case "encrypt" -> doEncrypt(cfg);
                case "decrypt" -> doDecrypt(cfg);
                case "roundtrip" -> doRoundtrip(cfg);
                default -> fail("unknown mode " + mode);
            }
        } catch (IopCrypto.IopCryptoException e) {
            fail(e.getMessage());
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            fail(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    static Config loadConfig(Path path) throws IOException {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            p.load(r);
        }
        for (String k : p.stringPropertyNames()) {   // catch typos in key names
            if (!KNOWN_KEYS.contains(k)) throw new IllegalArgumentException("unknown config key: " + k);
        }
        String priv = System.getenv("IOP_PRIVATE_KEY_FILE");
        String sign = System.getenv("IOP_SIGNING_KEY_FILE");
        return new Config(
                p.getProperty("payloadFile"),
                p.getProperty("jweFile"),
                (sign != null && !sign.isEmpty()) ? sign : p.getProperty("sender.signingKeyFile"),
                p.getProperty("sender.kid"),
                p.getProperty("sender.jwkFile"),
                p.getProperty("recipient.jwkFile"),
                (priv != null && !priv.isEmpty()) ? priv : p.getProperty("self.privateKeyFile"));
    }

    /** payload + sender's signing key + recipient public key -> compact JWE. */
    static String doEncrypt(Config cfg) throws IOException, GeneralSecurityException, IopCrypto.IopCryptoException {
        byte[] payload = Files.readAllBytes(Path.of(cfg.payloadFile()));
        RSAPrivateKey signingKey = loadPrivateKey(Path.of(cfg.senderSigningKeyFile()));
        String jwk = Files.readString(Path.of(cfg.recipientJwkFile()), StandardCharsets.UTF_8);

        String jwe = IopCrypto.encryptPayload(payload, signingKey, cfg.senderKid(), jwk);
        if (cfg.jweFile() != null && !cfg.jweFile().isEmpty()) {
            writePrivate(Path.of(cfg.jweFile()), jwe);
        }
        System.out.printf("iopPayload (%d chars):%n%s%n%n", jwe.length(), jwe);
        return jwe;
    }

    /** compact JWE + own private key + sender's public signing key -> verified payload. */
    static IopCrypto.Decrypted doDecrypt(Config cfg)
            throws IOException, GeneralSecurityException, IopCrypto.IopCryptoException {
        return decryptString(cfg, Files.readString(Path.of(cfg.jweFile())).strip());
    }

    static IopCrypto.Decrypted decryptString(Config cfg, String jwe)
            throws IOException, GeneralSecurityException, IopCrypto.IopCryptoException {
        RSAPrivateKey priv = loadPrivateKey(Path.of(cfg.selfPrivateKeyFile()));
        IopCrypto.KeyLookup senderKey = senderKeyLookup(Path.of(cfg.senderJwkFile()));
        printParts(jwe);
        IopCrypto.Decrypted d = IopCrypto.decryptPayload(jwe, priv, senderKey);
        String hdr = new String(Base64.getUrlDecoder().decode(d.jws().substring(0, d.jws().indexOf('.'))),
                StandardCharsets.UTF_8);
        System.out.println("=== Decrypted plaintext: inner JWS (RFC 7515), signature verified ===");
        System.out.printf("%s%n%nJWS header: %s%nsigner kid: %s%n%n", d.jws(), hdr, d.signerKid());
        System.out.printf("payload:%n%s%n%n", prettyJson(new String(d.payload(), StandardCharsets.UTF_8)));
        // Next: check that the signer is the expected party (Initiator.id on a request, the
        // Target.id the request was sent to on a response), then process the payload.
        return d;
    }

    /**
     * Stands in for the CR: returns the sender's public signing key from its JWK when the inner
     * JWS kid matches, and fails otherwise.
     */
    static IopCrypto.KeyLookup senderKeyLookup(Path jwkPath) throws IOException, IopCrypto.IopCryptoException {
        IopCrypto.RecipientKey k = IopCrypto.parseSigningJwk(Files.readString(jwkPath, StandardCharsets.UTF_8));
        return kid -> {
            if (!k.kid().equals(kid)) throw new IopCrypto.IopCryptoException("no signing key for kid \"" + kid + "\"");
            return k.publicKey();
        };
    }

    static void doRoundtrip(Config cfg) throws IOException, GeneralSecurityException, IopCrypto.IopCryptoException {
        String jwe = doEncrypt(cfg);
        IopCrypto.Decrypted d = decryptString(cfg, jwe);
        byte[] origPayload = Files.readAllBytes(Path.of(cfg.payloadFile()));
        if (!Arrays.equals(d.payload(), origPayload) || !d.signerKid().equals(cfg.senderKid())) {
            throw new IllegalStateException("roundtrip mismatch");
        }
        System.out.println("roundtrip OK: signature verified, payload byte-identical");
    }

    /** Shows the five parts of the compact JWE and their decoded sizes. Needs no key. */
    static void printParts(String jwe) {
        String[] parts = jwe.split("\\.", -1);
        if (parts.length != 5) throw new IllegalArgumentException("iopPayload has " + parts.length + " parts, want 5");
        String[] names = {"Protected header", "Encrypted key", "Initialization vector", "Ciphertext",
                "Authentication tag"};
        System.out.println("=== iopPayload: 5 parts ===");
        for (int i = 0; i < 5; i++) {
            byte[] raw;
            try {
                raw = Base64.getUrlDecoder().decode(parts[i]);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("part " + (i + 1) + " (" + names[i] + "): not base64url");
            }
            System.out.printf("%nPart %d: %s (%d chars, %d bytes)%n%s%n",
                    i + 1, names[i], parts[i].length(), raw.length, parts[i]);
            if (i == 0) System.out.println("decoded: " + new String(raw, StandardCharsets.UTF_8));
        }
        System.out.println();
    }

    // ---------------------------------------------------------------- keys (PEM, JWK)

    /**
     * Prints the public JWK for a PEM public key (test helper): an encryption JWK (use "enc",
     * alg RSA-OAEP-256) or a signing JWK (use "sig", alg RS256).
     */
    static void makeJwk(String pemPath, String kid, String use) throws IOException, GeneralSecurityException {
        if (pemPath == null || kid == null) throw new IllegalArgumentException("makejwk needs -pem and -kid");
        String alg = switch (use) {
            case "enc" -> "RSA-OAEP-256";
            case "sig" -> "RS256";
            default -> throw new IllegalArgumentException("makejwk -use must be \"enc\" or \"sig\"");
        };
        RSAPublicKey pub = loadPublicKey(Path.of(pemPath));
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        System.out.printf("{%n  \"kty\": \"RSA\",%n  \"kid\": \"%s\",%n  \"use\": \"%s\",%n"
                        + "  \"alg\": \"%s\",%n  \"n\": \"%s\",%n  \"e\": \"%s\"%n}%n",
                kid, use, alg, b64.encodeToString(unsigned(pub.getModulus())),
                b64.encodeToString(unsigned(pub.getPublicExponent())));
    }

    /** Big-endian bytes without the sign byte, as JWK requires. */
    private static byte[] unsigned(java.math.BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? Arrays.copyOfRange(b, 1, b.length) : b;
    }

    /** Accepts "PUBLIC KEY" (SPKI) or "RSA PUBLIC KEY" (PKCS#1). */
    static RSAPublicKey loadPublicKey(Path path) throws IOException, GeneralSecurityException {
        Pem pem = readPem(path);
        byte[] spki = switch (pem.type()) {
            case "PUBLIC KEY" -> pem.der();
            case "RSA PUBLIC KEY" -> pkcs1PublicToSpki(pem.der());
            default -> throw new GeneralSecurityException("unsupported PEM type " + pem.type());
        };
        PublicKey k = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
        return (RSAPublicKey) k;
    }

    /** Accepts "PRIVATE KEY" (PKCS#8) or "RSA PRIVATE KEY" (PKCS#1). Unencrypted PEM only. */
    static RSAPrivateKey loadPrivateKey(Path path) throws IOException, GeneralSecurityException {
        Pem pem = readPem(path);
        byte[] pkcs8 = switch (pem.type()) {
            case "PRIVATE KEY" -> pem.der();
            case "RSA PRIVATE KEY" -> pkcs1PrivateToPkcs8(pem.der());
            default -> throw new GeneralSecurityException("unsupported PEM type " + pem.type());
        };
        try {
            PrivateKey k = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            return (RSAPrivateKey) k;
        } finally {
            Arrays.fill(pkcs8, (byte) 0);
        }
    }

    record Pem(String type, byte[] der) {}

    static Pem readPem(Path path) throws IOException {
        String text = Files.readString(path, StandardCharsets.US_ASCII);
        int b = text.indexOf("-----BEGIN ");
        if (b < 0) throw new IOException("no PEM block found in " + path);
        int typeEnd = text.indexOf("-----", b + 11);
        String type = text.substring(b + 11, typeEnd);
        String endMarker = "-----END " + type + "-----";
        int e = text.indexOf(endMarker, typeEnd);
        if (e < 0) throw new IOException("unterminated PEM block in " + path);
        String body = text.substring(typeEnd + 5, e).replaceAll("\\s", "");
        return new Pem(type, Base64.getDecoder().decode(body));
    }

    // AlgorithmIdentifier for rsaEncryption: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
    private static final byte[] RSA_ALG_ID = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00};

    /** SubjectPublicKeyInfo ::= SEQUENCE { algId, BIT STRING { RSAPublicKey } } */
    static byte[] pkcs1PublicToSpki(byte[] pkcs1) {
        byte[] bitString = tlv(0x03, concat(new byte[]{0x00}, pkcs1));
        return tlv(0x30, concat(RSA_ALG_ID, bitString));
    }

    /** PrivateKeyInfo ::= SEQUENCE { INTEGER 0, algId, OCTET STRING { RSAPrivateKey } } */
    static byte[] pkcs1PrivateToPkcs8(byte[] pkcs1) {
        byte[] version = {0x02, 0x01, 0x00};
        return tlv(0x30, concat(version, RSA_ALG_ID, tlv(0x04, pkcs1)));
    }

    private static byte[] tlv(int tag, byte[] value) {
        byte[] len;
        int n = value.length;
        if (n < 0x80) len = new byte[]{(byte) n};
        else if (n < 0x100) len = new byte[]{(byte) 0x81, (byte) n};
        else if (n < 0x10000) len = new byte[]{(byte) 0x82, (byte) (n >> 8), (byte) n};
        else len = new byte[]{(byte) 0x83, (byte) (n >> 16), (byte) (n >> 8), (byte) n};
        return concat(new byte[]{(byte) tag}, len, value);
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, pos, a.length);
            pos += a.length;
        }
        return out;
    }

    // ---------------------------------------------------------------- helpers

    private static void writePrivate(Path path, String content) throws IOException {
        Files.writeString(path, content, StandardCharsets.US_ASCII);
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // not a POSIX file system (e.g. Windows)
        }
    }

    /** Indents JSON for display only. Use your JSON library (Jackson, Gson) in production. */
    static String prettyJson(String json) {
        StringBuilder out = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                out.append(c);
                if (c == '\\' && i + 1 < json.length()) out.append(json.charAt(++i));
                else if (c == '"') inString = false;
                continue;
            }
            switch (c) {
                case '"' -> { inString = true; out.append(c); }
                case '{', '[' -> { out.append(c).append('\n'); indent++; out.append("  ".repeat(indent)); }
                case '}', ']' -> { out.append('\n'); indent--; out.append("  ".repeat(indent)).append(c); }
                case ',' -> out.append(c).append('\n').append("  ".repeat(indent));
                case ':' -> out.append(": ");
                default -> { if (!Character.isWhitespace(c)) out.append(c); }
            }
        }
        return out.toString();
    }

    private static void fail(String msg) {
        System.err.println("error: " + msg);
        System.exit(1);
    }

    private IopSample() {}
}
