package org.example.iop;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Build and open the iop encryptedPayload. JDK only.
 *
 * <p>The plaintext inside the JWE is a compact JWS (RFC 7515), signed by the sender with RS256:
 * {@code BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)}, with header
 * {@code {"alg":"RS256","kid":"<sender's signing key id>"}} and the signature computed over the ASCII
 * of the first two parts. It is NOT the direct API's x-jws-signature: that one is RFC 7797
 * (b64=false, signed over the raw body) and cannot be reused here.
 *
 * <p>The JWE is Compact Serialization, RSA-OAEP-256 + A256GCM, with cty "JWT".
 */
public final class IopCrypto {

    /**
     * What the recipient gets from an encryptedPayload: the business payload, the kid of the
     * sender's signing key, the decrypted plaintext (the inner compact JWS) and the inner
     * signature in detached form, header..signature (RFC 7515).
     */
    public record Decrypted(byte[] payload, String signerKid, String jws, String signature) {}

    /** Returns the sender's public signing key for a kid. In production it reads the CR. */
    @FunctionalInterface
    public interface KeyLookup {
        RSAPublicKey forKid(String kid) throws IopCryptoException;
    }

    public static final class IopCryptoException extends Exception {
        private static final long serialVersionUID = 1L;
        public IopCryptoException(String msg) { super(msg); }
    }

    private static final Base64.Encoder B64E = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final SecureRandom RNG = new SecureRandom();

    // RSA-OAEP-256 = OAEP with SHA-256 AND MGF1 with SHA-256.
    // Java's default for "OAEPWithSHA-256AndMGF1Padding" uses MGF1-SHA-1, so set it explicitly.
    private static final OAEPParameterSpec OAEP_256 = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private IopCrypto() {}

    /** An RSA public key and its kid, taken from a public JWK. */
    public record RecipientKey(RSAPublicKey publicKey, String kid) {}

    /**
     * Turns the recipient's public encryption JWK (as published in the CR) into an RSA public key
     * and kid. Rejects keys not meant for encryption.
     */
    public static RecipientKey parseRecipientJwk(String jwk) throws IopCryptoException {
        return parseJwk(jwk, "enc", "RSA-OAEP-256", "wrapKey");
    }

    /**
     * Turns the sender's public signing JWK (as published in the CR) into an RSA public key and
     * kid. Rejects keys not meant for signatures.
     */
    public static RecipientKey parseSigningJwk(String jwk) throws IopCryptoException {
        return parseJwk(jwk, "sig", "RS256", "verify");
    }

    private static RecipientKey parseJwk(String jwk, String wantUse, String wantAlg, String wantOp)
            throws IopCryptoException {
        if (jwk == null || !jwk.strip().startsWith("{")) throw new IopCryptoException("JWK is not a JSON object");
        String kty = jsonString(jwk, "kty"), kid = jsonString(jwk, "kid");
        String use = jsonString(jwk, "use"), alg = jsonString(jwk, "alg");
        String n = jsonString(jwk, "n"), e = jsonString(jwk, "e");
        String keyOps = jsonArray(jwk, "key_ops");

        if (!"RSA".equals(kty)) throw new IopCryptoException("JWK kty must be \"RSA\"");
        if (hasMember(jwk, "d"))
            throw new IopCryptoException("JWK contains private key material (d); use the public JWK");
        if (kid == null || kid.isEmpty()) throw new IopCryptoException("JWK kid is required");
        if (use != null && !use.equals(wantUse)) throw new IopCryptoException("JWK use must be \"" + wantUse + "\"");
        if (alg != null && !alg.equals(wantAlg))
            throw new IopCryptoException("JWK alg must be \"" + wantAlg + "\"");
        if (keyOps != null && !keyOps.matches("(?s).*\"" + Pattern.quote(wantOp) + "\".*"))
            throw new IopCryptoException("JWK key_ops must include \"" + wantOp + "\"");

        byte[] nb, eb;
        try {
            nb = B64D.decode(n == null ? "" : n);
            eb = B64D.decode(e == null ? "" : e);
        } catch (IllegalArgumentException ex) {
            throw new IopCryptoException("JWK n or e is not valid base64url");
        }
        if (nb.length == 0 || eb.length == 0 || eb.length > 4)
            throw new IopCryptoException("JWK n or e is not valid base64url");
        BigInteger modulus = new BigInteger(1, nb), exponent = new BigInteger(1, eb);
        if (modulus.bitLength() < 2048) throw new IopCryptoException("RSA key must be at least 2048 bits");
        if (exponent.compareTo(BigInteger.valueOf(3)) < 0 || !exponent.testBit(0))
            throw new IopCryptoException("JWK e is not a valid RSA exponent");
        try {
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(modulus, exponent));
            return new RecipientKey(key, kid);
        } catch (GeneralSecurityException ex) {
            throw new IopCryptoException("JWK is not a valid RSA public key");
        }
    }

    /**
     * Signs payload as a compact JWS (RFC 7515, RS256):
     * {@code BASE64URL({"alg":"RS256","kid":kid}) "." BASE64URL(payload) "." BASE64URL(signature)}.
     */
    public static String signCompact(byte[] payload, RSAPrivateKey signingKey, String kid)
            throws IopCryptoException {
        if (kid == null || kid.isEmpty()) throw new IopCryptoException("signing kid is required");
        if (kid.contains("\"") || kid.contains("\\")) throw new IopCryptoException("invalid kid");
        String hdr = "{\"alg\":\"RS256\",\"kid\":\"" + kid + "\"}";
        String input = B64E.encodeToString(hdr.getBytes(StandardCharsets.UTF_8)) + "." + B64E.encodeToString(payload);
        try {
            Signature rs256 = Signature.getInstance("SHA256withRSA");
            rs256.initSign(signingKey);
            rs256.update(input.getBytes(StandardCharsets.US_ASCII));
            return input + "." + B64E.encodeToString(rs256.sign());
        } catch (GeneralSecurityException e) {
            throw new IopCryptoException("signing failed: " + e.getMessage());
        }
    }

    /**
     * Checks a compact JWS (RFC 7515, RS256) with the key keyFor returns for its kid.
     * Returns the decoded payload, the kid, the JWS and its detached signature.
     */
    public static Decrypted verifyCompact(String jws, KeyLookup keyFor) throws IopCryptoException {
        String[] p = jws == null ? new String[0] : jws.split("\\.", -1);
        if (p.length != 3 || p[0].isEmpty() || p[2].isEmpty()) throw new IopCryptoException("not a compact JWS");
        String hdr;
        byte[] payload, sig;
        try {
            hdr = new String(B64D.decode(p[0]), StandardCharsets.UTF_8);
            payload = B64D.decode(p[1]);
            sig = B64D.decode(p[2]);
        } catch (IllegalArgumentException e) {
            throw new IopCryptoException("not a compact JWS");
        }
        if (!"RS256".equals(jsonString(hdr, "alg"))) throw new IopCryptoException("JWS alg must be \"RS256\"");
        String kid = jsonString(hdr, "kid");
        if (kid == null || kid.isEmpty()) throw new IopCryptoException("JWS kid is required");
        if (hasMember(hdr, "b64") || hasMember(hdr, "crit"))
            throw new IopCryptoException("JWS must not carry b64 or crit: the inner JWS is RFC 7515");
        RSAPublicKey pub = keyFor.forKid(kid);
        try {
            Signature rs256 = Signature.getInstance("SHA256withRSA");
            rs256.initVerify(pub);
            rs256.update((p[0] + "." + p[1]).getBytes(StandardCharsets.US_ASCII));
            if (!rs256.verify(sig)) throw new IopCryptoException("JWS signature does not verify");
        } catch (GeneralSecurityException e) {
            throw new IopCryptoException("JWS signature does not verify");
        }
        return new Decrypted(payload, kid, jws, p[0] + ".." + p[2]);
    }

    /**
     * Signs payload with the sender's signing key (inner JWS, RFC 7515, RS256) and encrypts that
     * JWS as a compact JWE for the recipient whose public JWK (from the CR) is given. The JWK's kid
     * goes into the protected header.
     */
    public static String encryptPayload(byte[] payload, RSAPrivateKey signingKey, String signingKid,
                                        String recipientJwk) throws IopCryptoException {
        RecipientKey rk = parseRecipientJwk(recipientJwk);
        RSAPublicKey publicKey = rk.publicKey();
        String kid = rk.kid();
        if (kid.contains("\"") || kid.contains("\\")) throw new IopCryptoException("invalid kid");

        byte[] plaintext = signCompact(payload, signingKey, signingKid).getBytes(StandardCharsets.US_ASCII);

        // Part 1: protected header. Its base64url form is also the AES-GCM AAD.
        String hdr = "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\","
                + "\"kid\":\"" + kid + "\",\"cty\":\"JWT\"}";
        String protectedB64 = B64E.encodeToString(hdr.getBytes(StandardCharsets.UTF_8));

        byte[] cek = new byte[32];   // fresh 256-bit CEK
        byte[] iv = new byte[12];    // fresh 96-bit IV
        RNG.nextBytes(cek);
        RNG.nextBytes(iv);
        try {
            // Part 2: CEK wrapped with RSA-OAEP-256.
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_256);
            byte[] encKey = rsa.doFinal(cek);

            // Parts 3-5: AES-256-GCM. Java returns ciphertext || 16-byte tag.
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            aes.updateAAD(protectedB64.getBytes(StandardCharsets.US_ASCII));
            byte[] sealed = aes.doFinal(plaintext);
            int n = sealed.length - 16;

            return protectedB64 + "." + B64E.encodeToString(encKey) + "." + B64E.encodeToString(iv) + "."
                    + B64E.encodeToString(Arrays.copyOfRange(sealed, 0, n)) + "."
                    + B64E.encodeToString(Arrays.copyOfRange(sealed, n, sealed.length));
        } catch (GeneralSecurityException e) {
            throw new IopCryptoException("encryption failed: " + e.getMessage());
        } finally {
            Arrays.fill(cek, (byte) 0);
        }
    }

    /**
     * Opens a compact JWE with the recipient's private key, then verifies the inner JWS with the
     * sender's signing key (senderKey, looked up by the JWS kid). The caller still checks that the
     * signer is the expected party: Initiator.id on a request, the Target.id the request was sent
     * to on a response.
     */
    public static Decrypted decryptPayload(String compactJwe, RSAPrivateKey privateKey, KeyLookup senderKey)
            throws IopCryptoException {
        String[] p = compactJwe == null ? new String[0] : compactJwe.split("\\.", -1);
        if (p.length != 5) throw new IopCryptoException("iopPayload must have five parts");

        byte[] encKey, iv, ciphertext, tag;
        String hdr;
        try {
            hdr = new String(B64D.decode(p[0]), StandardCharsets.UTF_8);
            encKey = B64D.decode(p[1]);
            iv = B64D.decode(p[2]);
            ciphertext = B64D.decode(p[3]);
            tag = B64D.decode(p[4]);
        } catch (IllegalArgumentException e) {
            throw new IopCryptoException("malformed iopPayload");
        }
        if (!"RSA-OAEP-256".equals(jsonString(hdr, "alg")) || !"A256GCM".equals(jsonString(hdr, "enc"))
                || !"JWT".equals(jsonString(hdr, "cty")))
            throw new IopCryptoException("unsupported alg/enc/cty");
        if (iv.length != 12 || tag.length != 16) throw new IopCryptoException("malformed iopPayload");

        byte[] cek = null;
        byte[] plaintext;
        try {
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.DECRYPT_MODE, privateKey, OAEP_256);
            cek = rsa.doFinal(encKey);
            if (cek.length != 32) throw new GeneralSecurityException("bad CEK length");

            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            aes.updateAAD(p[0].getBytes(StandardCharsets.US_ASCII));
            aes.update(ciphertext);
            plaintext = aes.doFinal(tag); // throws AEADBadTagException on any tampering
        } catch (GeneralSecurityException e) {
            throw new IopCryptoException("decryption failed"); // keep generic
        } finally {
            if (cek != null) Arrays.fill(cek, (byte) 0);
        }

        // The plaintext is the inner compact JWS; verify it before using the payload.
        return verifyCompact(new String(plaintext, StandardCharsets.US_ASCII), senderKey);
    }

    // Raw text of an array member, e.g. ["wrapKey","encrypt"]; null if absent.
    private static String jsonArray(String json, String name) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(\\[[^\\]]*\\])").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static boolean hasMember(String json, String name) {
        return Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:").matcher(json).find();
    }

    // Minimal reader for flat string members.
    // Replace with your JSON library (Jackson, Gson) in production.
    private static String jsonString(String json, String name) {
        String regex = "\"" + Pattern.quote(name) + "\"\\s*:\\s*\"([^\"\\\\]*)\"";
        Matcher m = Pattern.compile(regex).matcher(json);
        return m.find() ? m.group(1) : null;
    }
}
