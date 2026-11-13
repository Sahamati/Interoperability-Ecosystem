package org.sahamati.iopgw.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.List;

/**
 * JOSE operations within the cryptographic profile. JWS: RS256 only. {@code x-jws-signature} is a
 * detached JWS with an unencoded payload (RFC 7797); the inner JWS inside {@code encryptedPayload}
 * is a compact JWS with a base64url-encoded payload (RFC 7515), where {@code b64: false} and
 * {@code crit} are rejected. {@code alg: none} and HMAC are rejected. JWE: RSA-OAEP-256 / A256GCM
 * only, {@code zip} rejected.
 */
public final class Jose {
    private Jose() {}

    public static final class JoseException extends Exception {
        public JoseException(String msg) {
            super(msg);
        }
    }

    private static JWSAlgorithm alg(String name) {
        return JWSAlgorithm.RS256; // the only JWS algorithm in the profile (jws.algorithm is checked at start-up)
    }

    /**
     * {@code x-jws-signature}: a detached JWS ({@code header..signature}) with an unencoded payload
     * (RFC 7797): protected header {@code {"alg":"RS256","kid","b64":false,"crit":["b64"]}}, signed
     * over {@code BASE64URL(header) + "." + payload}, the payload bytes as they are.
     */
    public static String signDetached(byte[] payload, KeyRing.PrivKey key, String algorithm) throws JoseException {
        try {
            com.fasterxml.jackson.databind.node.ObjectNode h = org.sahamati.iopgw.http.Json.object();
            h.put("alg", "RS256");
            h.put("kid", key.kid());
            h.put("b64", false);
            h.putArray("crit").add("b64");
            String header = Base64URL.encode(org.sahamati.iopgw.http.Json.bytes(h)).toString();
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(key.key());
            sig.update(signingInput(header, payload));
            return header + ".." + Base64URL.encode(sig.sign());
        } catch (GeneralSecurityException e) {
            throw new JoseException("unable to sign");
        }
    }

    private static byte[] signingInput(String header, byte[] payload) {
        byte[] h = (header + ".").getBytes(StandardCharsets.US_ASCII);
        byte[] in = new byte[h.length + payload.length];
        System.arraycopy(h, 0, in, 0, h.length);
        System.arraycopy(payload, 0, in, h.length, payload.length);
        return in;
    }

    /** Compact JWS over {@code payload}. */
    public static String signCompact(byte[] payload, KeyRing.PrivKey key, String algorithm) throws JoseException {
        return sign(payload, key, algorithm).serialize();
    }

    private static JWSObject sign(byte[] payload, KeyRing.PrivKey key, String algorithm) throws JoseException {
        try {
            JWSObject jws = new JWSObject(new JWSHeader.Builder(alg(algorithm)).keyID(key.kid()).build(), new Payload(payload));
            jws.sign(new RSASSASigner(key.key()));
            return jws;
        } catch (JOSEException e) {
            throw new JoseException("unable to sign");
        }
    }

    /**
     * True when {@code detached} is a valid {@code x-jws-signature} over {@code payload} by one of
     * {@code keys}: RFC 7797 only (RS256, {@code "b64": false}, {@code "crit": ["b64"]} exactly); a
     * detached JWS with an encoded payload is refused.
     */
    public static boolean verifyDetached(String detached, byte[] payload, List<PubKey> keys) {
        if (detached == null || payload == null) {
            return false;
        }
        String[] parts = detached.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || !parts[1].isEmpty() || parts[2].isEmpty()) {
            return false;
        }
        try {
            com.fasterxml.jackson.databind.JsonNode h = org.sahamati.iopgw.http.Json.MAPPER.readTree(new Base64URL(parts[0]).decode());
            if (h == null || !h.isObject() || !"RS256".equals(h.path("alg").asText(null))) {
                return false;
            }
            com.fasterxml.jackson.databind.JsonNode b64 = h.get("b64");
            com.fasterxml.jackson.databind.JsonNode crit = h.get("crit");
            if (b64 == null || !b64.isBoolean() || b64.asBoolean()
                    || crit == null || !crit.isArray() || crit.size() != 1 || !"b64".equals(crit.get(0).asText(null))) {
                return false;
            }
            String kid = h.hasNonNull("kid") ? h.get("kid").asText() : null;
            byte[] input = signingInput(parts[0], payload);
            byte[] signature = new Base64URL(parts[2]).decode();
            for (PubKey k : keys) {
                if (kid != null && !kid.equals(k.kid())) {
                    continue;
                }
                Signature v = Signature.getInstance("SHA256withRSA");
                v.initVerify(k.key());
                v.update(input);
                if (v.verify(signature)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * True when {@code detached} is a detached JWS with an encoded payload (RFC 7515) over
     * {@code payload}: the form of the signature the gateway passes to its core, taken from the
     * Initiator's or the Target's inner JWS.
     */
    public static boolean verifyDetachedEncoded(String detached, byte[] payload, List<PubKey> keys) {
        if (detached == null || payload == null) {
            return false;
        }
        String[] parts = detached.split("\\.", -1);
        if (parts.length != 3 || !parts[1].isEmpty()) {
            return false;
        }
        try {
            return verify(JWSObject.parse(detached, new Payload(payload)), keys);
        } catch (Exception e) {
            return false;
        }
    }

    /** Verifies a compact JWS and returns its payload bytes, or null when it does not verify. */
    public static byte[] verifyCompact(String compact, List<PubKey> keys) {
        try {
            JWSObject jws = JWSObject.parse(compact);
            return verify(jws, keys) ? jws.getPayload().toBytes() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean verify(JWSObject jws, List<PubKey> keys) throws JOSEException {
        JWSHeader h = jws.getHeader();
        if (!JWSAlgorithm.RS256.equals(h.getAlgorithm())) {
            return false;
        }
        if (!h.isBase64URLEncodePayload() || (h.getCriticalParams() != null && !h.getCriticalParams().isEmpty())) {
            return false;
        }
        String kid = h.getKeyID();
        for (PubKey k : keys) {
            if (kid != null && !kid.equals(k.kid())) {
                continue;
            }
            if (jws.verify(new RSASSAVerifier(k.key()))) {
                return true;
            }
        }
        return false;
    }

    /** True when {@code s} is shaped like a compact JWS (three parts). */
    public static boolean isCompactJws(String s) {
        return s != null && s.split("\\.", -1).length == 3;
    }

    /** True when {@code s} is shaped like a compact JWE (five parts). */
    public static boolean isCompactJwe(String s) {
        return s != null && s.split("\\.", -1).length == 5;
    }

    /** The detached form ({@code header..signature}) of a compact JWS. */
    public static String detach(String compact) {
        String[] parts = compact.split("\\.", -1);
        return parts[0] + ".." + parts[2];
    }

    /** The decoded payload of a compact JWS (no verification). */
    public static byte[] payloadOf(String compact) {
        return new Base64URL(compact.split("\\.", -1)[1]).decode();
    }

    public static String encrypt(String plaintext, PubKey key) throws JoseException {
        try {
            // cty "JWT": the plaintext is a signed message (compact JWS) to verify after decryption
            // (Sahamati "Encryption in Interoperability" v1.0, protected header parameters).
            JWEObject jwe = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).keyID(key.kid())
                            .contentType("JWT").build(),
                    new Payload(plaintext.getBytes(StandardCharsets.UTF_8)));
            jwe.encrypt(new RSAEncrypter(key.key()));
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new JoseException("unable to encrypt");
        }
    }

    /** Decrypts a compact JWE with the usable keys of {@code ring}, matched by kid. */
    public static String decrypt(String compact, KeyRing ring) throws JoseException {
        JWEObject jwe;
        try {
            jwe = JWEObject.parse(compact);
        } catch (Exception e) {
            throw new JoseException("not a compact JWE");
        }
        JWEHeader h = jwe.getHeader();
        if (!JWEAlgorithm.RSA_OAEP_256.equals(h.getAlgorithm()) || !EncryptionMethod.A256GCM.equals(h.getEncryptionMethod())
                || h.getCompressionAlgorithm() != null
                || (h.getCriticalParams() != null && !h.getCriticalParams().isEmpty())) {
            throw new JoseException("JWE outside the cryptographic profile");
        }
        String kid = h.getKeyID();
        for (KeyRing.PrivKey k : ring.usable()) {
            if (kid != null && !kid.equals(k.kid())) {
                continue;
            }
            try {
                JWEObject attempt = JWEObject.parse(compact);
                attempt.decrypt(new RSADecrypter(k.key()));
                return attempt.getPayload().toString();
            } catch (Exception ignored) {
                // try the next key
            }
        }
        throw new JoseException("unable to decrypt");
    }
}
