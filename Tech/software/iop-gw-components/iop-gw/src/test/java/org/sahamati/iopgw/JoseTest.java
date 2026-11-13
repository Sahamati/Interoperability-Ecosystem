package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.crypto.KeyRing;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.http.Json;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** encryptedPayload format; the JWS profile. */
class JoseTest {

    @Test
    void onlyRs256SignaturesVerify() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        byte[] payload = "{\"ver\":\"2.0.0\",\"txnid\":\"t-2\"}".getBytes(StandardCharsets.UTF_8);
        List<PubKey> keys = List.of(new PubKey("aa-test-001-sig", (RSAPublicKey) kp.getPublic()));
        KeyRing.PrivKey signer = new KeyRing.PrivKey("aa-test-001-sig", (RSAPrivateKey) kp.getPrivate(), true, null, null);

        assertTrue(Jose.verifyDetached(Jose.signDetached(payload, signer, "RS256"), payload, keys));

        // the same key, PS256: refused, detached and compact alike
        com.nimbusds.jose.JWSObject ps = new com.nimbusds.jose.JWSObject(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.PS256).keyID("aa-test-001-sig").build(),
                new com.nimbusds.jose.Payload(payload));
        ps.sign(new com.nimbusds.jose.crypto.RSASSASigner(kp.getPrivate()));
        assertFalse(Jose.verifyDetached(ps.serialize(true), payload, keys));
        assertNull(Jose.verifyCompact(ps.serialize(), keys));
    }

    @Test
    void xJwsSignatureIsRfc7797Only() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        byte[] payload = "{\"ver\":\"2.0.0\",\"txnid\":\"t-3\"}".getBytes(StandardCharsets.UTF_8);
        List<PubKey> keys = List.of(new PubKey("aa-test-001-sig", (RSAPublicKey) kp.getPublic()));
        KeyRing.PrivKey signer = new KeyRing.PrivKey("aa-test-001-sig", (RSAPrivateKey) kp.getPrivate(), true, null, null);

        // what the gateway signs: header {alg, kid, b64:false, crit:[b64]}, over the raw payload
        String sig = Jose.signDetached(payload, signer, "RS256");
        JsonNode h = Json.MAPPER.readTree(Base64.getUrlDecoder().decode(sig.split("\\.")[0]));
        assertEquals("RS256", h.get("alg").asText());
        assertEquals("aa-test-001-sig", h.get("kid").asText());
        assertFalse(h.get("b64").asBoolean());
        assertEquals("[\"b64\"]", h.get("crit").toString());
        assertTrue(Jose.verifyDetached(sig, payload, keys));
        assertFalse(Jose.verifyDetached(sig, "{\"tampered\":1}".getBytes(StandardCharsets.UTF_8), keys));

        // the signing input of RFC 7797 is BASE64URL(header) + "." + the raw payload
        java.security.Signature s = java.security.Signature.getInstance("SHA256withRSA");
        s.initVerify(kp.getPublic());
        s.update((sig.split("\\.")[0] + ".").getBytes(StandardCharsets.US_ASCII));
        s.update(payload);
        assertTrue(s.verify(Base64.getUrlDecoder().decode(sig.split("\\.", -1)[2])));

        // a standard detached JWS (encoded payload) is refused as x-jws-signature, and accepted by
        // the RFC 7515 check used for the signature a core receives
        String encoded = Jose.detach(Jose.signCompact(payload, signer, "RS256"));
        assertFalse(Jose.verifyDetached(encoded, payload, keys));
        assertTrue(Jose.verifyDetachedEncoded(encoded, payload, keys));
        assertFalse(Jose.verifyDetachedEncoded(sig, payload, keys), "RFC 7797 is not accepted where RFC 7515 is expected");

        // b64:false without crit, or with another crit value: refused
        assertFalse(Jose.verifyDetached(rfc7797(kp, payload, "{\"alg\":\"RS256\",\"kid\":\"aa-test-001-sig\",\"b64\":false}"), payload, keys));
        assertFalse(Jose.verifyDetached(rfc7797(kp, payload, "{\"alg\":\"RS256\",\"kid\":\"aa-test-001-sig\",\"b64\":false,\"crit\":[\"b64\",\"exp\"]}"), payload, keys));
        assertFalse(Jose.verifyDetached(rfc7797(kp, payload, "{\"alg\":\"PS256\",\"kid\":\"aa-test-001-sig\",\"b64\":false,\"crit\":[\"b64\"]}"), payload, keys));
        assertFalse(Jose.verifyDetached(rfc7797(kp, payload, "{\"alg\":\"RS256\",\"kid\":\"other-kid\",\"b64\":false,\"crit\":[\"b64\"]}"), payload, keys));
        // the same header built by hand verifies
        assertTrue(Jose.verifyDetached(rfc7797(kp, payload, "{\"alg\":\"RS256\",\"kid\":\"aa-test-001-sig\",\"b64\":false,\"crit\":[\"b64\"]}"), payload, keys));
    }

    @Test
    void jweWithoutCtyIsAccepted() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair enc = g.generateKeyPair();
        com.nimbusds.jose.JWEObject jwe = new com.nimbusds.jose.JWEObject(
                new com.nimbusds.jose.JWEHeader.Builder(com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256, com.nimbusds.jose.EncryptionMethod.A256GCM)
                        .keyID("aa-test-003-enc").build(),
                new com.nimbusds.jose.Payload("a.b.c"));
        jwe.encrypt(new com.nimbusds.jose.crypto.RSAEncrypter((RSAPublicKey) enc.getPublic()));
        KeyRing ring = new KeyRing(List.of(new KeyRing.PrivKey("aa-test-003-enc", (RSAPrivateKey) enc.getPrivate(), true, null, null)));
        assertEquals("a.b.c", Jose.decrypt(jwe.serialize(), ring));
    }

    /** An RS256 signature (SHA256withRSA) over BASE64URL(header) + "." + payload, with the given header. */
    private static String rfc7797(KeyPair kp, byte[] payload, String headerJson) throws Exception {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        java.security.Signature s = java.security.Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update((header + ".").getBytes(StandardCharsets.US_ASCII));
        s.update(payload);
        return header + ".." + Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
    }

    @Test
    void encryptedPayloadProtectedHeaderHasAlgEncKidAndCty() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair sig = g.generateKeyPair();
        KeyPair enc = g.generateKeyPair();
        byte[] payload = "{\"ver\":\"2.0.0\",\"txnid\":\"t-1\"}".getBytes(StandardCharsets.UTF_8);
        KeyRing.PrivKey signer = new KeyRing.PrivKey("fiu-test-001-sig", (RSAPrivateKey) sig.getPrivate(), true, null, null);

        String jws = Jose.signCompact(payload, signer, "RS256");
        String jwe = Jose.encrypt(jws, new PubKey("aa-test-003-enc", (RSAPublicKey) enc.getPublic()));

        String[] parts = jwe.split("\\.", -1);
        assertEquals(5, parts.length);
        JsonNode h = Json.MAPPER.readTree(Base64.getUrlDecoder().decode(parts[0]));
        assertEquals("RSA-OAEP-256", h.get("alg").asText());
        assertEquals("A256GCM", h.get("enc").asText());
        assertEquals("aa-test-003-enc", h.get("kid").asText());
        assertEquals("JWT", h.get("cty").asText());

        KeyRing ring = new KeyRing(List.of(new KeyRing.PrivKey("aa-test-003-enc", (RSAPrivateKey) enc.getPrivate(), true, null, null)));
        String inner = Jose.decrypt(jwe, ring);
        assertArrayEquals(payload, Jose.verifyCompact(inner, List.of(new PubKey("fiu-test-001-sig", (RSAPublicKey) sig.getPublic()))));
    }
}
