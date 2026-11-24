package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.http.Json;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Single-tenant mode, the default: no {@code Core-Entity-Id} to
 * the core, {@code Core-Entity-Id} and {@code Target-Id} ignored, and the JWE {@code kid} rule.
 *
 * <pre>
 * fip-test-e01  FIP, single-tenant
 * aa-test-e11   Inter-AA of the FIP (hop)
 * aa-test-e12   Origin-AA (Target of the FIP's notifications)
 * </pre>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SingleTenantE2ETest {

    TestNet net;
    TestNet.Party fip;
    TestNet.Party aa1;
    TestNet.Party aa2;

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        fip = net.add("fip-test-e01", "FIP", "FIP");
        aa1 = net.add("aa-test-e11", "AA", "AA");
        aa2 = net.add("aa-test-e12", "AA", "AA");
        fip.linked = List.of(aa1.id);
        fip.aigYaml = "aig:\n  aa:\n    - aa-test-e11: [aa-test-e12]\n";
        net.start();
    }

    @AfterAll
    void stop() {
        net.close();
    }

    private static final byte[] PAYLOAD = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"ConsentDetail\":{}}")
            .getBytes(StandardCharsets.UTF_8);

    private byte[] envelope(String targetId, String encryptedPayload) {
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        if (targetId != null) {
            ObjectNode t = env.putObject("Target");
            t.put("type", "AA");
            t.put("id", targetId);
        } else {
            ObjectNode i = env.putObject("Initiator");
            i.put("type", "AA");
            i.put("id", aa1.id);
        }
        if (encryptedPayload != null) {
            env.put("encryptedPayload", encryptedPayload);
        }
        return Json.bytes(env);
    }

    private HttpResponse<byte[]> send(TestNet.Party to, String path, String keyHeader, TestNet.Party from, byte[] body,
                                      Map<String, String> extra) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(to.publicUrl() + path))
                .header(keyHeader, from.apiKey())
                .header("x-jws-signature", Jose.signDetached(body, from.sig, "RS256"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        extra.forEach(b::header);
        return net.client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private static String withoutKid(RSAPublicKey key, String plaintext) throws Exception {
        JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT").build(),
                new Payload(plaintext.getBytes(StandardCharsets.UTF_8)));
        jwe.encrypt(new RSAEncrypter(key));
        return jwe.serialize();
    }

    /** No gateway → core request carries Core-Entity-Id; Target-Id is ignored. */
    @Test
    void noCoreEntityIdTowardsTheCoreAndTargetIdIgnored() throws Exception {
        fip.core.calls.clear();
        HttpResponse<byte[]> hb = send(fip, "/iop/Heartbeat", "x-inter_aa_api_key", aa1, envelope(null, null),
                Map.of("Target-Id", "fip-test-other"));
        assertEquals(200, hb.statusCode(), new String(hb.body()));
        String jwe = Jose.encrypt(Jose.signCompact(PAYLOAD, aa1.sig, "RS256"), fip.encPubKey());
        HttpResponse<byte[]> consent = send(fip, "/iop/Consent", "x-inter_aa_api_key", aa1, envelope(null, jwe), Map.of());
        assertEquals(200, consent.statusCode(), new String(consent.body()));
        assertEquals(2, fip.core.calls.size());
        for (TestNet.CoreCall c : fip.core.calls) {
            assertNull(c.header("Core-Entity-Id"), c.path());
        }
    }

    /** Core-Entity-Id from the core naming another id, or empty, is ignored. */
    @Test
    void coreEntityIdFromTheCoreIsIgnored() throws Exception {
        for (String value : List.of("fip-test-other", "")) {
            aa2.core.calls.clear();
            Map<String, String> h = TestNet.coreHeaders("AA", aa2.id, UUID.randomUUID().toString());
            h.put("Core-Entity-Id", value);
            HttpResponse<byte[]> r = net.call(fip, "POST", "/fip-sgw/Consent/Notification", h,
                    "{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"ConsentStatusNotification\":{}}");
            assertEquals(200, r.statusCode(), new String(r.body()));
            assertEquals("{\"type\":\"FIP\",\"id\":\"fip-test-e01\"}", aa2.core.calls.get(0).header("Initiator-Entity"));
        }
        // a linkedAAs push naming another id: no Core-Entity-Id error; the list is configured, so 404
        Map<String, String> h = Map.of("Authorization", "Bearer " + TestNet.GW_TOKEN, "Core-Entity-Id", "fip-test-other");
        HttpResponse<byte[]> push = net.call(fip, "POST", "/fip-sgw/linkedAAs", h, "{\"linkedAAs\":[\"aa-test-e11\"]}");
        assertEquals(404, push.statusCode());
        assertEquals("InvalidURI", Json.text(Json.parseObject(push.body()), "errorCode"));
        assertTrue(push.headers().firstValue("IOP-Gw-Error").isEmpty(), "push replies carry no headers");
    }

    /** One stats record per interval, for the one entity. */
    @Test
    void oneStatsRecord() {
        List<String> lines = fip.gw.gateway.stats.flush();
        assertEquals(1, lines.size(), lines.toString());
        assertTrue(lines.get(0).contains("|fip-test-e01|FIP|"), lines.get(0));
    }

    /** A terminating request without a kid, or with a kid that is not this entity's, gets 400; the core is not called. */
    @Test
    void terminatingRequestsNeedTheEntitysKid() throws Exception {
        fip.core.calls.clear();
        String inner = Jose.signCompact(PAYLOAD, aa1.sig, "RS256");
        HttpResponse<byte[]> noKid = send(fip, "/iop/Consent", "x-inter_aa_api_key", aa1, envelope(null, withoutKid(fip.encPub, inner)), Map.of());
        assertEquals(400, noKid.statusCode());
        JsonNode b = Json.parseObject(noKid.body());
        assertEquals("InvalidRequest", Json.text(b, "errorCode"));
        assertEquals("encryptedPayload has no kid in its JWE header", Json.text(b, "errorMsg"));
        assertTrue(Jose.verifyDetached(noKid.headers().firstValue("x-jws-signature").orElseThrow(), noKid.body(), List.of(fip.sigPubKey())),
                "single-tenant: every error is signed by the one entity");
        HttpResponse<byte[]> otherKid = send(fip, "/iop/Consent", "x-inter_aa_api_key", aa1,
                envelope(null, Jose.encrypt(inner, new PubKey("fip-test-e01-old-enc", fip.encPub))), Map.of());
        assertEquals(400, otherKid.statusCode());
        assertEquals("encryptedPayload not decryptable", Json.text(Json.parseObject(otherKid.body()), "errorMsg"));
        assertTrue(fip.core.calls.isEmpty());
    }

    /** An AA hop does not check the kid: it forwards a JWE without one to the Target unchanged. */
    @Test
    void anAaHopForwardsAJweWithoutKid() throws Exception {
        String jwe = withoutKid(aa2.encPub, Jose.signCompact(PAYLOAD, fip.sig, "RS256"));
        HttpResponse<byte[]> r = send(aa1, "/iop/Consent/Notification", "fip_api_key", fip, envelope(aa2.id, jwe), Map.of());
        // the hop forwarded it; the Target refused it (no kid) and the hop relays that answer
        assertEquals(400, r.statusCode(), new String(r.body()));
        JsonNode b = Json.parseObject(r.body());
        assertEquals("IopDownstreamError", Json.text(b, "errorCode"));
        assertEquals("{\"type\":\"AA\",\"id\":\"aa-test-e12\"}", b.get("errorSource").toString());
    }
}
