package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gateway as the Target: errorSource on its error replies, the core's own response signature,
 * and the hop's linkedAAs check. Envelopes are sent straight to the Target's /iop, as the
 * Connected-AA would.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TargetSideTest {

    TestNet net;
    TestNet.Party fiu;  // fiu-test-901: Initiator
    TestNet.Party aa2;  // aa-test-902: Connected-AA (the sender on the terminating leg)
    TestNet.Party aa3;  // aa-test-903: Customer-AA (Target)
    TestNet.Party aa5;  // aa-test-905: hop whose linkedAAs come from its core and are never pushed

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        fiu = net.add("fiu-test-901", "FIU", "FIU");
        aa2 = net.add("aa-test-902", "AA", "AA");
        aa3 = net.add("aa-test-903", "AA", "AA");
        aa5 = net.add("aa-test-905", "AA", "AA");
        aa5.overrides.put("linkedAAs", "linkedAAs: {source: api, token: \"${GW_TOKEN}\", url: \"http://127.0.0.1:1/linkedAAs\"}");
        net.start(aa2);
        net.start(aa3);
        net.start(aa5);
    }

    @AfterAll
    void stop() {
        net.close();
    }

    private static final byte[] PAYLOAD = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"ConsentDetail\":{}}")
            .getBytes(StandardCharsets.UTF_8);

    /** A Connected-AA → Customer-AA envelope for /iop/Consent; the inner JWS signed with {@code innerKey}. */
    private byte[] terminating(org.sahamati.iopgw.crypto.KeyRing.PrivKey innerKey) throws Exception {
        String inner = Jose.signCompact(PAYLOAD, innerKey, "RS256");
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode i = env.putObject("Initiator");
        i.put("type", "FIU");
        i.put("id", fiu.id);
        env.put("encryptedPayload", Jose.encrypt(inner, new PubKey(aa3.id + "-enc", aa3.encPub)));
        return Json.bytes(env);
    }

    private HttpResponse<byte[]> post(TestNet.Party to, String keyHeader, TestNet.Party from, byte[] body) throws Exception {
        Map<String, String> h = new LinkedHashMap<>();
        h.put(keyHeader, from.apiKey());
        h.put("x-jws-signature", Jose.signDetached(body, from.sig, "RS256"));
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(to.publicUrl() + "/iop/Consent"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        h.forEach(b::header);
        return net.client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private HttpResponse<byte[]> toTarget(byte[] body) throws Exception {
        return post(aa3, "x-conn_aa_api_key", aa2, body);
    }

    private static String inner(JsonNode reply, TestNet.Party recipient) throws Exception {
        JWEObject jwe = JWEObject.parse(reply.get("encryptedPayload").asText());
        jwe.decrypt(new RSADecrypter(recipient.enc.key()));
        return jwe.getPayload().toString();
    }

    private void restoreCore() {
        aa3.core.answer = c -> TestNet.CoreAnswer.json(200, "{\"ver\":\"2.0.0\",\"txnid\":\"t-ok\",\"ok\":true}");
    }

    // ------------------------------------------------------------------------------------

    @Test
    void successReplyHasNoErrorSource() throws Exception {
        HttpResponse<byte[]> r = toTarget(terminating(fiu.sig));
        assertEquals(200, r.statusCode(), new String(r.body()));
        JsonNode b = Json.parseObject(r.body());
        assertNull(b.get("errorSource"));
        assertNotNull(b.get("encryptedPayload"));
    }

    @Test
    void coreErrorReplyCarriesErrorSourceOfTheTarget() throws Exception {
        aa3.core.answer = c -> TestNet.CoreAnswer.json(400, "{\"ver\":\"2.0.0\",\"txnid\":\"t-1\",\"errorCode\":\"InvalidConsentDetail\",\"errorMsg\":\"synthetic\"}");
        try {
            HttpResponse<byte[]> r = toTarget(terminating(fiu.sig));
            assertEquals(400, r.statusCode());
            JsonNode b = Json.parseObject(r.body());
            assertEquals("{\"type\":\"AA\",\"id\":\"aa-test-903\"}", b.get("errorSource").toString());
            assertNotNull(b.get("encryptedPayload"), "the core's error stays encrypted for the Initiator");
            assertTrue(Jose.verifyDetached(r.headers().firstValue("x-jws-signature").orElseThrow(), r.body(), List.of(aa3.sigPubKey())));
        } finally {
            restoreCore();
        }
    }

    @Test
    void ownErrorAsTargetCarriesErrorSource() throws Exception {
        // the inner JWS is signed by the wrong participant: the Target's gateway refuses it itself
        HttpResponse<byte[]> r = toTarget(terminating(aa2.sig));
        assertEquals(401, r.statusCode());
        JsonNode b = Json.parseObject(r.body());
        assertEquals("Initiator signature does not verify", Json.text(b, "errorMsg"));
        assertEquals("{\"type\":\"AA\",\"id\":\"aa-test-903\"}", b.get("errorSource").toString());
    }

    @Test
    void hopNeverAddsItsOwnErrorSource() throws Exception {
        // a forwarding-leg error at a hop (Target is the hop itself)
        byte[] env = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"correlationId\":\"" + UUID.randomUUID()
                + "\",\"Target\":{\"type\":\"AA\",\"id\":\"aa-test-902\"},\"encryptedPayload\":\"a.b.c.d.e\"}")
                .getBytes(StandardCharsets.UTF_8);
        HttpResponse<byte[]> r = post(aa2, "client_api_key", fiu, env);
        assertEquals(400, r.statusCode());
        assertNull(Json.parseObject(r.body()).get("errorSource"));
    }

    @Test
    void coreResponseSignatureIsCheckedAndNotCarried() throws Exception {
        // a valid signature of the core's own: accepted; the inner JWS is the gateway's, with the same keys
        aa3.core.answer = c -> {
            byte[] body = "{\"ver\":\"2.0.0\",\"txnid\":\"t-3\",\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            try {
                return new TestNet.CoreAnswer(200, body, Map.of("x-jws-signature", Jose.signDetached(body, aa3.sig, "RS256")));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
        try {
            HttpResponse<byte[]> r = toTarget(terminating(fiu.sig));
            assertEquals(200, r.statusCode(), new String(r.body()));
            String inner = inner(Json.parseObject(r.body()), fiu);
            byte[] payload = Jose.verifyCompact(inner, List.of(aa3.sigPubKey()));
            assertArrayEquals("{\"ver\":\"2.0.0\",\"txnid\":\"t-3\",\"ok\":true}".getBytes(StandardCharsets.UTF_8), payload);
        } finally {
            restoreCore();
        }

        // a signature made with another participant's key: 502 InternalError to the Initiator
        aa3.core.answer = c -> {
            byte[] body = "{\"ver\":\"2.0.0\",\"txnid\":\"t-4\",\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            try {
                return new TestNet.CoreAnswer(200, body, Map.of("x-jws-signature", Jose.signDetached(body, aa2.sig, "RS256")));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
        try {
            HttpResponse<byte[]> r = toTarget(terminating(fiu.sig));
            assertEquals(502, r.statusCode());
            JsonNode b = Json.parseObject(r.body());
            assertEquals("InternalError", Json.text(b, "errorCode"));
            assertEquals("{\"type\":\"AA\",\"id\":\"aa-test-903\"}", b.get("errorSource").toString());
        } finally {
            restoreCore();
        }
    }

    @Test
    void hopWithoutLinkedAAsAnswers503ForAnAaTarget() throws Exception {
        aa3.core.calls.clear();
        String inner = Jose.signCompact(PAYLOAD, fiu.sig, "RS256");
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode t = env.putObject("Target");
        t.put("type", "AA");
        t.put("id", aa3.id);
        env.put("encryptedPayload", Jose.encrypt(inner, new PubKey(aa3.id + "-enc", aa3.encPub)));
        HttpResponse<byte[]> r = post(aa5, "client_api_key", fiu, Json.bytes(env));
        assertEquals(503, r.statusCode(), new String(r.body()));
        JsonNode b = Json.parseObject(r.body());
        assertEquals("InternalError", Json.text(b, "errorCode"));
        assertEquals("linkedAAs not loaded", Json.text(b, "errorMsg"));
        assertTrue(aa3.core.calls.isEmpty(), "the Target is not called");
    }
}
