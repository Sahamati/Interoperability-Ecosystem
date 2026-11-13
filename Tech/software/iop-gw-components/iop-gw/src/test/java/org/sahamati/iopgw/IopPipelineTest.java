package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Rejections on the public /iop surface, all signed by the gateway. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IopPipelineTest {

    TestNet net;
    TestNet.Party fiu;
    TestNet.Party aa2;
    TestNet.Party aa3;

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        fiu = net.add("fiu-test-101", "FIU", "FIU");
        aa2 = net.add("aa-test-102", "AA", "AA");
        aa3 = net.add("aa-test-103", "AA", "AA");
        fiu.aigYaml = "aig:\n  aa:\n    - aa-test-102: [aa-test-103]\n";
        fiu.linked = List.of("aa-test-102");
        net.start(fiu);
        net.start(aa2);
        net.start(aa3);
    }

    @AfterAll
    void stop() {
        net.close();
    }

    /** A valid FIU → Connected-AA envelope for /iop/Consent, encrypted to aa-test-103. */
    private ObjectNode envelope() throws Exception {
        byte[] payload = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\"}").getBytes(StandardCharsets.UTF_8);
        String inner = Jose.signCompact(payload, fiu.sig, "RS256");
        String jwe = Jose.encrypt(inner, new PubKey(aa3.id + "-enc", aa3.encPub));
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode t = env.putObject("Target");
        t.put("type", "AA");
        t.put("id", aa3.id);
        env.put("encryptedPayload", jwe);
        return env;
    }

    private HttpResponse<byte[]> post(String path, byte[] body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(aa2.publicUrl() + path))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        headers.forEach(b::header);
        return net.client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private Map<String, String> signedBy(byte[] body) throws Exception {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("client_api_key", fiu.apiKey());
        h.put("x-jws-signature", Jose.signDetached(body, fiu.sig, "RS256"));
        h.put("Content-Type", "application/json");
        return h;
    }

    private void expect(HttpResponse<byte[]> r, int status, String code, String msg) {
        assertEquals(status, r.statusCode(), new String(r.body()));
        JsonNode b = Json.parseObject(r.body());
        assertEquals(code, Json.text(b, "errorCode"));
        if (msg != null) {
            assertEquals(msg, Json.text(b, "errorMsg"));
        }
        String sig = r.headers().firstValue("x-jws-signature").orElse(null);
        assertTrue(Jose.verifyDetached(sig, r.body(), List.of(aa2.sigPubKey())), "errors on /iop are signed by the gateway");
    }

    @Test
    void validEnvelopeIsForwardedAndRelayed() throws Exception {
        ObjectNode env = envelope();
        byte[] body = Json.bytes(env);
        HttpResponse<byte[]> r = post("/iop/Consent", body, signedBy(body));
        assertEquals(200, r.statusCode(), new String(r.body()));
        JsonNode reply = Json.parseObject(r.body());
        assertEquals(env.get("txnid").asText(), Json.text(reply, "txnid"), "the hop relays with the caller's txnid");
        assertEquals(env.get("correlationId").asText(), Json.text(reply, "correlationId"));
        assertTrue(Jose.verifyDetached(r.headers().firstValue("x-jws-signature").orElseThrow(), r.body(), List.of(aa2.sigPubKey())));
    }

    @Test
    void unknownPathAndWrongMethod() throws Exception {
        byte[] body = Json.bytes(envelope());
        expect(post("/iop/Nope", body, signedBy(body)), 404, "InvalidURI", null);
        HttpResponse<byte[]> get = net.client.send(HttpRequest.newBuilder(URI.create(aa2.publicUrl() + "/iop/Consent")).GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());
        expect(get, 405, "InvalidRequest", null);
    }

    @Test
    void roleKeyRules() throws Exception {
        byte[] body = Json.bytes(envelope());
        Map<String, String> none = signedBy(body);
        none.remove("client_api_key");
        expect(post("/iop/Consent", body, none), 401, "InvalidSecurity", null);
        Map<String, String> two = signedBy(body);
        two.put("x-cust_aa_api_key", fiu.apiKey());
        expect(post("/iop/Consent", body, two), 401, "InvalidSecurity", null);
        Map<String, String> notOnPath = signedBy(body);
        notOnPath.remove("client_api_key");
        notOnPath.put("fip_api_key", fiu.apiKey());
        expect(post("/iop/Consent", body, notOnPath), 403, "InvalidSecurity", null);
        Map<String, String> unknownKey = signedBy(body);
        unknownKey.put("client_api_key", "not-a-known-key");
        expect(post("/iop/Consent", body, unknownKey), 401, "InvalidSecurity", null);
        Map<String, String> wrongOwner = signedBy(body);
        wrongOwner.remove("client_api_key");
        wrongOwner.put("x-orig_aa_api_key", fiu.apiKey()); // an FIU using an AA's key header
        expect(post("/iop/Consent", body, wrongOwner), 403, "InvalidSecurity", null);
    }

    @Test
    void signatureRules() throws Exception {
        byte[] body = Json.bytes(envelope());
        Map<String, String> noSig = signedBy(body);
        noSig.remove("x-jws-signature");
        expect(post("/iop/Consent", body, noSig), 401, "InvalidSecurity", null);
        Map<String, String> h = signedBy(body);
        byte[] tampered = new String(body, StandardCharsets.UTF_8).replace("\"2.0.0\"", "\"2.0.1\"").getBytes(StandardCharsets.UTF_8);
        expect(post("/iop/Consent", tampered, h), 401, "SignatureDoesNotMatch", null);
    }

    @Test
    void correlationIdRules() throws Exception {
        ObjectNode env = envelope();
        env.remove("correlationId");
        byte[] body = Json.bytes(env);
        expect(post("/iop/Consent", body, signedBy(body)), 400, "InvalidRequest", "correlationId is required");
        env.put("correlationId", "corr-1");
        body = Json.bytes(env);
        expect(post("/iop/Consent", body, signedBy(body)), 400, "InvalidRequest", "correlationId must be in standard UUID format");
    }

    @Test
    void forwardingRules() throws Exception {
        ObjectNode env = envelope();
        env.remove("Target");
        byte[] body = Json.bytes(env);
        expect(post("/iop/Consent", body, signedBy(body)), 400, "InvalidRequest", null);

        env = envelope();
        ((ObjectNode) env.get("Target")).put("id", aa2.id);
        body = Json.bytes(env);
        expect(post("/iop/Consent", body, signedBy(body)), 400, "InvalidRequest", "Target is this AA");

        env = envelope();
        ((ObjectNode) env.get("Target")).put("id", "aa-test-404");
        body = Json.bytes(env);
        expect(post("/iop/Consent", body, signedBy(body)), 400, "InvalidRoute", "Target is not registered with this AA");

        env = envelope();
        env.put("encryptedPayload", "not-a-jwe");
        body = Json.bytes(env);
        expect(post("/iop/Consent", body, signedBy(body)), 400, "InvalidRequest", "encryptedPayload must be a compact JWE");
    }

    @Test
    void initiatorNextToTargetIsIgnoredOnForwardingLeg() throws Exception {
        ObjectNode env = envelope();
        ObjectNode spoof = env.putObject("Initiator");
        spoof.put("type", "FIU");
        spoof.put("id", "fiu-test-999");
        byte[] body = Json.bytes(env);
        aa3.core.calls.clear();
        HttpResponse<byte[]> r = post("/iop/Consent", body, signedBy(body));
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("{\"type\":\"FIU\",\"id\":\"fiu-test-101\"}", aa3.core.calls.get(0).header("Initiator-Entity"),
                "the hop sets the Initiator from the authenticated sender");
    }

    @Test
    void healthz() throws Exception {
        HttpResponse<String> r = net.client.send(HttpRequest.newBuilder(URI.create(aa2.publicUrl() + "/healthz")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
    }

    @Test
    void internalApisAreNotServedOnThePublicListener() throws Exception {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        HttpResponse<byte[]> r = post("/aa-sgw/Consent", body, Map.of());
        assertEquals(404, r.statusCode());
    }
}
