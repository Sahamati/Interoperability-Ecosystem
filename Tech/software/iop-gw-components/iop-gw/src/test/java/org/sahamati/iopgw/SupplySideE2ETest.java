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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Supply side end to end: Origin-AA → Inter-AA → FIP connector, and
 * FIP connector → Inter-AA → Origin-AA. All participants are synthetic, with generated keys.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupplySideE2ETest {

    TestNet net;
    TestNet.Party fip;      // fip-test-301: FIP connector (FIP mode)
    TestNet.Party inter;    // aa-test-302: Inter-AA (hop)
    TestNet.Party origin;   // aa-test-303: Origin-AA
    TestNet.Party other;    // aa-test-305: an AA the Inter-AA is not linked to
    TestNet.Party fakeFip;  // fip-test-304: a FIP whose "gateway" is a canned server (errorSource)
    com.sun.net.httpserver.HttpServer fakeFipServer;

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        fip = net.add("fip-test-301", "FIP", "FIP");
        inter = net.add("aa-test-302", "AA", "AA");
        origin = net.add("aa-test-303", "AA", "AA");
        other = net.add("aa-test-305", "AA", "AA");
        fakeFip = net.add("fip-test-304", "FIP", "FIP");

        fip.aigYaml = "aig:\n  aa:\n    - aa-test-302: [aa-test-303]\n";
        fip.linked = List.of("aa-test-302");
        fip.hopPreferenceYaml = "hopPreference: {interAAs: [aa-test-302]}\n";

        origin.aigYaml = "aig:\n  fiu:\n    - fiu-unused: [aa-unused]\n  fip:\n    - fip-test-301: [aa-test-302]\n";
        origin.linked = List.of("aa-test-302");
        origin.hopPreferenceYaml = "hopPreference: {interAAs: [aa-test-302]}\n";

        // The Inter-AA forwards only to Targets linked to it: the FIPs list it as their
        // Inter-AA in its AIG, and the Origin-AA is in its linkedAAs (aa-test-305 is not).
        inter.aigYaml = "aig:\n  fiu:\n    - fiu-unused: [aa-unused]\n  fip:\n    - fip-test-301: [aa-test-302]\n    - fip-test-304: [aa-test-302]\n";
        inter.linked = List.of("aa-test-303");

        for (TestNet.Party p : List.of(fip, inter, origin)) {
            net.start(p);
        }
        // fip-test-304 answers every request with a signed error envelope carrying errorSource.
        fakeFipServer = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", fakeFip.publicPort), 0);
        fakeFipServer.createContext("/", ex -> {
            ex.getRequestBody().readAllBytes();
            byte[] b = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"timestamp\":\"2026-11-09T10:00:00.000Z\","
                    + "\"errorCode\":\"InternalError\",\"errorMsg\":\"synthetic\",\"errorSource\":{\"type\":\"FIP\",\"id\":\"fip-test-304\"}}")
                    .getBytes(StandardCharsets.UTF_8);
            try {
                ex.getResponseHeaders().add("x-jws-signature", Jose.signDetached(b, fakeFip.sig, "RS256"));
            } catch (Exception e) {
                throw new java.io.IOException(e);
            }
            ex.sendResponseHeaders(500, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        fakeFipServer.start();
    }

    @AfterAll
    void stop() {
        net.close();
        fakeFipServer.stop(0);
    }

    private static String payload() {
        return "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-09T10:00:00.000Z\",\"txnid\":\"" + UUID.randomUUID()
                + "\",\"Customer\":{\"id\":\"customer-test-001@aa-test-303\",\"Identifiers\":[{\"category\":\"STRONG\",\"type\":\"MOBILE\",\"value\":\"9999999999\"}]}}";
    }

    private static String header(HttpResponse<?> r, String name) {
        return r.headers().firstValue(name).orElse(null);
    }

    // ---------------- Origin-AA → Inter-AA → FIP (/aa-sgw) ----------------

    @Test
    void accountDiscoveryReachesFipCore() throws Exception {
        fip.core.calls.clear();
        String corr = UUID.randomUUID().toString();
        String body = payload();
        HttpResponse<byte[]> r = net.call(origin, "POST", "/aa-sgw/Accounts/discover",
                TestNet.coreHeaders("FIP", "fip-test-301", corr), body);

        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("aa-test-302", header(r, "Forwarding-Hop"));
        assertEquals(corr, header(r, "Correlation-Id"));
        assertNull(header(r, "IOP-Gw-Error"));
        assertTrue(Jose.verifyDetachedEncoded(header(r, "x-jws-signature"), r.body(), List.of(fip.sigPubKey())),
                "the Origin-AA core gets the FIP's signature");

        assertEquals(1, fip.core.calls.size());
        TestNet.CoreCall call = fip.core.calls.get(0);
        assertEquals("POST", call.method());
        assertEquals("/fip-core/Accounts/discover", call.path());
        assertEquals("{\"type\":\"AA\",\"id\":\"aa-test-303\"}", call.header("Initiator-Entity"));
        assertEquals("aa-test-302", call.header("Forwarding-Hop"));
        assertEquals(corr, call.header("Correlation-Id"));
        assertNull(call.header("Content-Type"));
        assertNull(call.header("x-inter_aa_api_key"));
        assertArrayEquals(body.getBytes(StandardCharsets.UTF_8), call.body());
        assertTrue(Jose.verifyDetachedEncoded(call.header("x-jws-signature"), call.body(), List.of(origin.sigPubKey())),
                "the FIP core gets the Origin-AA's signature");
    }

    @Test
    void everyAaSgwApiReachesTheMatchingFipCorePath() throws Exception {
        Map<String, String> apis = new LinkedHashMap<>();
        apis.put("/aa-sgw/Accounts/link", "/fip-core/Accounts/link");
        apis.put("/aa-sgw/Accounts/link/verify", "/fip-core/Accounts/link/verify");
        apis.put("/aa-sgw/Accounts/link/reverify", "/fip-core/Accounts/link/reverify");
        apis.put("/aa-sgw/Accounts/delink", "/fip-core/Accounts/delink");
        apis.put("/aa-sgw/Consent", "/fip-core/Consent");
        apis.put("/aa-sgw/FI/request", "/fip-core/FI/request");
        apis.put("/aa-sgw/FI/fetch", "/fip-core/FI/fetch");
        apis.put("/aa-sgw/Consent/Notification", "/fip-core/Consent/Notification");
        for (Map.Entry<String, String> e : apis.entrySet()) {
            fip.core.calls.clear();
            HttpResponse<byte[]> r = net.call(origin, "POST", e.getKey(),
                    TestNet.coreHeaders("FIP", "fip-test-301", UUID.randomUUID().toString()), payload());
            assertEquals(200, r.statusCode(), e.getKey() + ": " + new String(r.body()));
            assertEquals(e.getValue(), fip.core.calls.get(0).path(), e.getKey());
        }
    }

    @Test
    void heartbeatFromOriginAaReachesFipCore() throws Exception {
        fip.core.calls.clear();
        HttpResponse<byte[]> r = net.call(origin, "GET", "/aa-sgw/Heartbeat",
                TestNet.coreHeaders("FIP", "fip-test-301", UUID.randomUUID().toString()), null);
        assertEquals(200, r.statusCode(), new String(r.body()));
        TestNet.CoreCall call = fip.core.calls.get(0);
        assertEquals("GET", call.method());
        assertEquals("/fip-core/Heartbeat", call.path());
        assertEquals("aa-test-302", call.header("Forwarding-Hop"));
        assertEquals("{\"type\":\"AA\",\"id\":\"aa-test-303\"}", call.header("Initiator-Entity"));
    }

    @Test
    void fipCoreErrorIsPassedOnToOriginAa() throws Exception {
        fip.core.answer = c -> TestNet.CoreAnswer.json(404,
                "{\"ver\":\"2.0.0\",\"txnid\":\"t-3\",\"errorCode\":\"NoAccountsFound\",\"errorMsg\":\"synthetic\"}");
        try {
            HttpResponse<byte[]> r = net.call(origin, "POST", "/aa-sgw/Accounts/discover",
                    TestNet.coreHeaders("FIP", "fip-test-301", UUID.randomUUID().toString()), payload());
            assertEquals(404, r.statusCode());
            assertNull(header(r, "IOP-Gw-Error"));
            assertEquals("NoAccountsFound", Json.text(Json.parseObject(r.body()), "errorCode"));
            assertTrue(Jose.verifyDetachedEncoded(header(r, "x-jws-signature"), r.body(), List.of(fip.sigPubKey())));
        } finally {
            fip.core.answer = c -> TestNet.CoreAnswer.json(200, "{\"ver\":\"2.0.0\",\"txnid\":\"t-4\",\"ok\":true}");
        }
    }

    /** An /iop request to the Inter-AA as the Origin-AA would send it (x-orig_aa_api_key). */
    private HttpResponse<byte[]> iopToInter(String path, String targetType, String targetId) throws Exception {
        byte[] inner = payload().getBytes(StandardCharsets.UTF_8);
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode t = env.putObject("Target");
        t.put("type", targetType);
        t.put("id", targetId);
        TestNet.Party tp = net.get(targetId);
        env.put("encryptedPayload", Jose.encrypt(Jose.signCompact(inner, origin.sig, "RS256"), new PubKey(tp.id + "-enc", tp.encPub)));
        byte[] body = Json.bytes(env);
        String key = "FIP".equals(targetType) ? "x-orig_aa_api_key" : "fip_api_key";
        String apiKey = "FIP".equals(targetType) ? origin.apiKey() : fip.apiKey();
        byte[] sigBody = body;
        String sig = "FIP".equals(targetType) ? Jose.signDetached(sigBody, origin.sig, "RS256") : Jose.signDetached(sigBody, fip.sig, "RS256");
        return net.client.send(HttpRequest.newBuilder(URI.create(inter.publicUrl() + path))
                .header(key, apiKey).header("x-jws-signature", sig)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    @Test
    void linkReverifyReachesTheFipCoreThroughTheInterAA() throws Exception {
        // AA mode accepts x-orig_aa_api_key with Target{FIP}; the FIP connector delivers it.
        fip.core.calls.clear();
        HttpResponse<byte[]> r = iopToInter("/iop/Accounts/link/reverify", "FIP", fip.id);
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("/fip-core/Accounts/link/reverify", fip.core.calls.get(0).path());
        assertTrue(Jose.verifyDetached(r.headers().firstValue("x-jws-signature").orElseThrow(), r.body(),
                List.of(inter.sigPubKey())), "the relay is re-signed by the Inter-AA");
    }

    @Test
    void consentArtefactIsNoLongerAnIopPathAndNothingIsRewritten() throws Exception {
        // an /iop path outside the route table is 404 InvalidURI; /iop/Consent goes as /iop/Consent.
        HttpResponse<byte[]> r = iopToInter("/iop/Consent/artefact", "FIP", fip.id);
        assertEquals(404, r.statusCode());
        assertEquals("InvalidURI", Json.text(Json.parseObject(r.body()), "errorCode"));
        fip.core.calls.clear();
        r = iopToInter("/iop/Consent", "FIP", fip.id);
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("/fip-core/Consent", fip.core.calls.get(0).path());
    }

    @Test
    void hopRouteCheckRefusesTargetsNotLinkedToTheHop() throws Exception {
        // an AA Target not in the hop's linkedAAs gets 400 InvalidRoute, and the Target is not called.
        other.core = null;
        HttpResponse<byte[]> r = iopToInter("/iop/FI/Notification", "AA", "aa-test-305");
        assertEquals(400, r.statusCode(), new String(r.body()));
        assertEquals("InvalidRoute", Json.text(Json.parseObject(r.body()), "errorCode"));
        assertEquals("Target is not linked to this AA", Json.text(Json.parseObject(r.body()), "errorMsg"));

        // A FIP Target whose Inter-AAs (in the hop's AIG) do not include the hop: 400 InvalidRoute.
        TestNet.Party originAsHop = origin; // aa-test-303's AIG lists aa-test-302, not itself, for fip-test-301
        byte[] inner = payload().getBytes(StandardCharsets.UTF_8);
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode t = env.putObject("Target");
        t.put("type", "FIP");
        t.put("id", fip.id);
        env.put("encryptedPayload", Jose.encrypt(Jose.signCompact(inner, inter.sig, "RS256"), new PubKey(fip.id + "-enc", fip.encPub)));
        byte[] body = Json.bytes(env);
        fip.core.calls.clear();
        HttpResponse<byte[]> r2 = net.client.send(HttpRequest.newBuilder(URI.create(originAsHop.publicUrl() + "/iop/Consent"))
                .header("x-orig_aa_api_key", inter.apiKey()).header("x-jws-signature", Jose.signDetached(body, inter.sig, "RS256"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(400, r2.statusCode(), new String(r2.body()));
        assertEquals("InvalidRoute", Json.text(Json.parseObject(r2.body()), "errorCode"));
        assertTrue(fip.core.calls.isEmpty(), "the Target is not called");
    }

    @Test
    void targetErrorSourceIsCopiedByTheHop() throws Exception {
        // the Target's errorSource object reaches the caller unchanged, next to IopDownstreamError.
        HttpResponse<byte[]> r = iopToInter("/iop/Consent", "FIP", fakeFip.id);
        assertEquals(500, r.statusCode(), new String(r.body()));
        JsonNode b = Json.parseObject(r.body());
        assertEquals("IopDownstreamError", Json.text(b, "errorCode"));
        assertEquals("No error payload received", Json.text(b, "errorMsg"));
        assertEquals("{\"type\":\"FIP\",\"id\":\"fip-test-304\"}", b.get("errorSource").toString());
        assertNull(b.get("encryptedPayload"));
    }

    // ---------------- FIP → Inter-AA → Origin-AA (/fip-sgw) ----------------

    @Test
    void fiNotificationFromFipReachesOriginAaCore() throws Exception {
        origin.core.calls.clear();
        String corr = UUID.randomUUID().toString();
        String body = payload();
        HttpResponse<byte[]> r = net.call(fip, "POST", "/fip-sgw/FI/Notification",
                TestNet.coreHeaders("AA", "aa-test-303", corr), body);
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("aa-test-302", header(r, "Forwarding-Hop"));
        assertTrue(Jose.verifyDetachedEncoded(header(r, "x-jws-signature"), r.body(), List.of(origin.sigPubKey())));

        TestNet.CoreCall call = origin.core.calls.get(0);
        assertEquals("/aa-core/FI/Notification", call.path());
        assertEquals("{\"type\":\"FIP\",\"id\":\"fip-test-301\"}", call.header("Initiator-Entity"));
        assertEquals("aa-test-302", call.header("Forwarding-Hop"));
        assertEquals(corr, call.header("Correlation-Id"));
        assertNull(call.header("fip_api_key"));
        assertTrue(Jose.verifyDetachedEncoded(call.header("x-jws-signature"), call.body(), List.of(fip.sigPubKey())));
    }

    @Test
    void everyFipSgwApiReachesTheMatchingAaCorePath() throws Exception {
        Map<String, String> apis = new LinkedHashMap<>();
        apis.put("/fip-sgw/Consent/Notification", "/aa-core/Consent/Notification");
        apis.put("/fip-sgw/Account/link/Notification", "/aa-core/Account/link/Notification");
        for (Map.Entry<String, String> e : apis.entrySet()) {
            origin.core.calls.clear();
            HttpResponse<byte[]> r = net.call(fip, "POST", e.getKey(),
                    TestNet.coreHeaders("AA", "aa-test-303", UUID.randomUUID().toString()), payload());
            assertEquals(200, r.statusCode(), e.getKey() + ": " + new String(r.body()));
            assertEquals(e.getValue(), origin.core.calls.get(0).path(), e.getKey());
        }
    }

    @Test
    void heartbeatFromFipReachesOriginAaCore() throws Exception {
        origin.core.calls.clear();
        HttpResponse<byte[]> r = net.call(fip, "GET", "/fip-sgw/Heartbeat",
                TestNet.coreHeaders("AA", "aa-test-303", UUID.randomUUID().toString()), null);
        assertEquals(200, r.statusCode(), new String(r.body()));
        TestNet.CoreCall call = origin.core.calls.get(0);
        assertEquals("GET", call.method());
        assertEquals("/aa-core/Heartbeat", call.path());
        assertEquals("{\"type\":\"FIP\",\"id\":\"fip-test-301\"}", call.header("Initiator-Entity"));
    }

    // ---------------- FIP-mode restrictions ----------------

    @Test
    void fipModeInternalApiRestrictions() throws Exception {
        Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-303", UUID.randomUUID().toString());
        HttpResponse<byte[]> notFipApi = net.call(fip, "POST", "/fip-sgw/Consent", h, payload());
        assertEquals(404, notFipApi.statusCode());
        assertEquals("unknown internal API path in FIP mode", Json.text(Json.parseObject(notFipApi.body()), "errorMsg"));

        assertEquals(404, net.call(fip, "POST", "/fiu-dgw/Consent", h, payload()).statusCode());
        assertEquals(404, net.call(fip, "POST", "/fip-sgw/User/discover", h, payload()).statusCode(),
                "user discovery is not served in FIP mode");

        HttpResponse<byte[]> wrongType = net.call(fip, "POST", "/fip-sgw/FI/Notification",
                TestNet.coreHeaders("FIU", "fiu-test-001", UUID.randomUUID().toString()), payload());
        assertEquals(400, wrongType.statusCode());
        assertEquals("Target.type must be AA on /fip-sgw/FI/Notification", Json.text(Json.parseObject(wrongType.body()), "errorMsg"));

        HttpResponse<byte[]> postHeartbeat = net.call(fip, "POST", "/fip-sgw/Heartbeat", h, payload());
        assertEquals(405, postHeartbeat.statusCode());
        assertEquals("GET", header(postHeartbeat, "Allow"));
    }

    @Test
    void fipConnectorIopRestrictions() throws Exception {
        byte[] body = "{\"ver\":\"2.0.0\",\"txnid\":\"x\",\"correlationId\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        // /iop/Consent/artefact is not an IOP path.
        HttpResponse<byte[]> artefact = net.client.send(HttpRequest.newBuilder(URI.create(fip.publicUrl() + "/iop/Consent/artefact"))
                .header("x-inter_aa_api_key", inter.apiKey()).POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(404, artefact.statusCode());
        // FI/Notification is an AA path, not served in FIP mode.
        HttpResponse<byte[]> notif = net.client.send(HttpRequest.newBuilder(URI.create(fip.publicUrl() + "/iop/FI/Notification"))
                .header("x-inter_aa_api_key", inter.apiKey()).POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(404, notif.statusCode());
        // Only the Inter-AA key is accepted by a FIP connector.
        HttpResponse<byte[]> wrongKey = net.client.send(HttpRequest.newBuilder(URI.create(fip.publicUrl() + "/iop/Consent"))
                .header("x-orig_aa_api_key", origin.apiKey()).POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(403, wrongKey.statusCode());
        JsonNode b = Json.parseObject(wrongKey.body());
        assertEquals("InvalidSecurity", Json.text(b, "errorCode"));
    }
}
