package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.http.Json;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * User discovery: FIU user discovery through a Connected-AA,
 * the broadcast to every AA, and /aa-dgw/User/discover.
 *
 * <pre>
 * fiu-test-611  FIU; linkedAAs [aa-test-612, aa-test-613]; broadcast timeout 2 s
 * aa-test-612   linked: answers the Direct API itself (User Found) and is a real AA gateway (hop)
 * aa-test-613   linked: answers the Direct API after 4 s (too slow: ignored)
 * aa-test-614   not linked, interop ready: a real AA gateway, reached via aa-test-612 (User Found)
 * aa-test-615   not linked, not interop ready: never asked
 * fiu-test-621  FIU; linkedAAs [aa-test-613] only; broadcast timeout 1 s (every AA fails)
 * </pre>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserDiscoveryE2ETest {

    TestNet net;
    TestNet.Party fiu;
    TestNet.Party fiu2;
    TestNet.Party aa612;
    TestNet.Party aa613;
    TestNet.Party aa614;
    TestNet.Party aa615;
    final List<HttpServer> servers = new ArrayList<>();
    final List<JsonNode> directBodies = new CopyOnWriteArrayList<>();
    final List<Map<String, String>> directHeaders = new CopyOnWriteArrayList<>();
    final List<String> asked615 = new CopyOnWriteArrayList<>();
    final int aa612Inner = TestNet.freePort();

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        fiu = net.add("fiu-test-611", "FIU", "FIU");
        aa612 = net.add("aa-test-612", "AA", "AA");
        aa613 = net.add("aa-test-613", "AA", "AA");
        aa614 = net.add("aa-test-614", "AA", "AA");
        aa615 = net.add("aa-test-615", "AA", "AA");
        fiu2 = net.add("fiu-test-621", "FIU", "FIU");

        String aig = "aig:\n  aa:\n    - aa-test-612: [aa-test-614]\n";
        fiu.aigYaml = aig;
        fiu.linked = List.of("aa-test-612", "aa-test-613");
        fiu.interop.put("aa-test-615", false);
        fiu.yamlEdit = y -> y.replace("  token: \"${GW_TOKEN}\"\n", "  token: \"${GW_TOKEN}\"\n  broadcastTimeoutSeconds: 2\n");
        fiu2.aigYaml = aig;
        fiu2.linked = List.of("aa-test-613");
        fiu2.interop.put("aa-test-612", false);
        fiu2.interop.put("aa-test-614", false);
        fiu2.interop.put("aa-test-615", false);
        fiu2.yamlEdit = y -> y.replace("  token: \"${GW_TOKEN}\"\n", "  token: \"${GW_TOKEN}\"\n  broadcastTimeoutSeconds: 1\n");

        // aa-test-612's gateway listens behind a front door that also answers the Direct API.
        aa612.yamlEdit = y -> y.replace("listenAddr: \"127.0.0.1:" + aa612.publicPort + "\"", "listenAddr: \"127.0.0.1:" + aa612Inner + "\"");
        aa614.core = null;
        net.start(aa612);
        net.start(aa614);
        aa614.core.answer = c -> c.path().equals("/aa-core/User/discover")
                ? TestNet.CoreAnswer.json(200, found("customer-test-001@aa-test-614", c.body()))
                : TestNet.CoreAnswer.json(200, "{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"ok\":true}");
        net.start(fiu);
        net.start(fiu2);

        servers.add(frontDoor(aa612, ex -> answerDirect(ex, aa612, found("customer-test-001@aa-test-612", null), 0)));
        servers.add(frontDoor(aa613, ex -> answerDirect(ex, aa613, found("customer-test-001@aa-test-613", null), 4000)));
        servers.add(frontDoor(aa615, ex -> {
            asked615.add(ex.getRequestURI().getPath());
            answerDirect(ex, aa615, found("customer-test-001@aa-test-615", null), 0);
        }));
    }

    @AfterAll
    void stop() {
        servers.forEach(s -> s.stop(0));
        net.close();
    }

    // ---------------- helpers ----------------

    interface Handler {
        void handle(HttpExchange ex) throws IOException;
    }

    /** At p's public address: /User/discover goes to {@code direct}; anything else to p's gateway (if any). */
    HttpServer frontDoor(TestNet.Party p, Handler direct) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", p.publicPort), 0);
        s.createContext("/", ex -> {
            if (ex.getRequestURI().getPath().equals("/User/discover")) {
                direct.handle(ex);
                return;
            }
            try {
                HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + aa612Inner + ex.getRequestURI().getPath()));
                ex.getRequestHeaders().forEach((k, v) -> {
                    if (!Set.of("host", "content-length", "connection").contains(k.toLowerCase())) {
                        b.header(k, v.get(0));
                    }
                });
                b.POST(HttpRequest.BodyPublishers.ofByteArray(ex.getRequestBody().readAllBytes()));
                HttpResponse<byte[]> r = net.client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
                r.headers().map().forEach((k, v) -> {
                    if (k != null && !k.startsWith(":") && !Set.of("content-length", "transfer-encoding", "date").contains(k.toLowerCase())) {
                        ex.getResponseHeaders().add(k, v.get(0));
                    }
                });
                ex.sendResponseHeaders(r.statusCode(), r.body().length == 0 ? -1 : r.body().length);
                if (r.body().length > 0) {
                    ex.getResponseBody().write(r.body());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                ex.close();
            }
        });
        s.start();
        return s;
    }

    /** A Direct API answer, signed by the AA, after {@code delayMs}. */
    void answerDirect(HttpExchange ex, TestNet.Party aa, String body, long delayMs) throws IOException {
        byte[] req = ex.getRequestBody().readAllBytes();
        Map<String, String> h = new java.util.HashMap<>();
        ex.getRequestHeaders().forEach((k, v) -> h.put(k.toLowerCase(), v.get(0)));
        h.put("x-aa", aa.id);
        directHeaders.add(h);
        directBodies.add(Json.parseObject(req));
        try {
            Thread.sleep(delayMs);
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("x-jws-signature", Jose.signDetached(b, aa.sig, "RS256"));
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
        } catch (Exception e) {
            // the gateway gave up on us (timeout): fine
        } finally {
            ex.close();
        }
    }

    /** A CustDiscoveryResponse with one entry (synthetic handle), echoing the request's txnid when given. */
    static String found(String handle, byte[] request) {
        String txn = request == null ? UUID.randomUUID().toString() : Json.text(Json.parseObject(request), "txnid");
        return "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-10T10:00:00.000Z\",\"txnid\":\"" + txn + "\",\"status\":\"User Found\","
                + "\"customerDiscoveryResponse\":[{\"customerAddress\":\"" + handle + "\",\"maskedMobile\":\"XXXXXX9999\","
                + "\"vuaAttestation\":\"synthetic\"}]}";
    }

    static String request(String txnid) {
        return "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-10T10:00:00.000Z\",\"txnid\":\"" + txnid + "\",\"correlationId\":\"ignored\","
                + "\"customer\":{\"vuaHash\":\"synthetic-vua-hash\",\"mobileHash\":\"synthetic-mobile-hash\"}}";
    }

    static Map<String, String> broadcastHeaders(String corr) {
        Map<String, String> h = new java.util.LinkedHashMap<>();
        h.put("Authorization", "Bearer " + TestNet.GW_TOKEN);
        h.put("Correlation-Id", corr);
        return h;
    }

    // ---------------- tests ----------------

    @Test
    void fiuUserDiscoveryReachesTheCustomerAaCore() throws Exception {
        // FIU user discovery through a Connected-AA
        aa614.core.calls.clear();
        String corr = UUID.randomUUID().toString();
        String txn = UUID.randomUUID().toString();
        HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/User/discover", TestNet.coreHeaders("AA", "aa-test-614", corr), request(txn));
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("aa-test-612", r.headers().firstValue("Forwarding-Hop").orElse(null));
        assertTrue(Jose.verifyDetachedEncoded(r.headers().firstValue("x-jws-signature").orElseThrow(), r.body(), List.of(aa614.sigPubKey())),
                "the fiu-core gets the Customer-AA's signature");
        JsonNode b = Json.parseObject(r.body());
        assertEquals("User Found", Json.text(b, "status"));
        assertEquals("customer-test-001@aa-test-614", b.get("customerDiscoveryResponse").get(0).get("customerAddress").asText());

        TestNet.CoreCall call = aa614.core.calls.get(0);
        assertEquals("/aa-core/User/discover", call.path());
        assertEquals("{\"type\":\"FIU\",\"id\":\"fiu-test-611\"}", call.header("Initiator-Entity"));
        assertEquals("aa-test-612", call.header("Forwarding-Hop"));
    }

    @Test
    void broadcastAsksEveryEligibleAaAndMergesTheFoundEntries() throws Exception {
        // the broadcast asks every eligible AA and merges the found entries
        directBodies.clear();
        directHeaders.clear();
        asked615.clear();
        aa614.core.calls.clear();
        String corr = UUID.randomUUID().toString();
        String txn = UUID.randomUUID().toString();
        long t0 = System.nanoTime();
        HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/broadcast/User/discover", broadcastHeaders(corr), request(txn));
        long ms = (System.nanoTime() - t0) / 1_000_000;

        assertEquals(200, r.statusCode(), new String(r.body()));
        assertTrue(ms < 3800, "the slow AA is not waited for (" + ms + " ms)");
        assertEquals(corr, r.headers().firstValue("Correlation-Id").orElse(null));
        assertNull(r.headers().firstValue("x-jws-signature").orElse(null), "no signature: several AAs answered");
        assertNull(r.headers().firstValue("Content-Type").orElse(null));
        JsonNode b = Json.parseObject(r.body());
        assertEquals("User Found", Json.text(b, "status"));
        assertEquals(txn, Json.text(b, "txnid"), "the core's txnid");
        assertEquals(corr, Json.text(b, "correlationId"));
        Set<String> handles = new HashSet<>();
        b.get("customerDiscoveryResponse").forEach(e -> handles.add(e.get("customerAddress").asText()));
        assertEquals(Set.of("customer-test-001@aa-test-612", "customer-test-001@aa-test-614"), handles,
                "the linked AA (Direct API) and the interop-ready AA (/iop) are merged; the slow answer is ignored");

        // linked AAs were called on the Direct API, signed by the FIU, with client_api_key
        Set<String> direct = new HashSet<>();
        for (Map<String, String> h : directHeaders) {
            direct.add(h.get("x-aa"));
            assertEquals(fiu.apiKey(), h.get("client_api_key"));
        }
        assertEquals(Set.of("aa-test-612", "aa-test-613"), direct);
        assertTrue(asked615.isEmpty(), "an AA neither linked nor interop ready is never asked");

        // each AA got its own txnid and the core's correlationId
        Set<String> txnids = new HashSet<>();
        for (JsonNode d : directBodies) {
            assertEquals(corr, Json.text(d, "correlationId"));
            txnids.add(Json.text(d, "txnid"));
        }
        JsonNode viaIop = Json.parseObject(aa614.core.calls.get(0).body());
        assertEquals("/aa-core/User/discover", aa614.core.calls.get(0).path());
        assertEquals(corr, Json.text(viaIop, "correlationId"));
        txnids.add(Json.text(viaIop, "txnid"));
        assertEquals(3, txnids.size(), "every request has its own txnid");
        assertTrue(!txnids.contains(txn), "none is the core's txnid");
    }

    @Test
    void broadcastErrors() throws Exception {
        // every AA fails (here: too slow) -> 503 AllRoutesUnavailable, with IOP-Gw-Error
        HttpResponse<byte[]> r = net.call(fiu2, "POST", "/fiu-dgw/broadcast/User/discover",
                broadcastHeaders(UUID.randomUUID().toString()), request(UUID.randomUUID().toString()));
        assertEquals(503, r.statusCode(), new String(r.body()));
        assertEquals("AllRoutesUnavailable", Json.text(Json.parseObject(r.body()), "errorCode"));
        assertEquals("no AA answered the user discovery (1 asked)", Json.text(Json.parseObject(r.body()), "errorMsg"));
        assertEquals("true", r.headers().firstValue("IOP-Gw-Error").orElse(null));

        // token, Correlation-Id and body checks
        Map<String, String> noToken = broadcastHeaders(UUID.randomUUID().toString());
        noToken.remove("Authorization");
        assertEquals(401, net.call(fiu, "POST", "/fiu-dgw/broadcast/User/discover", noToken, request("t")).statusCode());
        Map<String, String> noCorr = broadcastHeaders("not-a-uuid");
        assertEquals(400, net.call(fiu, "POST", "/fiu-dgw/broadcast/User/discover", noCorr, request("t")).statusCode());
        assertEquals(400, net.call(fiu, "POST", "/fiu-dgw/broadcast/User/discover",
                broadcastHeaders(UUID.randomUUID().toString()), "{\"ver\":\"2.0.0\"}").statusCode());
        assertEquals(405, net.call(fiu, "GET", "/fiu-dgw/broadcast/User/discover",
                broadcastHeaders(UUID.randomUUID().toString()), null).statusCode());

        // in AA mode the broadcast path does not exist
        HttpResponse<byte[]> aaMode = net.call(aa614, "POST", "/aa-dgw/broadcast/User/discover",
                broadcastHeaders(UUID.randomUUID().toString()), request("t"));
        assertEquals(404, aaMode.statusCode());
        assertEquals("InvalidURI", Json.text(Json.parseObject(aaMode.body()), "errorCode"));
    }

    @Test
    void aaDgwUserDiscoverIsNotServed() throws Exception {
        // an AA never sends user discovery: /aa-dgw/User/discover is not served
        Map<String, String> h = TestNet.coreHeaders("FIU", "fiu-test-611", UUID.randomUUID().toString());
        HttpResponse<byte[]> r = net.call(aa614, "POST", "/aa-dgw/User/discover", h, request("t"));
        assertEquals(404, r.statusCode());
        assertEquals("InvalidURI", Json.text(Json.parseObject(r.body()), "errorCode"));
    }
}
