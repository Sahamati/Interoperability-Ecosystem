package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.obs.Stats;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end tests through real gateways: Initiator's gateway → hop AA gateway → Target gateway → fake core.
 * All participants are synthetic ({@code *-test-*}) with generated keys.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RoutingE2ETest {

    TestNet net;
    TestNet.Party fiu;      // fiu-test-001: Initiator (FIU mode)
    TestNet.Party aa2;      // aa-test-002: Connected-AA (hop)
    TestNet.Party aa3;      // aa-test-003: Customer-AA (Target)
    TestNet.Party aa4;      // aa-test-004: second Connected-AA (hop)
    TestNet.Party aa5;      // aa-test-005: linked AA that cannot route to aa-test-003 (InvalidRoute)
    TestNet.Party aa6;      // aa-test-006: linked AA whose gateway is down
    TestNet.Party fiu7;     // fiu-test-007: policy [aa-test-005, aa-test-002]
    TestNet.Party fiu8;     // fiu-test-008: only failing routes
    TestNet.Party aa9;      // aa-test-009: Target whose gateway is down
    TestNet.Party aa10;     // aa-test-010: Target not interop ready
    TestNet.Party aa11;     // aa-test-011: Target no AA can reach
    TestNet.Party fiu12;    // fiu-test-012: linkedAAs from the core (not loaded until pushed)
    TestNet.Party fiu13;    // fiu-test-013: AIG API down

    @BeforeAll
    void startNet() throws Exception {
        net = new TestNet();
        fiu = net.add("fiu-test-001", "FIU", "FIU");
        aa2 = net.add("aa-test-002", "AA", "AA");
        aa3 = net.add("aa-test-003", "AA", "AA");
        aa4 = net.add("aa-test-004", "AA", "AA");
        aa5 = net.add("aa-test-005", "AA", "AA");
        aa6 = net.add("aa-test-006", "AA", "AA");
        fiu7 = net.add("fiu-test-007", "FIU", "FIU");
        fiu8 = net.add("fiu-test-008", "FIU", "FIU");
        aa9 = net.add("aa-test-009", "AA", "AA");
        aa10 = net.add("aa-test-010", "AA", "AA");
        aa11 = net.add("aa-test-011", "AA", "AA");
        fiu12 = net.add("fiu-test-012", "FIU", "FIU");
        fiu13 = net.add("fiu-test-013", "FIU", "FIU");

        String fiuAig = """
                aig:
                  aa:
                    - aa-test-002: [aa-test-003, aa-test-009, aa-test-010]
                    - aa-test-004: [aa-test-003]
                    - aa-test-005: [aa-test-003]
                    - aa-test-006: [aa-test-003]
                """;
        fiu.aigYaml = fiuAig;
        fiu.linked = List.of("aa-test-002", "aa-test-004", "aa-test-005", "aa-test-006");
        fiu.interop.put("aa-test-010", false);

        fiu7.aigYaml = fiuAig;
        fiu7.linked = List.of("aa-test-002", "aa-test-005");
        fiu7.hopPreferenceYaml = "hopPreference: {connectedAAs: [aa-test-005, aa-test-002]}\n";

        fiu8.aigYaml = fiuAig;
        fiu8.linked = List.of("aa-test-005", "aa-test-006");
        fiu8.hopPreferenceYaml = "hopPreference: {connectedAAs: [aa-test-006, aa-test-005]}\n";

        fiu12.aigYaml = fiuAig;
        fiu12.overrides.put("linkedAAs", "linkedAAs: {source: api, token: \"${GW_TOKEN}\"}");

        fiu13.overrides.put("aigSource", "aigSource: api\naigBaseUrl: \"http://127.0.0.1:1\"\naigToken: \"${GW_TOKEN}\"");
        fiu13.linked = List.of("aa-test-002");

        aa3.aigYaml = "aig:\n  fiu:\n    - fiu-test-001: [aa-test-002]\n  fip:\n    - fip-unused: [aa-unused]\n";
        aa3.linked = List.of("aa-test-002");
        aa5.unknown.add("aa-test-003");

        for (TestNet.Party p : List.of(fiu, aa2, aa3, aa4, aa5, fiu7, fiu8, fiu12, fiu13)) {
            net.start(p);
        }
        // aa-test-006 and aa-test-009 are left down on purpose; their ports are never bound.
    }

    @AfterAll
    void stopNet() {
        net.close();
    }

    private static String payload() {
        return "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-09T10:00:00.000Z\",\"txnid\":\"" + UUID.randomUUID()
                + "\",\"ConsentDetail\":{\"customer\":{\"id\":\"customer-test-001@aa-test-003\"}}}";
    }

    private static String header(HttpResponse<?> r, String name) {
        return r.headers().firstValue(name).orElse(null);
    }

    // ------------------------------------------------------------------------------------

    @Test
    void consentEndToEndThroughConnectedAA() throws Exception {
        aa3.core.calls.clear();
        String corr = UUID.randomUUID().toString();
        String body = payload();
        Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", corr);
        h.put("Preferred-Hop", "aa-test-002");
        HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/Consent", h, body);

        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("aa-test-002", header(r, "Forwarding-Hop"));
        assertEquals(corr, header(r, "Correlation-Id"));
        assertNull(header(r, "Content-Type"));
        assertNull(header(r, "IOP-Gw-Error"));
        assertTrue(Jose.verifyDetachedEncoded(header(r, "x-jws-signature"), r.body(), List.of(aa3.sigPubKey())),
                "the core gets the Target's signature");
        assertTrue(Json.parseObject(r.body()).get("ok").asBoolean());

        assertEquals(1, aa3.core.calls.size());
        TestNet.CoreCall call = aa3.core.calls.get(0);
        assertEquals("POST", call.method());
        assertEquals("/aa-core/Consent", call.path());
        assertEquals("{\"type\":\"FIU\",\"id\":\"fiu-test-001\"}", call.header("Initiator-Entity"));
        assertEquals("aa-test-002", call.header("Forwarding-Hop"));
        assertEquals(corr, call.header("Correlation-Id"));
        assertNull(call.header("Content-Type"));
        assertNull(call.header("x-conn_aa_api_key"));
        assertArrayEquals(body.getBytes(StandardCharsets.UTF_8), call.body());
        assertTrue(Jose.verifyDetachedEncoded(call.header("x-jws-signature"), call.body(), List.of(fiu.sigPubKey())),
                "the Target core gets the Initiator's signature");
    }

    @Test
    void customerAANotifiesFiuThroughConnectedAA() throws Exception {
        fiu.core.calls.clear();
        String corr = UUID.randomUUID().toString();
        HttpResponse<byte[]> r = net.call(aa3, "POST", "/aa-dgw/FI/Notification",
                TestNet.coreHeaders("FIU", "fiu-test-001", corr), payload());
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("aa-test-002", header(r, "Forwarding-Hop"));
        TestNet.CoreCall call = fiu.core.calls.get(0);
        assertEquals("/fiu-core/FI/Notification", call.path());
        assertEquals("{\"type\":\"AA\",\"id\":\"aa-test-003\"}", call.header("Initiator-Entity"));
        assertEquals("aa-test-002", call.header("Forwarding-Hop"));
    }

    @Test
    void heartbeatReachesTargetCoreAsGet() throws Exception {
        aa3.core.calls.clear();
        Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString());
        h.put("Preferred-Hop", "aa-test-002");
        HttpResponse<byte[]> r = net.call(fiu, "GET", "/fiu-dgw/Heartbeat", h, null);
        assertEquals(200, r.statusCode(), new String(r.body()));
        TestNet.CoreCall call = aa3.core.calls.get(0);
        assertEquals("GET", call.method());
        assertEquals("/aa-core/Heartbeat", call.path());
        assertEquals(0, call.body().length);
        assertNull(call.header("x-jws-signature"));
        assertEquals("aa-test-002", call.header("Forwarding-Hop"));
    }

    @Test
    void targetCoreErrorIsPassedOnWithoutGatewayMarker() throws Exception {
        aa3.core.answer = c -> TestNet.CoreAnswer.json(400,
                "{\"ver\":\"2.0.0\",\"txnid\":\"t-1\",\"errorCode\":\"InvalidConsentDetail\",\"errorMsg\":\"synthetic\"}");
        try {
            Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString());
            h.put("Preferred-Hop", "aa-test-002");
            HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/Consent", h, payload());
            assertEquals(400, r.statusCode());
            assertNull(header(r, "IOP-Gw-Error"));
            assertEquals("InvalidConsentDetail", Json.text(Json.parseObject(r.body()), "errorCode"));
            assertTrue(Jose.verifyDetachedEncoded(header(r, "x-jws-signature"), r.body(), List.of(aa3.sigPubKey())));
        } finally {
            aa3.core.answer = c -> TestNet.CoreAnswer.json(200, "{\"ver\":\"2.0.0\",\"txnid\":\"t-2\",\"ok\":true}");
        }
    }

    @Test
    void hopPolicyInvalidRouteMovesToNextRoute() throws Exception {
        aa3.core.calls.clear();
        HttpResponse<byte[]> r = net.call(fiu7, "POST", "/fiu-dgw/Consent",
                TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString()), payload());
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("aa-test-002", header(r, "Forwarding-Hop"), "aa-test-005 answered InvalidRoute; aa-test-002 delivered");
        assertEquals(1, fiu7.gw.gateway.stats.get(Stats.C.nextRoute) >= 1 ? 1 : 0);
    }

    @Test
    void unreachableHopIsRetriedThenAnotherRouteDelivers() throws Exception {
        Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString());
        h.put("Preferred-Hop", "aa-test-006");
        h.put("Http-Retries", "1");
        long retriesBefore = fiu.gw.gateway.stats.get(Stats.C.retries);
        HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/Consent", h, payload());
        assertEquals(200, r.statusCode(), new String(r.body()));
        String hop = header(r, "Forwarding-Hop");
        assertNotEquals("aa-test-006", hop);
        assertNotEquals("aa-test-005", hop);
        assertTrue(fiu.gw.gateway.stats.get(Stats.C.retries) - retriesBefore >= 1, "the unreachable hop was retried");
    }

    @Test
    void everyRouteFailingGivesAllRoutesUnavailable() throws Exception {
        String corr = UUID.randomUUID().toString();
        Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", corr);
        h.put("Http-Retries", "0");
        HttpResponse<byte[]> r = net.call(fiu8, "POST", "/fiu-dgw/Consent", h, payload());
        assertEquals(503, r.statusCode());
        assertEquals("true", header(r, "IOP-Gw-Error"));
        assertEquals(corr, header(r, "Correlation-Id"));
        assertNull(header(r, "Forwarding-Hop"));
        assertNull(header(r, "Content-Type"));
        assertNull(header(r, "x-jws-signature"));
        JsonNode b = Json.parseObject(r.body());
        assertEquals("AllRoutesUnavailable", Json.text(b, "errorCode"));
        assertEquals("no route could deliver the call (2 tried)", Json.text(b, "errorMsg"));
        assertFieldOrder(b);
    }

    @Test
    void routeRetriesZeroTriesOneRouteOnly() throws Exception {
        Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString());
        h.put("Http-Retries", "0");
        h.put("Route-Retries", "0");
        HttpResponse<byte[]> r = net.call(fiu8, "POST", "/fiu-dgw/Consent", h, payload());
        assertEquals(503, r.statusCode());
        assertEquals("no route could deliver the call (1 tried)", Json.text(Json.parseObject(r.body()), "errorMsg"));
    }

    @Test
    void targetGatewayDownGivesHopStatusWithEmptyBodyAndNoOtherRoute() throws Exception {
        long hopRetriesBefore = aa2.gw.gateway.stats.get(Stats.C.targetRetries);
        long fiuRoutesBefore = fiu.gw.gateway.stats.get(Stats.C.nextRoute);
        HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/Consent",
                TestNet.coreHeaders("AA", "aa-test-009", UUID.randomUUID().toString()), payload());
        assertEquals(502, r.statusCode());
        assertEquals(0, r.body().length);
        assertNull(header(r, "IOP-Gw-Error"), "a Target failure is not generated by this gateway");
        assertEquals("aa-test-002", header(r, "Forwarding-Hop"));
        assertEquals(2, aa2.gw.gateway.stats.get(Stats.C.targetRetries) - hopRetriesBefore, "the hop retried the Target twice");
        assertEquals(fiuRoutesBefore, fiu.gw.gateway.stats.get(Stats.C.nextRoute), "no other route after IopDownstreamError");
    }

    @Test
    void coreCorrelationIdMismatchIsRefused() throws Exception {
        aa3.core.echoCorrelation = false;
        try {
            Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString());
            h.put("Preferred-Hop", "aa-test-002");
            HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/Consent", h, payload());
            assertEquals(502, r.statusCode());
            assertEquals(0, r.body().length);
        } finally {
            aa3.core.echoCorrelation = true;
        }
    }

    // ---------------- errors returned to the core ----------------

    private record Case(String name, String method, String path, Map<String, String> headers, String body,
                        int status, String code, String msg) {}

    @Test
    void errorsReturnedToTheCore() throws Exception {
        String corr = UUID.randomUUID().toString();
        List<Case> cases = new ArrayList<>();
        Map<String, String> ok = TestNet.coreHeaders("AA", "aa-test-003", corr);

        cases.add(new Case("unknown path", "POST", "/fiu-dgw/Nope", ok, payload(), 404, "InvalidURI", "unknown internal API path in FIU mode"));
        cases.add(new Case("other mode's path", "POST", "/aa-sgw/Consent", ok, payload(), 404, "InvalidURI", "unknown internal API path in FIU mode"));
        cases.add(new Case("wrong method", "GET", "/fiu-dgw/Consent", ok, null, 405, "InvalidRequest", "method not allowed"));
        Map<String, String> badToken = new java.util.LinkedHashMap<>(ok);
        badToken.put("Authorization", "Bearer wrong");
        cases.add(new Case("wrong token", "POST", "/fiu-dgw/Consent", badToken, payload(), 401, "InvalidSecurity", "invalid or missing internal API token"));
        Map<String, String> noCorr = new java.util.LinkedHashMap<>(ok);
        noCorr.remove("Correlation-Id");
        cases.add(new Case("no Correlation-Id", "POST", "/fiu-dgw/Consent", noCorr, payload(), 400, "InvalidRequest", "Correlation-Id header is required, in standard UUID format"));
        Map<String, String> badCorr = new java.util.LinkedHashMap<>(ok);
        badCorr.put("Correlation-Id", "not-a-uuid");
        cases.add(new Case("non-UUID Correlation-Id", "POST", "/fiu-dgw/Consent", badCorr, payload(), 400, "InvalidRequest", "Correlation-Id header is required, in standard UUID format"));
        Map<String, String> noTarget = new java.util.LinkedHashMap<>(ok);
        noTarget.remove("Target-Entity");
        cases.add(new Case("no Target-Entity", "POST", "/fiu-dgw/Consent", noTarget, payload(), 400, "InvalidRequest", "Target-Entity header must be {\"type\":...,\"id\":...}"));
        cases.add(new Case("wrong Target type", "POST", "/fiu-dgw/Consent", TestNet.coreHeaders("FIP", "fip-test-001", corr), payload(),
                400, "InvalidRequest", "Target.type must be AA on /fiu-dgw/Consent"));
        cases.add(new Case("unknown Target", "POST", "/fiu-dgw/Consent", TestNet.coreHeaders("AA", "aa-test-404", corr), payload(),
                400, "InvalidRequest", "Target is not registered"));
        cases.add(new Case("Target not interop ready", "POST", "/fiu-dgw/Consent", TestNet.coreHeaders("AA", "aa-test-010", corr), payload(),
                400, "InvalidRequest", "Target is not interop ready"));
        Map<String, String> badRetries = new java.util.LinkedHashMap<>(ok);
        badRetries.put("Http-Retries", "-1");
        cases.add(new Case("negative Http-Retries", "POST", "/fiu-dgw/Consent", badRetries, payload(), 400, "InvalidRequest", "Http-Retries: not a non-negative integer"));
        Map<String, String> badRoutes = new java.util.LinkedHashMap<>(ok);
        badRoutes.put("Route-Retries", "x");
        cases.add(new Case("bad Route-Retries", "POST", "/fiu-dgw/Consent", badRoutes, payload(), 400, "InvalidRequest", "Route-Retries: not a non-negative integer"));
        cases.add(new Case("no route to Target", "POST", "/fiu-dgw/Consent", TestNet.coreHeaders("AA", "aa-test-011", corr), payload(),
                400, "InvalidRequest", "no interop-ready linked AA can reach this Target"));
        cases.add(new Case("body without txnid", "POST", "/fiu-dgw/Consent", ok, "{\"ver\":\"2.0.0\"}", 400, "InvalidRequest", "body must be a JSON object with txnid"));
        Map<String, String> foreignSig = new java.util.LinkedHashMap<>(ok);
        String body = payload();
        foreignSig.put("x-jws-signature", Jose.signDetached(body.getBytes(StandardCharsets.UTF_8), aa4.sig, "RS256"));
        cases.add(new Case("core signature by another key", "POST", "/fiu-dgw/Consent", foreignSig, body, 400, "InvalidRequest",
                "core x-jws-signature does not verify with any of this participant's signing keys"));
        Map<String, String> badSig = new java.util.LinkedHashMap<>(ok);
        badSig.put("x-jws-signature", "garbage");
        cases.add(new Case("malformed core signature", "POST", "/fiu-dgw/Consent", badSig, payload(), 400, "InvalidRequest",
                "core x-jws-signature does not verify with any of this participant's signing keys"));

        for (Case c : cases) {
            HttpResponse<byte[]> r = net.call(fiu, c.method, c.path, c.headers, c.body);
            JsonNode b = Json.parseObject(r.body());
            assertEquals(c.status, r.statusCode(), c.name + ": " + new String(r.body()));
            assertEquals(c.code, Json.text(b, "errorCode"), c.name);
            assertEquals(c.msg, Json.text(b, "errorMsg"), c.name);
            assertEquals("true", header(r, "IOP-Gw-Error"), c.name);
            assertNull(header(r, "Content-Type"), c.name);
            assertNull(header(r, "x-jws-signature"), c.name);
            if (c.headers.containsKey("Correlation-Id")) {
                assertEquals(c.headers.get("Correlation-Id"), header(r, "Correlation-Id"), c.name);
            }
            if (c.status == 405) {
                assertEquals("POST", header(r, "Allow"));
            }
            assertFieldOrder(b);
        }
    }

    @Test
    void preferredHopThatIsNotEligibleIsIgnored() throws Exception {
        Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString());
        h.put("Preferred-Hop", "aa-test-404");
        h.put("Route-Retries", "2");
        HttpResponse<byte[]> r = net.call(fiu7, "POST", "/fiu-dgw/Consent", h, payload());
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals("aa-test-002", header(r, "Forwarding-Hop"));
    }

    @Test
    void linkedAAsNotLoadedThenPushed() throws Exception {
        Map<String, String> h = TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString());
        HttpResponse<byte[]> r = net.call(fiu12, "POST", "/fiu-dgw/Consent", h, payload());
        assertEquals(503, r.statusCode());
        assertEquals("linkedAAs not loaded", Json.text(Json.parseObject(r.body()), "errorMsg"));

        Map<String, String> push = Map.of("Authorization", "Bearer " + TestNet.GW_TOKEN, "Correlation-Id", UUID.randomUUID().toString());
        HttpResponse<byte[]> bad = net.call(fiu12, "POST", "/fiu-dgw/linkedAAs", push, "{\"linkedAAs\":[\"aa-test-002\",\"aa-test-002\"]}");
        assertEquals(400, bad.statusCode());
        assertNull(header(bad, "Correlation-Id"), "linkedAAs replies carry no headers");
        assertNull(header(bad, "IOP-Gw-Error"));

        HttpResponse<byte[]> okPush = net.call(fiu12, "POST", "/fiu-dgw/linkedAAs", push, "{\"linkedAAs\":[\"aa-test-002\"]}");
        assertEquals(200, okPush.statusCode());
        assertNull(header(okPush, "Correlation-Id"));
        assertNull(header(okPush, "Content-Type"));
        assertEquals("aa-test-002", Json.parseObject(okPush.body()).get("linkedAAs").get(0).asText());

        HttpResponse<byte[]> after = net.call(fiu12, "POST", "/fiu-dgw/Consent", h, payload());
        assertEquals(200, after.statusCode(), new String(after.body()));
        assertEquals("aa-test-002", header(after, "Forwarding-Hop"));
    }

    @Test
    void aigNotLoadedGivesBadGateway() throws Exception {
        HttpResponse<byte[]> r = net.call(fiu13, "POST", "/fiu-dgw/Consent",
                TestNet.coreHeaders("AA", "aa-test-003", UUID.randomUUID().toString()), payload());
        assertEquals(502, r.statusCode());
        JsonNode b = Json.parseObject(r.body());
        assertEquals("BadGateway", Json.text(b, "errorCode"));
        assertEquals("hop directory unavailable", Json.text(b, "errorMsg"));
        assertEquals("true", header(r, "IOP-Gw-Error"));
    }

    @Test
    void iopGwErrorIsSpelledExactlyOnTheWire() throws Exception {
        try (Socket s = new Socket("127.0.0.1", fiu.gwHttpPort)) {
            OutputStream out = s.getOutputStream();
            out.write(("POST /fiu-dgw/Consent HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + TestNet.GW_TOKEN
                    + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = s.getInputStream();
            String raw = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
            assertTrue(raw.startsWith("HTTP/1.1 400"), raw);
            assertTrue(raw.contains("\r\nIOP-Gw-Error: true\r\n"), raw);
            assertFalse(raw.toLowerCase().contains("content-type"), raw);
        }
    }

    private static void assertFieldOrder(JsonNode b) {
        List<String> names = new ArrayList<>();
        Iterator<String> it = b.fieldNames();
        it.forEachRemaining(names::add);
        assertEquals(List.of("ver", "txnid", "timestamp", "errorCode", "errorMsg"), names);
    }
}
