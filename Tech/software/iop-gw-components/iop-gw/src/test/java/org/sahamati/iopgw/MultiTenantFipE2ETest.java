package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.http.Json;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code Target-Id} in FIP mode with two FIPs on one gateway. The calls come
 * straight from the Inter-AA, as the participant's application gateway would pass them on.
 *
 * <pre>
 * fip-host      multiTenant: on, FIP mode, serving fip-test-a01 and fip-test-b01
 * aa-test-a21   Inter-AA (sender and Initiator)
 * </pre>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MultiTenantFipE2ETest {

    TestNet net;
    TestNet.Host host;
    TestNet.Party fipA;
    TestNet.Party fipB;
    TestNet.Party aa;

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        host = net.addHost("fip-host", "FIP", "fip-test-a01", "fip-test-b01");
        fipA = host.entity("fip-test-a01");
        fipB = host.entity("fip-test-b01");
        aa = net.add("aa-test-a21", "AA", "AA");
        net.start(host);
    }

    @AfterAll
    void stop() {
        net.close();
    }

    private byte[] envelope(String encryptedPayload) {
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode i = env.putObject("Initiator");
        i.put("type", "AA");
        i.put("id", aa.id);
        if (encryptedPayload != null) {
            env.put("encryptedPayload", encryptedPayload);
        }
        return Json.bytes(env);
    }

    private HttpResponse<byte[]> send(String path, byte[] body, String targetId) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(host.publicUrl() + path))
                .header("x-inter_aa_api_key", aa.apiKey())
                .header("x-jws-signature", Jose.signDetached(body, aa.sig, "RS256"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (targetId != null) {
            b.header("Target-Id", targetId);
        }
        return net.client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private HttpResponse<byte[]> heartbeat(String targetId) throws Exception {
        return send("/iop/Heartbeat", envelope(null), targetId);
    }

    private void clearCores() {
        fipA.core.calls.clear();
        fipB.core.calls.clear();
    }

    @Test
    @Order(1)
    void targetIdNamesTheEntityOfAHeartbeat() throws Exception {
        clearCores();
        HttpResponse<byte[]> r = heartbeat(fipB.id);
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertTrue(fipA.core.calls.isEmpty());
        assertEquals(1, fipB.core.calls.size());
        assertEquals("/fip-core/Heartbeat", fipB.core.calls.get(0).path());
        assertEquals(fipB.id, fipB.core.calls.get(0).header("Core-Entity-Id"));
        assertTrue(Jose.verifyDetached(r.headers().firstValue("x-jws-signature").orElseThrow(), r.body(), List.of(fipB.sigPubKey())));
    }

    @Test
    @Order(2)
    void aHeartbeatWithoutOrWithAnUnknownTargetIdIsRefused() throws Exception {
        clearCores();
        assertEquals(400, heartbeat(null).statusCode());
        HttpResponse<byte[]> unknown = heartbeat("fip-test-none");
        assertEquals(400, unknown.statusCode());
        assertEquals("InvalidRequest", Json.text(Json.parseObject(unknown.body()), "errorCode"));
        assertTrue(fipA.core.calls.isEmpty() && fipB.core.calls.isEmpty());
    }

    @Test
    @Order(3)
    void targetIdIsIgnoredOnCallsWithAPayload() throws Exception {
        clearCores();
        byte[] payload = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"ConsentDetail\":{}}").getBytes(StandardCharsets.UTF_8);
        String jwe = Jose.encrypt(Jose.signCompact(payload, aa.sig, "RS256"), fipA.encPubKey());
        HttpResponse<byte[]> r = send("/iop/Consent", envelope(jwe), fipB.id);
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertTrue(fipB.core.calls.isEmpty(), "Target-Id names B, the kid is A's: A answers");
        assertEquals(fipA.id, fipA.core.calls.get(0).header("Core-Entity-Id"));
    }

    @Test
    @Order(4)
    void withOneEntityLoadedAHeartbeatNeedsNoTargetId() throws Exception {
        host.writeEntity(fipB.id + ".yaml", host.entityYaml(fipB).replace("enable: true", "enable: false"));
        TestNet.await("fip-test-b01 unloaded", () -> !host.tenants().isOwn(fipB.id));
        clearCores();
        HttpResponse<byte[]> r = heartbeat(null);
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals(fipA.id, fipA.core.calls.get(0).header("Core-Entity-Id"));
    }
}
