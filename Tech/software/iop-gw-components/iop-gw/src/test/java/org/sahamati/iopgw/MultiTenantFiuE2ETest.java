package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.obs.Stats;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Multi-tenant mode with two FIUs on one gateway.
 *
 * <pre>
 * fiu-host       one gateway, multiTenant: on, FIU mode, serving fiu-test-a01 and fiu-test-b01
 *                (fiu-test-c01 is added later by writing its entity file)
 * aa-test-a11    Connected-AA of both FIUs (a real gateway)
 * aa-test-a12    Customer-AA (a real gateway)
 * aa-test-a13    a hop we answer ourselves, to send back replies the FIU gateway must refuse
 * </pre>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MultiTenantFiuE2ETest {

    TestNet net;
    TestNet.Host host;
    TestNet.Party fiuA;
    TestNet.Party fiuB;
    TestNet.Party fiuC;
    TestNet.Party aa1;
    TestNet.Party aa2;
    TestNet.Party aa3;
    HttpServer aa3Server;
    final AtomicReference<String> aa3Reply = new AtomicReference<>();

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        host = net.addHost("fiu-host", "FIU", "fiu-test-a01", "fiu-test-b01");
        fiuA = host.entity("fiu-test-a01");
        fiuB = host.entity("fiu-test-b01");
        fiuC = net.addEntity(host, "fiu-test-c01");
        aa1 = net.add("aa-test-a11", "AA", "AA");
        aa2 = net.add("aa-test-a12", "AA", "AA");
        aa3 = net.add("aa-test-a13", "AA", "AA");
        for (TestNet.Party f : List.of(fiuA, fiuB, fiuC)) {
            f.linked = List.of(aa1.id, aa3.id);
        }
        host.aigYaml = "aig:\n  aa:\n    - aa-test-a11: [aa-test-a12]\n    - aa-test-a13: [aa-test-a12]\n";
        net.start(aa1);
        net.start(aa2);
        net.start(host);

        // aa-test-a13: answers every /iop call with the reply the test sets, signed as aa-test-a13
        aa3Server = HttpServer.create(new InetSocketAddress("127.0.0.1", aa3.publicPort), 0);
        aa3Server.createContext("/", ex -> {
            ex.getRequestBody().readAllBytes();
            byte[] b = aa3Reply.get().getBytes(StandardCharsets.UTF_8);
            try {
                ex.getResponseHeaders().add("x-jws-signature", Jose.signDetached(b, aa3.sig, "RS256"));
            } catch (Exception e) {
                throw new java.io.IOException(e);
            }
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        aa3Server.start();
    }

    @AfterAll
    void stop() {
        net.close();
        aa3Server.stop(0);
    }

    static String payload() {
        return "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-23T10:00:00.000Z\",\"txnid\":\"" + UUID.randomUUID()
                + "\",\"ConsentDetail\":{\"customer\":{\"id\":\"customer-test-001@aa-test-a12\"}}}";
    }

    static String header(HttpResponse<?> r, String name) {
        return r.headers().firstValue(name).orElse(null);
    }

    private HttpResponse<byte[]> consent(TestNet.Party fiu, Map<String, String> headers) throws Exception {
        return net.call(fiu, "POST", "/fiu-dgw/Consent", headers, payload());
    }

    private Map<String, String> headersOf(TestNet.Party fiu) {
        Map<String, String> h = TestNet.entityHeaders(fiu, "AA", aa2.id, UUID.randomUUID().toString());
        h.put("Preferred-Hop", aa1.id);
        return h;
    }

    // ---------------- /iop calls to the FIUs: the Connected-AA's Consent Notification ----------------

    private static final byte[] NOTIFICATION = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID()
            + "\",\"ConsentStatusNotification\":{\"consentStatus\":\"ACTIVE\"}}").getBytes(StandardCharsets.UTF_8);

    /** aa-test-a12 (Initiator) → aa-test-a11 (Connected-AA, sender) → this FIU gateway; encrypted with {@code jwe}. */
    private byte[] notification(String initiatorId, String jwe) {
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode i = env.putObject("Initiator");
        i.put("type", "AA");
        i.put("id", initiatorId);
        env.put("encryptedPayload", jwe);
        return Json.bytes(env);
    }

    private String encryptedFor(TestNet.Party fiu) throws Exception {
        return Jose.encrypt(Jose.signCompact(NOTIFICATION, aa2.sig, "RS256"), fiu.encPubKey());
    }

    /** A JWE to {@code fiu}'s key with no kid in its protected header. */
    private String withoutKid(TestNet.Party fiu, String plaintext) throws Exception {
        JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT").build(),
                new Payload(plaintext.getBytes(StandardCharsets.UTF_8)));
        jwe.encrypt(new RSAEncrypter(fiu.encPub));
        return jwe.serialize();
    }

    private HttpResponse<byte[]> toHost(String path, String apiKey, byte[] body) throws Exception {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("x-conn_aa_api_key", apiKey);
        h.put("x-jws-signature", Jose.signDetached(body, aa1.sig, "RS256"));
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(host.publicUrl() + path))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        h.forEach(b::header);
        return net.client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    // ------------------------------------------------------------------------------------

    @Test
    @Order(1)
    void bothEntitiesLoadFromTheirFiles() {
        assertEquals(List.of(fiuA.id, fiuB.id), host.tenants().ids());
    }

    /** Each entity sends with its own keys and token; the hop and the Target see the right FIU. */
    @Test
    @Order(2)
    void eachCoreSendsAsItsOwnEntity() throws Exception {
        for (TestNet.Party fiu : List.of(fiuA, fiuB)) {
            aa2.core.calls.clear();
            HttpResponse<byte[]> r = consent(fiu, headersOf(fiu));
            assertEquals(200, r.statusCode(), new String(r.body()));
            assertEquals(aa1.id, header(r, "Forwarding-Hop"));
            // aa-test-a11 checked fiu's api-key and signature; aa-test-a12 decrypted and checked fiu's inner JWS
            assertEquals("{\"type\":\"FIU\",\"id\":\"" + fiu.id + "\"}", aa2.core.calls.get(0).header("Initiator-Entity"));
        }
        assertTrue(host.gw.gateway.stats.get(fiuA.id, Stats.C.coreReq) >= 1);
        assertTrue(host.gw.gateway.stats.get(fiuB.id, Stats.C.coreReq) >= 1);
    }

    /** With two entities loaded, Core-Entity-Id is required and must name a loaded entity. */
    @Test
    @Order(3)
    void coreEntityIdRules() throws Exception {
        Map<String, String> none = headersOf(fiuA);
        none.remove("Core-Entity-Id");
        expectCoreError(consent(fiuA, none), 400, "InvalidRequest", "Core-Entity-Id header is required");

        Map<String, String> unknown = headersOf(fiuA);
        unknown.put("Core-Entity-Id", "fiu-test-none");
        expectCoreError(consent(fiuA, unknown), 400, "InvalidRequest", "Core-Entity-Id is not a loaded entity");

        Map<String, String> empty = headersOf(fiuA);
        empty.put("Core-Entity-Id", "");
        expectCoreError(consent(fiuA, empty), 400, "InvalidRequest", "Core-Entity-Id is not a loaded entity");

        // entity A's internal API token on a call for entity B
        Map<String, String> crossed = headersOf(fiuB);
        crossed.put("Authorization", "Bearer " + fiuA.gwToken());
        expectCoreError(consent(fiuB, crossed), 400, "InvalidSecurity", "invalid or missing internal API token");
    }

    private static void expectCoreError(HttpResponse<byte[]> r, int status, String code, String msg) {
        assertEquals(status, r.statusCode(), new String(r.body()));
        assertEquals("true", header(r, "IOP-Gw-Error"));
        JsonNode b = Json.parseObject(r.body());
        assertEquals(code, Json.text(b, "errorCode"));
        assertEquals(msg, Json.text(b, "errorMsg"));
    }

    /** The JWE kid picks the entity; its core gets Core-Entity-Id, and its key signs the reply. */
    @Test
    @Order(4)
    void kidSelectsTheEntity() throws Exception {
        fiuA.core.calls.clear();
        fiuB.core.calls.clear();
        HttpResponse<byte[]> r = toHost("/iop/Consent/Notification", aa1.apiKey(), notification(aa2.id, encryptedFor(fiuB)));
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertTrue(fiuA.core.calls.isEmpty(), "entity A's core is not called");
        assertEquals(1, fiuB.core.calls.size());
        TestNet.CoreCall call = fiuB.core.calls.get(0);
        assertEquals("/fiu-core/Consent/Notification", call.path());
        assertEquals(fiuB.id, call.header("Core-Entity-Id"));
        String sig = header(r, "x-jws-signature");
        assertTrue(Jose.verifyDetached(sig, r.body(), List.of(fiuB.sigPubKey())), "signed with entity B's key");
        assertFalse(Jose.verifyDetached(sig, r.body(), List.of(fiuA.sigPubKey())));
    }

    /** Errors found before the entity is known are unsigned with two entities loaded. */
    @Test
    @Order(5)
    void errorsBeforeTheEntityIsKnownAreUnsigned() throws Exception {
        // no kid in the JWE header
        HttpResponse<byte[]> r = toHost("/iop/Consent/Notification", aa1.apiKey(),
                notification(aa2.id, withoutKid(fiuA, Jose.signCompact(NOTIFICATION, aa2.sig, "RS256"))));
        expectUnsigned(r, "InvalidRequest");
        // a kid no loaded entity owns
        String foreign = Jose.encrypt(Jose.signCompact(NOTIFICATION, aa2.sig, "RS256"), new PubKey("kid-of-nobody", fiuA.encPub));
        expectUnsigned(toHost("/iop/Consent/Notification", aa1.apiKey(), notification(aa2.id, foreign)), "InvalidRequest");
        // a wrong api-key
        expectUnsigned(toHost("/iop/Consent/Notification", "not-an-api-key", notification(aa2.id, encryptedFor(fiuA))), "InvalidSecurity");
        assertTrue(fiuA.core.calls.stream().noneMatch(c -> c.path().endsWith("/Consent/Notification") && c.header("Core-Entity-Id") == null));
        assertTrue(host.gw.gateway.stats.get(Stats.UNKNOWN, Stats.C.iopReq) >= 3, "counted under entity -");
    }

    private static void expectUnsigned(HttpResponse<byte[]> r, String code) {
        assertEquals(400, r.statusCode(), new String(r.body()));
        assertNull(header(r, "x-jws-signature"), "no entity's signing key can be chosen");
        JsonNode b = Json.parseObject(r.body());
        assertEquals(code, Json.text(b, "errorCode"));
        assertNull(b.get("errorSource"));
    }

    /** Once the kid names the entity, its errors are signed by it and carry its errorSource. */
    @Test
    @Order(6)
    void errorsAfterTheEntityIsKnownAreSignedByIt() throws Exception {
        HttpResponse<byte[]> r = toHost("/iop/Consent/Notification", aa1.apiKey(), notification("aa-test-unregistered", encryptedFor(fiuB)));
        assertEquals(400, r.statusCode(), new String(r.body()));
        JsonNode b = Json.parseObject(r.body());
        assertEquals("Initiator not registered", Json.text(b, "errorMsg"));
        assertTrue(Jose.verifyDetached(header(r, "x-jws-signature"), r.body(), List.of(fiuB.sigPubKey())));
        assertEquals("{\"type\":\"FIU\",\"id\":\"fiu-test-b01\"}", b.get("errorSource").toString());
    }

    /** A reply without a kid, or with another entity's kid, gives the core 502 BadGateway. */
    @Test
    @Order(7)
    void repliesMustBeEncryptedToTheSendingEntity() throws Exception {
        byte[] answer = "{\"ver\":\"2.0.0\",\"txnid\":\"t\",\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
        String inner = Jose.signCompact(answer, aa2.sig, "RS256");
        for (String cipher : List.of(withoutKid(fiuA, inner), Jose.encrypt(inner, fiuB.encPubKey()))) {
            ObjectNode env = Json.object();
            env.put("ver", "2.0.0");
            env.put("txnid", "t");
            env.put("correlationId", UUID.randomUUID().toString());
            env.put("encryptedPayload", cipher);
            aa3Reply.set(env.toString());
            Map<String, String> h = TestNet.entityHeaders(fiuA, "AA", aa2.id, UUID.randomUUID().toString());
            h.put("Preferred-Hop", aa3.id);
            h.put("Route-Retries", "0");
            HttpResponse<byte[]> r = consent(fiuA, h);
            expectCoreError(r, 502, "BadGateway", "unable to decrypt reply");
            assertEquals(aa3.id, header(r, "Forwarding-Hop"));
        }
        // the same reply encrypted to entity A's own key is opened
        aa3Reply.set("{\"ver\":\"2.0.0\",\"txnid\":\"t\",\"correlationId\":\"" + UUID.randomUUID()
                + "\",\"encryptedPayload\":\"" + Jose.encrypt(inner, fiuA.encPubKey()) + "\"}");
        Map<String, String> h = TestNet.entityHeaders(fiuA, "AA", aa2.id, UUID.randomUUID().toString());
        h.put("Preferred-Hop", aa3.id);
        HttpResponse<byte[]> ok = consent(fiuA, h);
        assertEquals(200, ok.statusCode(), new String(ok.body()));
    }

    /**
     * A new file's entity accepts calls after the rescan; an invalid change keeps the
     * previous settings; a disabled or deleted file unloads its entity.
     */
    @Test
    @Order(8)
    void rescanAddsChangesAndRemovesEntities() throws Exception {
        // a new entity file
        host.writeEntity(fiuC);
        TestNet.await("fiu-test-c01 loaded", () -> host.tenants().isOwn(fiuC.id));
        assertEquals(200, consent(fiuC, headersOf(fiuC)).statusCode());
        HttpResponse<byte[]> n = toHost("/iop/Consent/Notification", aa1.apiKey(), notification(aa2.id, encryptedFor(fiuC)));
        assertEquals(200, n.statusCode(), new String(n.body()));
        assertEquals(fiuC.id, fiuC.core.calls.get(fiuC.core.calls.size() - 1).header("Core-Entity-Id"));

        // an invalid change: the entity keeps its previous settings
        var before = host.tenants().get(fiuA.id).orElseThrow();
        host.writeEntity(fiuA.id + ".yaml", host.entityYaml(fiuA) + "noSuchKey: 1\n");
        Thread.sleep(2500);
        assertTrue(host.tenants().get(fiuA.id).orElseThrow() == before, "the previous settings stay in use");
        assertEquals(200, consent(fiuA, headersOf(fiuA)).statusCode());
        host.writeEntity(fiuA);

        // disabled: core calls for it get 400, its kid is unknown
        host.writeEntity(fiuB.id + ".yaml", host.entityYaml(fiuB).replace("enable: true", "enable: false"));
        TestNet.await("fiu-test-b01 unloaded", () -> !host.tenants().isOwn(fiuB.id));
        expectCoreError(consent(fiuB, headersOf(fiuB)), 400, "InvalidRequest", "Core-Entity-Id is not a loaded entity");
        HttpResponse<byte[]> gone = toHost("/iop/Consent/Notification", aa1.apiKey(), notification(aa2.id, encryptedFor(fiuB)));
        assertEquals(400, gone.statusCode());

        // deleted
        Files.delete(host.entityDir.resolve(fiuC.id + ".yaml"));
        TestNet.await("fiu-test-c01 unloaded", () -> !host.tenants().isOwn(fiuC.id));
        assertEquals(List.of(fiuA.id), host.tenants().ids());

        // with one entity loaded, a call without Core-Entity-Id is for that entity; another id is refused
        Map<String, String> noId = headersOf(fiuA);
        noId.remove("Core-Entity-Id");
        assertEquals(200, consent(fiuA, noId).statusCode());
        Map<String, String> other = headersOf(fiuA);
        other.put("Core-Entity-Id", fiuB.id);
        expectCoreError(consent(fiuA, other), 400, "InvalidRequest", "Core-Entity-Id is not a loaded entity");

        // with one entity loaded, an error before the entity is known is signed by it
        HttpResponse<byte[]> wrongKey = toHost("/iop/Consent/Notification", "not-an-api-key", notification(aa2.id, encryptedFor(fiuA)));
        assertEquals(400, wrongKey.statusCode());
        assertTrue(Jose.verifyDetached(header(wrongKey, "x-jws-signature"), wrongKey.body(), List.of(fiuA.sigPubKey())));

        // restore B for the tests that follow
        host.writeEntity(fiuB);
        TestNet.await("fiu-test-b01 loaded again", () -> host.tenants().isOwn(fiuB.id));
    }

    /**
     * A changed entity file: the previous settings serve until the new ones have their keys,
     * linkedAAs and token; then the new settings take over.
     */
    @Test
    @Order(9)
    void aChangedFileTakesOverOnlyWhenReady() throws Exception {
        TestNet.FakeCore newCore = new TestNet.FakeCore(TestNet.freePort());
        try {
            // new settings that cannot become ready: decryption keys from a core that answers 500
            HttpServer keys = net.httpsServer();
            keys.createContext("/", ex -> {
                ex.sendResponseHeaders(500, -1);
                ex.close();
            });
            keys.start();
            String keysUrl = "https://127.0.0.1:" + keys.getAddress().getPort() + "/fiu-core/keys/decryption";
            net.env().put("KEYS_TOKEN_A01", "synthetic-keys-token");
            String notReady = host.entityYaml(fiuA)
                    .replaceFirst("decryptionKeys: \\{[^\\n]*\\n", "decryptionKeys: {source: api, url: \"" + keysUrl
                            + "\", token: \"\\${KEYS_TOKEN_A01}\"}\n")
                    .replace("127.0.0.1:" + fiuA.corePort, "127.0.0.1:" + newCore.server.getAddress().getPort());
            var before = host.tenants().get(fiuA.id).orElseThrow();
            host.writeEntity(fiuA.id + ".yaml", notReady);
            Thread.sleep(3000);
            assertTrue(host.tenants().get(fiuA.id).orElseThrow() == before, "the previous settings keep serving");
            fiuA.core.calls.clear();
            assertEquals(200, toHost("/iop/Consent/Notification", aa1.apiKey(), notification(aa2.id, encryptedFor(fiuA))).statusCode());
            assertEquals(1, fiuA.core.calls.size(), "still the previous core");
            assertTrue(newCore.calls.isEmpty());
            keys.stop(0);

            // new settings that are ready at once (file keys): they take over after the rescan
            host.writeEntity(fiuA.id + ".yaml", host.entityYaml(fiuA)
                    .replace("127.0.0.1:" + fiuA.corePort, "127.0.0.1:" + newCore.server.getAddress().getPort()));
            TestNet.await("fiu-test-a01 reloaded", () -> host.tenants().get(fiuA.id).orElseThrow() != before);
            assertEquals(200, toHost("/iop/Consent/Notification", aa1.apiKey(), notification(aa2.id, encryptedFor(fiuA))).statusCode());
            assertEquals(1, newCore.calls.size(), "the new core");
            assertEquals(fiuA.id, newCore.calls.get(0).header("Core-Entity-Id"));
        } finally {
            host.writeEntity(fiuA);
            newCore.close();
        }
        assertNotNull(host.tenants().get(fiuA.id).orElse(null));
    }
}
