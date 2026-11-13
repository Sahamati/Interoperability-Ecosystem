package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.sahamati.iopgw.crypto.KeyRing;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.sources.CoreKeys;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Signing and decryption keys from the core. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CoreKeysE2ETest {

    TestNet net;
    TestNet.Party fiu;     // fiu-test-301: keys fetched from its core
    TestNet.Party fiuDown; // fiu-test-304: its core's key API is down at start-up
    TestNet.Party aa2;     // aa-test-302: Connected-AA (file keys)
    TestNet.Party aa3;     // aa-test-303: Customer-AA (file keys)
    HttpsServer keyApi;
    final AtomicInteger keyGets = new AtomicInteger();
    final AtomicReference<String> signingSet = new AtomicReference<>();
    final AtomicReference<String> decryptionSet = new AtomicReference<>();

    static final String KEYS_TOKEN = "synthetic-core-keys-token";

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        fiu = net.add("fiu-test-301", "FIU", "FIU");
        aa2 = net.add("aa-test-302", "AA", "AA");
        aa3 = net.add("aa-test-303", "AA", "AA");
        fiuDown = net.add("fiu-test-304", "FIU", "FIU");
        net.env().put("KEYS_TOKEN", KEYS_TOKEN);

        // The cores' key API (https): fiu-test-301 serves its keys; fiu-test-304 answers 503.
        keyApi = net.httpsServer();
        keyApi.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath();
            boolean auth = ("Bearer " + KEYS_TOKEN).equals(ex.getRequestHeaders().getFirst("Authorization"));
            String body = null;
            if (auth && path.equals("/fiu-core/keys/signing")) {
                body = signingSet.get();
            } else if (auth && path.equals("/fiu-core/keys/decryption")) {
                body = decryptionSet.get();
            }
            keyGets.incrementAndGet();
            byte[] b = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(body == null ? 503 : 200, b.length == 0 ? -1 : b.length);
            if (b.length > 0) {
                ex.getResponseBody().write(b);
            }
            ex.close();
        });
        keyApi.start();
        signingSet.set(set(key(fiu.id + "-sig", pemOf(fiu.id + "-sig.pem"), true, "2026-01-01", null)));
        decryptionSet.set(set(key(fiu.id + "-enc", pemOf(fiu.id + "-enc.pem"), true, "2026-01-01", null)));

        String aig = "aig:\n  aa:\n    - aa-test-302: [aa-test-303]\n";
        for (TestNet.Party f : List.of(fiu, fiuDown)) {
            f.aigYaml = aig;
            f.linked = List.of("aa-test-302");
            String keysBase = f == fiu ? "https://127.0.0.1:" + keyApi.getAddress().getPort()
                    : "https://127.0.0.1:" + keyApi.getAddress().getPort() + "/down";
            f.yamlEdit = y -> y
                    .replaceFirst("signingKey: \\{source: file, kid: [^}]*}", "signingKey: {source: api, token: \"\\${KEYS_TOKEN}\"}")
                    .replaceFirst("decryptionKeys: \\{source: file, keys: \\[[^]]*]}", "decryptionKeys: {source: api, token: \"\\${KEYS_TOKEN}\"}")
                    .replace("core: {baseUrl:", "core: {keysBaseUrl: \"" + keysBase + "\", baseUrl:");
        }
        aa3.linked = List.of("aa-test-302");
        for (TestNet.Party p : List.of(aa2, aa3, fiu, fiuDown)) {
            net.start(p);
        }
    }

    @AfterAll
    void stop() {
        net.close();
        keyApi.stop(0);
    }

    // ---------------- helpers ----------------

    String pemOf(String file) throws Exception {
        return Files.readString(net.dir.resolve(file));
    }

    static String newPem() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return TestNet.pem("PRIVATE KEY", g.generateKeyPair().getPrivate().getEncoded());
    }

    static ObjectNode key(String kid, String pem, Boolean active, String applied, String expiry) {
        ObjectNode k = Json.object();
        k.put("kid", kid);
        k.put("privateKey", pem);
        if (active != null) {
            k.put("active", active);
        }
        if (applied != null) {
            k.put("applied", applied);
        }
        if (expiry != null) {
            k.put("expiry", expiry);
        }
        return k;
    }

    static String set(ObjectNode... keys) {
        ObjectNode o = Json.object();
        ArrayNode a = o.putArray("keys");
        for (ObjectNode k : keys) {
            a.add(k);
        }
        return o.toString();
    }

    static String payload() {
        return "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-09T10:00:00.000Z\",\"txnid\":\"" + UUID.randomUUID()
                + "\",\"ConsentDetail\":{\"customer\":{\"id\":\"customer-test-301@aa-test-303\"}}}";
    }

    HttpResponse<byte[]> consent(TestNet.Party from) throws Exception {
        return net.call(from, "POST", "/fiu-dgw/Consent", TestNet.coreHeaders("AA", "aa-test-303", UUID.randomUUID().toString()), payload());
    }

    HttpResponse<byte[]> push(TestNet.Party p, String kind, String body) throws Exception {
        return net.callHttps(p, "POST", "/fiu-dgw/keys/" + kind, Map.of("Authorization", "Bearer " + TestNet.GW_TOKEN,
                "Correlation-Id", UUID.randomUUID().toString()), body);
    }

    static void noHeaders(HttpResponse<?> r) {
        for (String h : List.of("x-jws-signature", "Content-Type", "Correlation-Id", "Allow", "IOP-Gw-Error")) {
            assertTrue(r.headers().firstValue(h).isEmpty(), h + " must be absent");
        }
    }

    // ---------------- tests ----------------

    @Test
    void keysFetchedFromTheCoreSignAndDecryptEndToEnd() throws Exception {
        HttpResponse<byte[]> r = consent(fiu);
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals(List.of(fiu.id + "-sig"), fiu.gw.gateway.signing.all().stream().map(KeyRing.PrivKey::kid).toList());
    }

    @Test
    void coreDownAtStartUpThenKeysArriveByPush() throws Exception {
        // no signing key: the gateway cannot sign (500), and the core app is never reached
        aa3.core.calls.clear();
        HttpResponse<byte[]> r = consent(fiuDown);
        assertEquals(500, r.statusCode(), new String(r.body()));
        assertTrue(aa3.core.calls.isEmpty());

        // signing keys pushed; decryption keys still missing: the encrypted reply cannot be opened (503)
        HttpResponse<byte[]> p = push(fiuDown, "signing", set(key(fiuDown.id + "-sig", pemOf(fiuDown.id + "-sig.pem"), true, "2026-01-01", null)));
        assertEquals(200, p.statusCode(), new String(p.body()));
        r = consent(fiuDown);
        assertEquals(503, r.statusCode(), new String(r.body()));
        assertTrue(new String(r.body()).contains("decryption keys not loaded"));

        // {old, current} decryption keys: the reply is decrypted by kid
        p = push(fiuDown, "decryption", set(key("old-enc", newPem(), true, "2025-01-01", null),
                key(fiuDown.id + "-enc", pemOf(fiuDown.id + "-enc.pem"), true, "2026-01-01", null)));
        assertEquals(200, p.statusCode(), new String(p.body()));
        r = consent(fiuDown);
        assertEquals(200, r.statusCode(), new String(r.body()));
    }

    @Test
    void keyPushRules() throws Exception {
        String good = set(key(fiu.id + "-sig", pemOf(fiu.id + "-sig.pem"), true, "2026-01-01", null));

        // plain-HTTP listener: 403, no headers
        HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/keys/signing", Map.of("Authorization", "Bearer " + TestNet.GW_TOKEN), good);
        assertEquals(403, r.statusCode());
        assertTrue(new String(r.body()).contains("key push is accepted only over HTTPS"));
        noHeaders(r);

        // GET on the push path: 405; no token: 401; invalid set: 400 - all header-less
        r = net.callHttps(fiu, "GET", "/fiu-dgw/keys/signing", Map.of("Authorization", "Bearer " + TestNet.GW_TOKEN), null);
        assertEquals(405, r.statusCode());
        noHeaders(r);
        r = net.callHttps(fiu, "POST", "/fiu-dgw/keys/signing", Map.of("Correlation-Id", UUID.randomUUID().toString()), good);
        assertEquals(401, r.statusCode());
        noHeaders(r);
        r = push(fiu, "signing", set(key("dup", newPem(), true, "2026-01-01", null), key("dup", newPem(), true, "2026-01-01", null)));
        assertEquals(400, r.statusCode());
        noHeaders(r);
        assertEquals("", Json.text(Json.parseObject(r.body()), "txnid"), "a key set has no txnid");
        assertEquals(List.of(fiu.id + "-sig"), fiu.gw.gateway.signing.all().stream().map(KeyRing.PrivKey::kid).toList(),
                "an invalid set leaves the current one");

        // another mode's family is not served (404); neither is a file-sourced key type
        r = net.callHttps(fiu, "POST", "/fip-sgw/keys/signing", Map.of("Authorization", "Bearer " + TestNet.GW_TOKEN), good);
        assertEquals(404, r.statusCode());
        r = net.callHttps(aa2, "POST", "/aa-dgw/keys/signing", Map.of("Authorization", "Bearer " + TestNet.GW_TOKEN), good);
        assertEquals(404, r.statusCode());
        assertEquals("InvalidURI", Json.text(Json.parseObject(r.body()), "errorCode"));
        noHeaders(r);

        // a valid push replaces the set; the reply lists kids and validity, never key material
        String newKey = newPem();
        r = push(fiu, "signing", set(key("rotated-sig", newKey, true, "2026-01-01", null)));
        assertEquals(200, r.statusCode(), new String(r.body()));
        noHeaders(r);
        String reply = new String(r.body());
        assertFalse(reply.contains("PRIVATE KEY") || reply.contains("privateKey"), reply);
        JsonNode k = Json.parseObject(r.body()).get("keys").get(0);
        assertEquals("rotated-sig", k.get("kid").asText());
        assertTrue(k.get("usable").asBoolean());
        assertTrue(k.get("expiry").isNull());
        assertEquals(List.of("rotated-sig"), fiu.gw.gateway.signing.all().stream().map(KeyRing.PrivKey::kid).toList());

        // a set with only a future key is accepted, but nothing can be signed (500)
        r = push(fiu, "signing", set(key("future-sig", newPem(), true, "2099-01-01", null)));
        assertEquals(200, r.statusCode());
        assertFalse(Json.parseObject(r.body()).get("keys").get(0).get("usable").asBoolean());
        assertEquals(500, consent(fiu).statusCode());

        // restore for the other tests
        assertEquals(200, push(fiu, "signing", good).statusCode());
        assertEquals(200, consent(fiu).statusCode());
    }

    // ---------------- parsing ----------------

    @Test
    void keySetValidation() throws Exception {
        String pem = newPem();
        assertEquals(1, CoreKeys.parse(set(key("k1", pem, true, "2026-11-09T00:00:00+05:30", null)).getBytes()).size(),
                "offsets accepted, expiry absent accepted");
        ObjectNode nullExpiry = key("k1", pem, true, "2026-01-01", null);
        nullExpiry.putNull("expiry");
        assertEquals(1, CoreKeys.parse(set(nullExpiry).getBytes()).size());

        for (String bad : List.of(
                set(key("k1", pem, null, "2026-01-01", null)),             // active missing
                set(key("k1", pem, true, null, null)),                     // applied missing
                set(key("k1", pem, true, "09-11-2026", null)),             // bad date
                set(key("k1", pem, true, "2026-01-01", "2026-01-01")),     // expiry == applied
                set(key("k1", pem, true, "2026-02-01", "2026-01-01")),     // expiry before applied
                set(key("", pem, true, "2026-01-01", null)),               // empty kid
                set(key("k1", "not a pem", true, "2026-01-01", null)),     // not a key
                set(), "{}", "[]", "not json")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> CoreKeys.parse(bad.getBytes()), bad);
            assertFalse(e.getMessage().contains("PRIVATE") || e.getMessage().contains(pem.substring(40, 80)),
                    "errors never contain key material");
        }
    }

    @Test
    void validityChangesTheUsableSetByDate() throws Exception {
        java.time.Instant now = java.time.Instant.now();
        List<KeyRing.PrivKey> set = CoreKeys.parse(set(
                key("current", newPem(), true, now.minusSeconds(3600).toString(), now.plusSeconds(3600).toString()),
                key("next", newPem(), true, now.plusSeconds(1800).toString(), null),
                key("inactive", newPem(), false, "2026-01-01", null)).getBytes());
        KeyRing ring = new KeyRing(set);
        assertEquals(List.of("current"), ring.usable().stream().map(KeyRing.PrivKey::kid).toList());
        assertTrue(set.get(1).usable(now.plusSeconds(2000)), "the next key joins at applied");
        assertFalse(set.get(0).usable(now.plusSeconds(3600)), "the expiring key drops at expiry");
        assertFalse(set.get(2).usable(now));
        for (int i = 0; i < 20; i++) {
            assertEquals("current", ring.pickSigning().orElseThrow().kid());
        }
        assertNull(CoreKeys.status(set).get(1).get("expiry").textValue());
    }
}
