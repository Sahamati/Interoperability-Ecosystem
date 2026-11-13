package org.sahamati.iopgw;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.model.Roles;
import org.sahamati.iopgw.sources.Registry;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Central Registry entity lists. */
class RegistryTest {

    HttpServer cr;
    final Map<String, String> lists = new ConcurrentHashMap<>();
    Config.Cr conf;

    @BeforeEach
    void start() throws Exception {
        cr = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        cr.createContext("/v2/entityInfo/", ex -> {
            String type = ex.getRequestURI().getPath().substring("/v2/entityInfo/".length());
            byte[] body = lists.getOrDefault(type, "[]").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        cr.start();
        conf = new Config.Cr();
        conf.baseUrl = "http://127.0.0.1:" + cr.getAddress().getPort();
        conf.timeoutSeconds = 5;
    }

    @AfterEach
    void stop() {
        cr.stop(0);
    }

    private static String jwk(String kid, KeyUse use) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return new RSAKey.Builder((RSAPublicKey) g.generateKeyPair().getPublic()).keyID(kid).keyUse(use).build().toJSONString();
    }

    /** A CR key item: {"key": <JWK>, "validFrom", "validTo"}; null bounds are left out. */
    private static String item(String jwk, String from, String to) {
        return "{\"key\":" + jwk + (from == null ? "" : ",\"validFrom\":\"" + from + "\"")
                + (to == null ? "" : ",\"validTo\":\"" + to + "\"") + "}";
    }

    private static String entry(String id, String baseurl, String interop) throws Exception {
        return entry(id, baseurl, interop, item(jwk(id + "-sig", KeyUse.SIGNATURE), null, null),
                item(jwk(id + "-enc", KeyUse.ENCRYPTION), null, null));
    }

    private static String entry(String id, String baseurl, String interop, String sigItems, String encItems) {
        return "{\"ver\":\"2.0.0\",\"entityinfo\":{\"id\":\"" + id + "\",\"baseurl\":\"" + baseurl + "\""
                + (interop == null ? "" : ",\"interop\":" + interop)
                + ",\"keys\":{\"signature\":[" + sigItems + "],\"encryption\":[" + encItems + "]}}}";
    }

    private boolean load(Registry r) {
        return r.loadFromCr(conf, Roles.Mode.FIU, new Http(), () -> Optional.of("synthetic-token"));
    }

    @Test
    void trailingSlashIsRemovedFromBaseUrl() throws Exception {
        lists.put("AA", "[" + entry("aa-test-002", "https://aa-test-002.example.invalid/v2/", "true") + ","
                + entry("aa-test-003", "https://aa-test-003.example.invalid", "false") + "]");
        Registry r = Registry.fromCentralRegistry(Map.of());
        assertTrue(load(r));
        assertEquals("https://aa-test-002.example.invalid/v2", r.get("aa-test-002").orElseThrow().baseUrl());
        assertTrue(r.get("aa-test-002").orElseThrow().interop());
        assertFalse(r.get("aa-test-003").orElseThrow().interop());
    }

    @Test
    void absentInteropMeansNotReady() throws Exception {
        lists.put("AA", "[" + entry("aa-test-002", "https://aa-test-002.example.invalid", null) + "]");
        Registry r = Registry.fromCentralRegistry(Map.of());
        assertTrue(load(r));
        assertFalse(r.get("aa-test-002").orElseThrow().interop());
    }

    @Test
    void interopAsAStringFailsTheFetchAndKeepsThePreviousLists() throws Exception {
        lists.put("AA", "[" + entry("aa-test-002", "https://aa-test-002.example.invalid", "true") + "]");
        Registry r = Registry.fromCentralRegistry(Map.of());
        assertTrue(load(r));
        lists.put("AA", "[" + entry("aa-test-004", "https://aa-test-004.example.invalid", "\"true\"") + "]");
        assertFalse(load(r), "a string interop fails the whole fetch");
        assertTrue(r.get("aa-test-002").isPresent(), "the previous lists are kept");
        assertTrue(r.get("aa-test-004").isEmpty());
    }

    @Test
    void emptyListFailsTheFetch() {
        lists.put("AA", "[]");
        Registry r = Registry.fromCentralRegistry(Map.of());
        assertFalse(load(r));
        assertFalse(r.loaded());
    }

    // ---------------- key validity windows ----------------

    @Test
    void keyWindowsDecideWhichKeysAreUsedAtEachUse() throws Exception {
        java.time.Instant now = java.time.Instant.now();
        String past = now.minusSeconds(60).toString();
        String yesterday = now.minusSeconds(86_400).toString();
        String tomorrow = now.plusSeconds(86_400).toString();
        String inAnHour = now.plusSeconds(3600).atOffset(java.time.ZoneOffset.ofHoursMinutes(5, 30)).toString();
        String sig = String.join(",",
                item(jwk("s-ended", KeyUse.SIGNATURE), yesterday, past),        // validTo just passed: loaded, not used
                item(jwk("s-current", KeyUse.SIGNATURE), yesterday, tomorrow),  // used
                item(jwk("s-open", KeyUse.SIGNATURE), null, null),              // no window: used
                item(jwk("s-next", KeyUse.SIGNATURE), inAnHour, null),          // starts in an hour (+05:30 offset)
                item(jwk("s-date", KeyUse.SIGNATURE), "2026-11-01", null),      // a date without a time: skipped
                item(jwk("s-reversed", KeyUse.SIGNATURE), tomorrow, yesterday), // validTo before validFrom: skipped
                jwk("s-bare", KeyUse.SIGNATURE));                               // a bare JWK: skipped
        String enc = String.join(",",
                item(jwk("e-ended", KeyUse.ENCRYPTION), null, past),
                item(jwk("e-current", KeyUse.ENCRYPTION), "", ""));             // empty bounds: no limit
        lists.put("AA", "[" + entry("aa-test-002", "https://aa-test-002.example.invalid", "true", sig, enc) + "]");
        Registry r = Registry.fromCentralRegistry(Map.of());
        assertTrue(load(r), "invalid keys are skipped; the load does not fail");
        Registry.Entity e = r.get("aa-test-002").orElseThrow();

        assertEquals(java.util.List.of("s-ended", "s-current", "s-open", "s-next"),
                e.allSigningKeys().stream().map(org.sahamati.iopgw.crypto.PubKey::kid).toList(), "out-of-window keys stay in the lists");
        assertEquals(java.util.List.of("s-current", "s-open"), e.signingKeys().stream().map(org.sahamati.iopgw.crypto.PubKey::kid).toList());
        org.sahamati.iopgw.crypto.PubKey next = e.allSigningKeys().get(3);
        assertFalse(next.usable(now));
        assertTrue(next.usable(now.plusSeconds(3601)), "usable after its validFrom, without a refresh");
        for (int i = 0; i < 20; i++) {
            assertEquals("e-current", e.encryptionKey().orElseThrow().kid(), "an ended encryption key is never chosen");
        }
    }

    @Test
    void keyWindowsSurvivePersistenceAndOldSnapshotsAreNotRestored() throws Exception {
        String past = java.time.Instant.now().minusSeconds(60).toString();
        lists.put("AA", "[" + entry("aa-test-002", "https://aa-test-002.example.invalid", "true",
                item(jwk("s-ended", KeyUse.SIGNATURE), null, past), item(jwk("e-open", KeyUse.ENCRYPTION), null, null)) + "]");
        Registry r = Registry.fromCentralRegistry(Map.of());
        assertTrue(load(r));
        var snapshot = org.sahamati.iopgw.sources.CacheCodec.entities(r.rawEntities());
        Registry restored = Registry.fromCentralRegistry(Map.of());
        restored.restore(org.sahamati.iopgw.sources.CacheCodec.entities(snapshot));
        Registry.Entity e = restored.get("aa-test-002").orElseThrow();
        assertEquals(1, e.allSigningKeys().size());
        assertTrue(e.signingKeys().isEmpty(), "the window came back with the key");

        // a snapshot from before the windows (a bare array) is not restored
        var old = org.sahamati.iopgw.http.Json.MAPPER.createArrayNode();
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> org.sahamati.iopgw.sources.CacheCodec.entities(old));
    }
}
