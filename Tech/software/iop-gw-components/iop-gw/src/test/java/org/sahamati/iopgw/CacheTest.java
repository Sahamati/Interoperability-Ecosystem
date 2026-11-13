package org.sahamati.iopgw;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.sources.CacheCodec;
import org.sahamati.iopgw.sources.Registry;
import org.sahamati.iopgw.sources.Store;
import org.sahamati.iopgw.sources.TokenService;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Persistent cache, both engines. */
class CacheTest {

    @ParameterizedTest
    @ValueSource(strings = {"rocksdb", "file"})
    void storeSurvivesReopenReplacesSnapshotsAndIs0700(String engine) throws Exception {
        Path dir = Files.createTempDirectory("iopgw-cache").resolve("store");
        try (Store s = Store.open(dir, engine)) {
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
            s.save("aig/graph", Json.MAPPER.readTree("{\"v\":1}"));
            s.save("aig/graph", Json.MAPPER.readTree("{\"v\":2}"));
            // one gateway process per directory
            assertThrows(IOException.class, () -> Store.open(dir, engine));
            s.compact();
        }
        try (Store s = Store.open(dir, engine)) {
            Store.Snapshot snap = s.load("aig/graph").orElseThrow();
            assertEquals(2, snap.data().get("v").asInt());
            assertTrue(s.load("cr/entities").isEmpty());
            // decoding into the wrong type fails
            assertThrows(IllegalArgumentException.class, () -> CacheCodec.entities(snap.data()));
            assertThrows(IllegalArgumentException.class, () -> CacheCodec.pubKeys(snap.data()));
        }
    }

    @Test
    void unknownEngineIsRefused() {
        assertThrows(IOException.class, () -> Store.open(Files.createTempDirectory("iopgw-cache"), "sqlite"));
    }

    private static TokenService tokenService(Path credentials, String url) {
        Config.TokenServiceConf c = new Config.TokenServiceConf();
        c.baseUrl = url;
        c.credentialsFile = credentials.toString();
        c.timeoutSeconds = 2;
        return new TokenService(c, "fiu-test-501", new Http());
    }

    private static void saveToken(Store s, Instant issued, Instant expires) {
        var o = Json.object();
        o.put("token", "synthetic-access-token");
        o.put("issuedAt", issued.toString());
        o.put("expiresAt", expires.toString());
        s.save("token/fiu-test-501", o);
    }

    @Test
    void accessTokenRestoreRules() throws Exception {
        Path dir = Files.createTempDirectory("iopgw-cache");
        Path creds = dir.resolve("creds.json");
        Files.writeString(creds, "{\"entityId\":\"fiu-test-501\",\"entitySecret\":\"synthetic-secret\"}");
        AtomicInteger calls = new AtomicInteger();
        HttpServer ts = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ts.createContext("/", ex -> {
            calls.incrementAndGet();
            ex.sendResponseHeaders(503, -1);
            ex.close();
        });
        ts.start();
        String url = "http://127.0.0.1:" + ts.getAddress().getPort();
        try (Store s = Store.open(dir.resolve("store"))) {
            // fresh: restored, no token-service call
            saveToken(s, Instant.now().minusSeconds(60), Instant.now().plusSeconds(86_400));
            TokenService t = tokenService(creds, url);
            t.persistIn(s);
            assertEquals("synthetic-access-token", t.get().orElseThrow());
            assertEquals(0, calls.get());

            // within the refresh margin: refreshed at first use (the refresh fails here: the valid token is kept)
            saveToken(s, Instant.now().minusSeconds(80_000), Instant.now().plusSeconds(600));
            t = tokenService(creds, url);
            t.persistIn(s);
            assertEquals("synthetic-access-token", t.get().orElseThrow());
            assertEquals(1, calls.get());

            // expired: never restored
            saveToken(s, Instant.now().minusSeconds(7200), Instant.now().minusSeconds(1));
            t = tokenService(creds, url);
            t.persistIn(s);
            assertTrue(t.get().isEmpty());
        } finally {
            ts.stop(0);
        }
    }

    @Test
    void crListsAreRestoredWithOverridesReappliedButNeverPersisted() throws Exception {
        Path dir = Files.createTempDirectory("iopgw-cache");
        try (TestNet net = new TestNet(); Store s = Store.open(dir.resolve("store"))) {
            TestNet.Party aa = net.add("aa-test-502", "AA", "AA");
            Registry.Entity e = new Registry.Entity("aa-test-502", org.sahamati.iopgw.model.Roles.EntityType.AA,
                    "https://aa-test-502.example.invalid", true, List.of(aa.sigPubKey()), List.of(), null);
            s.save("cr/entities", CacheCodec.entities(List.of(e)));

            Registry r = Registry.fromCentralRegistry(Map.of("aa-test-502",
                    new Registry.Override("http://127.0.0.1:1", "synthetic-outbound-key")));
            r.restore(CacheCodec.entities(s.load("cr/entities").orElseThrow().data()));
            assertTrue(r.loaded());
            assertEquals("http://127.0.0.1:1", r.get("aa-test-502").orElseThrow().baseUrl());
            assertEquals("synthetic-outbound-key", r.get("aa-test-502").orElseThrow().outboundApiKey());
            String persisted = CacheCodec.entities(r.rawEntities()).toString();
            assertFalse(persisted.contains("synthetic-outbound-key") || persisted.contains("127.0.0.1:1"), persisted);
        }
    }

    /** End to end: a gateway with cache.dir persists the AIG and serves it after a restart with the AIG down. */
    @ParameterizedTest
    @ValueSource(strings = {"rocksdb", "file"})
    void aigServedFromTheCacheAfterARestartWithTheSourceDown(String engine) throws Exception {
        AtomicInteger aigCalls = new AtomicInteger();
        HttpServer aig = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        aig.createContext("/v1/aig/aa", ex -> {
            aigCalls.incrementAndGet();
            byte[] b = ("{\"ver\":\"1.0.0\",\"aa\":[{\"id\":\"aa-test-512\",\"peer-AA\":[{\"id\":\"aa-test-513\",\"verified\":true}]}]}")
                    .getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        aig.start();
        Path cacheDir = Files.createTempDirectory("iopgw-cache").resolve("fiu");
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-511", "FIU", "FIU");
            net.add("aa-test-512", "AA", "AA");
            TestNet.Party aa3 = net.add("aa-test-513", "AA", "AA");
            fiu.linked = List.of("aa-test-512");
            fiu.overrides.put("aigSource", "aigSource: api\naigBaseUrl: \"http://127.0.0.1:" + aig.getAddress().getPort()
                    + "\"\naigToken: \"${GW_TOKEN}\"\ncache: {dir: \"" + cacheDir + "\", engine: " + engine + "}");
            aa3.linked = List.of("aa-test-512");
            net.start();
            assertEquals(200, consent(net, fiu).statusCode());
            assertEquals(1, aigCalls.get());
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(cacheDir)));

            // restart with the AIG down: the fresh persisted graph is served, nothing fetched
            net.stopGateway(fiu);
            aig.stop(0);
            net.start(fiu);
            assertTrue(fiu.gw.gateway.aig.loaded());
            assertEquals(200, consent(net, fiu).statusCode());
            assertEquals(1, aigCalls.get());

            // nothing secret in the store: no private key, no api-key, no internal API token
            net.stopGateway(fiu);
            try (Stream<Path> files = Files.walk(cacheDir)) {
                for (Path f : files.filter(Files::isRegularFile).toList()) {
                    String text = new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1);
                    assertFalse(text.contains("PRIVATE KEY"), f.toString());
                    assertFalse(text.contains("api-key-of-"), f.toString());
                    assertFalse(text.contains(TestNet.GW_TOKEN), f.toString());
                }
            }
        } finally {
            aig.stop(0);
        }
    }

    private static java.net.http.HttpResponse<byte[]> consent(TestNet net, TestNet.Party fiu) throws Exception {
        String body = "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-09T10:00:00.000Z\",\"txnid\":\"" + UUID.randomUUID()
                + "\",\"ConsentDetail\":{\"customer\":{\"id\":\"customer-test-501@aa-test-513\"}}}";
        return net.call(fiu, "POST", "/fiu-dgw/Consent", TestNet.coreHeaders("AA", "aa-test-513", UUID.randomUUID().toString()), body);
    }
}
