package org.sahamati.iopgw;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.crypto.KeyRing;
import org.sahamati.iopgw.http.Json;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A decryption key {@code kid} belongs to one entity only. A {@code kid} already used by
 * another loaded entity stops that entity from loading (files in name order at start-up); a key set
 * fetched or pushed later that holds another entity's {@code kid} is refused: the GET keeps the
 * current set, the POST answers {@code 400 InvalidRequest}.
 */
class MultiTenantKidsE2ETest {

    /** {@code {"keys": [...]}} with each entity's decryption private key under the given kid. */
    private static String keySet(TestNet net, String... idAndKid) throws Exception {
        StringBuilder sb = new StringBuilder("{\"keys\":[");
        for (int i = 0; i < idAndKid.length; i += 2) {
            String pem = Files.readString(net.dir.resolve(idAndKid[i] + "-enc.pem"));
            sb.append(i == 0 ? "" : ",").append("{\"kid\":\"").append(idAndKid[i + 1]).append("\",\"privateKey\":")
                    .append(Json.MAPPER.writeValueAsString(pem)).append(",\"active\":true,\"applied\":\"2026-01-01\"}");
        }
        return sb.append("]}").toString();
    }

    private static List<String> kids(TestNet.Host host, String id) {
        return host.tenants().get(id).orElseThrow().decryption.all().stream().map(KeyRing.PrivKey::kid).toList();
    }

    /** At start-up, files load in name order: the second entity naming the same kid is not loaded. */
    @Test
    void aKidUsedByAnEntityLoadedEarlierStopsTheLaterOne() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Host host = net.addHost("kids-start", "FIU");
            TestNet.Party a = net.addEntity(host, "fiu-test-k01");
            TestNet.Party b = net.addEntity(host, "fiu-test-k02");
            TestNet.Party c = net.addEntity(host, "fiu-test-k03");
            net.add("aa-test-k11", "AA", "AA");
            host.writeEntity("a.yaml", host.entityYaml(a));
            // b's file names a's decryption kid (with b's own key file): b is not loaded
            host.writeEntity("b.yaml", host.entityYaml(b).replace("kid: fiu-test-k02-enc", "kid: fiu-test-k01-enc"));
            host.writeEntity("c.yaml", host.entityYaml(c));
            net.start(host);
            assertEquals(List.of(a.id, c.id), host.tenants().ids());

            // a later file with a kid already in use is not loaded either
            TestNet.Party d = net.addEntity(host, "fiu-test-k04");
            host.writeEntity("d.yaml", host.entityYaml(d).replace("kid: fiu-test-k04-enc", "kid: fiu-test-k03-enc"));
            TestNet.Party e = net.addEntity(host, "fiu-test-k05");
            host.writeEntity("e.yaml", host.entityYaml(e));
            TestNet.await("fiu-test-k05 loaded", () -> host.tenants().isOwn(e.id));
            assertFalse(host.tenants().isOwn(d.id), "fiu-test-k04 names fiu-test-k03's kid");
            assertEquals(List.of(c.id + "-enc"), kids(host, c.id), "the entity that owns the kid keeps it");
        }
    }

    /** Keys from the core: a first fetch with another entity's kid stops the entity from loading. */
    @Test
    void aFirstFetchedSetWithAnotherEntitysKidStopsTheEntity() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Host host = net.addHost("kids-fetch", "FIU", "fiu-test-k21");
            TestNet.Party a = host.entity("fiu-test-k21");
            TestNet.Party b = net.addEntity(host, "fiu-test-k22");
            net.add("aa-test-k31", "AA", "AA");
            HttpServer core = net.httpsServer();
            byte[] set = keySet(net, b.id, a.id + "-enc").getBytes(StandardCharsets.UTF_8);
            core.createContext("/", ex -> {
                ex.sendResponseHeaders(200, set.length);
                ex.getResponseBody().write(set);
                ex.close();
            });
            core.start();
            try {
                net.env().put("KEYS_TOKEN", "synthetic-keys-token");
                net.start(host);
                host.writeEntity(b.id + ".yaml", host.entityYaml(b).replaceFirst("decryptionKeys: \\{[^\\n]*\\n",
                        "decryptionKeys: {source: api, url: \"https://127.0.0.1:" + core.getAddress().getPort()
                                + "/fiu-core/keys/decryption\", token: \"\\${KEYS_TOKEN}\"}\n"));
                Thread.sleep(2500);
                assertEquals(List.of(a.id), host.tenants().ids(), "fiu-test-k22's first key set holds fiu-test-k21's kid");
            } finally {
                core.stop(0);
            }
        }
    }

    /** Keys from the core: a later GET or POST with another entity's kid is refused; the current set stays. */
    @Test
    void aLaterSetWithAnotherEntitysKidIsRefused() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Host host = net.addHost("kids-later", "FIU", "fiu-test-k41", "fiu-test-k42");
            TestNet.Party a = host.entity("fiu-test-k41");
            TestNet.Party b = host.entity("fiu-test-k42");
            net.add("aa-test-k51", "AA", "AA");
            AtomicReference<String> served = new AtomicReference<>(keySet(net, b.id, b.id + "-enc"));
            HttpServer core = net.httpsServer();
            core.createContext("/", ex -> {
                byte[] body = served.get().getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, body.length);
                ex.getResponseBody().write(body);
                ex.close();
            });
            core.start();
            try {
                net.env().put("KEYS_TOKEN", "synthetic-keys-token");
                host.entityEdit.put(b.id, y -> y.replaceFirst("decryptionKeys: \\{[^\\n]*\\n",
                        "decryptionKeys: {source: api, url: \"https://127.0.0.1:" + core.getAddress().getPort()
                                + "/fiu-core/keys/decryption\", token: \"\\${KEYS_TOKEN}\", refreshSeconds: 1}\n"));
                net.start(host);
                assertEquals(List.of(b.id + "-enc"), kids(host, b.id));

                // the core now serves a set holding a's kid: the scheduled GET keeps b's current set
                served.set(keySet(net, b.id, b.id + "-enc", a.id, a.id + "-enc"));
                Thread.sleep(2500);
                assertEquals(List.of(b.id + "-enc"), kids(host, b.id), "the GET keeps the current set");
                served.set(keySet(net, b.id, b.id + "-enc"));

                // a push holding a's kid: 400 InvalidRequest, header-less; the current set stays
                Map<String, String> h = Map.of("Authorization", "Bearer " + b.gwToken(), "Core-Entity-Id", b.id);
                HttpResponse<byte[]> r = net.callHttps(b, "POST", "/fiu-dgw/keys/decryption", h,
                        keySet(net, b.id, "fiu-test-k42-enc-2", a.id, a.id + "-enc"));
                assertEquals(400, r.statusCode(), new String(r.body()));
                assertEquals("InvalidRequest", Json.text(Json.parseObject(r.body()), "errorCode"));
                assertTrue(Json.text(Json.parseObject(r.body()), "errorMsg").contains("already used by entity fiu-test-k41"));
                assertTrue(r.headers().firstValue("IOP-Gw-Error").isEmpty(), "push replies carry no headers");
                assertEquals(List.of(b.id + "-enc"), kids(host, b.id));
                assertEquals(List.of(a.id + "-enc"), kids(host, a.id));

                // a push of b's own new key is accepted
                HttpResponse<byte[]> ok = net.callHttps(b, "POST", "/fiu-dgw/keys/decryption", h,
                        keySet(net, b.id, b.id + "-enc", b.id, "fiu-test-k42-enc-2"));
                assertEquals(200, ok.statusCode(), new String(ok.body()));
                assertEquals(List.of(b.id + "-enc", "fiu-test-k42-enc-2"), kids(host, b.id));
            } finally {
                core.stop(0);
            }
        }
    }
}
