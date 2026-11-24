package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.http.Json;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Which entity files load, and a gateway with no entity loaded. */
class MultiTenantFilesE2ETest {

    /**
     * Of three entity files (two enabled, one disabled), a file without {@code enable}, a
     * {@code .txt} file, a file in a sub-folder, a duplicate entityId and an invalid file, exactly
     * the two enabled entities load, and the gateway starts.
     */
    @Test
    void onlyEnabledEntityFilesDirectlyInTheFolderLoad() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Host host = net.addHost("files", "FIU");
            TestNet.Party c1 = net.addEntity(host, "fiu-test-c01");
            TestNet.Party c2 = net.addEntity(host, "fiu-test-c02");
            TestNet.Party c3 = net.addEntity(host, "fiu-test-c03");
            TestNet.Party c4 = net.addEntity(host, "fiu-test-c04");
            TestNet.Party c5 = net.addEntity(host, "fiu-test-c05");
            TestNet.Party c6 = net.addEntity(host, "fiu-test-c06");
            net.add("aa-test-c11", "AA", "AA");
            host.writeEntity("a.yaml", host.entityYaml(c1));
            host.writeEntity("b.yml", host.entityYaml(c2));
            host.writeEntity("c.yaml", host.entityYaml(c3).replace("enable: true", "enable: false"));
            host.writeEntity("d.yaml", host.entityYaml(c4).replace("enable: true\n", ""));
            host.writeEntity("notes.txt", host.entityYaml(c5));
            Files.createDirectories(host.entityDir.resolve("sub"));
            Files.writeString(host.entityDir.resolve("sub").resolve("e.yaml"), host.entityYaml(c6));
            // same entityId as a.yaml, sorts after it: skipped
            host.writeEntity("e-duplicate.yaml", host.entityYaml(c1).replace("127.0.0.1:" + c1.corePort, "127.0.0.1:1"));
            // invalid at start-up: skipped, the gateway still starts
            host.writeEntity("f-invalid.yaml", host.entityYaml(c5).replace("entityId: fiu-test-c05", "entityId: fiu-test-c05\nnoSuchKey: 1"));
            net.start(host);

            assertEquals(List.of(c1.id, c2.id), host.tenants().ids());
            assertEquals("a.yaml", host.tenants().get(c1.id).orElseThrow().settings.file, "the file whose name sorts first is used");
            assertEquals("b.yml", host.tenants().get(c2.id).orElseThrow().settings.file);
        }
    }

    /**
     * With no enabled entity the gateway starts; /iop calls get 503 ServiceUnavailable and
     * internal API calls 400 InvalidRequest; an entity file added later is used after the next rescan.
     */
    @Test
    void noEntityLoaded() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Host host = net.addHost("empty", "FIU");
            TestNet.Party d1 = net.addEntity(host, "fiu-test-d01");
            TestNet.Party aa = net.add("aa-test-d11", "AA", "AA");
            net.start(host);
            assertEquals(List.of(), host.tenants().ids());

            byte[] body = "{\"ver\":\"2.0.0\",\"txnid\":\"t\",\"correlationId\":\"0b6f9e2c-3c1a-4d55-9b1e-6a2f4c1d9e01\"}"
                    .getBytes(StandardCharsets.UTF_8);
            HttpRequest req = HttpRequest.newBuilder(URI.create(host.publicUrl() + "/iop/Consent/Notification"))
                    .header("x-conn_aa_api_key", aa.apiKey())
                    .header("x-jws-signature", Jose.signDetached(body, aa.sig, "RS256"))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            HttpResponse<byte[]> r = net.client.send(req, HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(503, r.statusCode(), new String(r.body()));
            assertEquals("ServiceUnavailable", Json.text(Json.parseObject(r.body()), "errorCode"));
            assertNull(r.headers().firstValue("x-jws-signature").orElse(null), "no entity to sign with");

            Map<String, String> h = TestNet.entityHeaders(d1, "AA", aa.id, UUID.randomUUID().toString());
            HttpResponse<byte[]> internal = net.call(d1, "POST", "/fiu-dgw/Consent", h, "{\"ver\":\"2.0.0\",\"txnid\":\"t\"}");
            assertEquals(400, internal.statusCode());
            JsonNode b = Json.parseObject(internal.body());
            assertEquals("InvalidRequest", Json.text(b, "errorCode"));
            assertEquals("no entity loaded", Json.text(b, "errorMsg"));
            assertEquals("true", internal.headers().firstValue("IOP-Gw-Error").orElse(null));

            // a file added later: the entity is used after the next rescan (here: the call gets past
            // the entity checks and stops at the Target, which this test net does not register)
            host.writeEntity(d1);
            TestNet.await("fiu-test-d01 loaded", () -> host.tenants().isOwn(d1.id));
            HttpResponse<byte[]> later = net.call(d1, "POST", "/fiu-dgw/Consent",
                    TestNet.entityHeaders(d1, "AA", "aa-test-unknown", UUID.randomUUID().toString()), "{\"ver\":\"2.0.0\",\"txnid\":\"t\"}");
            assertEquals("Target is not registered", Json.text(Json.parseObject(later.body()), "errorMsg"));
        }
    }
}
