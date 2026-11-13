package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpsServer;
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
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CR key validity windows end to end: a Customer-AA gateway loads its
 * entities from an HTTPS Central Registry whose keys carry validFrom / validTo.
 *
 * <pre>
 * aa-test-703   the gateway under test (AA mode, cr.source api)
 * aa-test-704   Connected-AA whose signing key is in its window
 * aa-test-702   Connected-AA whose only signing key ended a minute ago
 * fiu-test-701  FIU whose encryption key is in its window
 * fiu-test-705  FIU whose only encryption key ended a minute ago
 * </pre>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CrKeyWindowsE2ETest {

    TestNet net;
    TestNet.Party aa703;
    TestNet.Party aa704;
    TestNet.Party aa702;
    TestNet.Party fiu701;
    TestNet.Party fiu705;
    HttpsServer cr;

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        aa703 = net.add("aa-test-703", "AA", "AA");
        aa704 = net.add("aa-test-704", "AA", "AA");
        aa702 = net.add("aa-test-702", "AA", "AA");
        fiu701 = net.add("fiu-test-701", "FIU", "FIU");
        fiu705 = net.add("fiu-test-705", "FIU", "FIU");
        net.env().put("CR_TOKEN", "synthetic-cr-token");

        String ended = Instant.now().minusSeconds(60).toString();
        Map<String, String> lists = Map.of(
                "AA", "[" + entry(aa703, null, null) + "," + entry(aa704, null, null) + "," + entry(aa702, ended, null) + "]",
                "FIU", "[" + entry(fiu701, null, null) + "," + entry(fiu705, null, ended) + "]",
                "FIP", "[" + entry(net.add("fip-test-706", "FIP", "FIP"), null, null) + "]");
        cr = net.httpsServer();
        cr.createContext("/v2/entityInfo/", ex -> {
            String type = ex.getRequestURI().getPath().substring("/v2/entityInfo/".length());
            boolean auth = "Bearer synthetic-cr-token".equals(ex.getRequestHeaders().getFirst("Authorization"));
            byte[] b = (auth ? lists.getOrDefault(type, "[]") : "").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(auth ? 200 : 401, b.length == 0 ? -1 : b.length);
            if (b.length > 0) {
                ex.getResponseBody().write(b);
            }
            ex.close();
        });
        cr.start();
        String crBlock = "cr: {source: api, baseUrl: \"https://127.0.0.1:" + cr.getAddress().getPort() + "\", token: \"${CR_TOKEN}\"}\n";
        aa703.yamlEdit = y -> y.replaceFirst("(?s)cr: \\{source: config\\}\\nentities:\\n.*?(?=aigSource:)",
                java.util.regex.Matcher.quoteReplacement(crBlock));
        net.start(aa703);
    }

    @AfterAll
    void stop() {
        net.close();
        cr.stop(0);
    }

    /** A CR element whose keys are {key, validTo} items; sigTo / encTo end the signing / encryption key. */
    static String entry(TestNet.Party p, String sigTo, String encTo) {
        String sig = new RSAKey.Builder(p.sigPub).keyID(p.id + "-sig").keyUse(KeyUse.SIGNATURE).build().toJSONString();
        String enc = new RSAKey.Builder(p.encPub).keyID(p.id + "-enc").keyUse(KeyUse.ENCRYPTION).build().toJSONString();
        return "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-10T10:00:00.000Z\",\"txnid\":\"" + UUID.randomUUID() + "\","
                + "\"entityinfo\":{\"id\":\"" + p.id + "\",\"baseurl\":\"" + p.publicUrl() + "\",\"interop\":true,"
                + "\"keys\":{\"signature\":[{\"key\":" + sig + (sigTo == null ? "" : ",\"validTo\":\"" + sigTo + "\"") + "}],"
                + "\"encryption\":[{\"key\":" + enc + (encTo == null ? "" : ",\"validTo\":\"" + encTo + "\"") + "}]}}}";
    }

    /** /iop/Consent to aa-test-703 from Connected-AA {@code hop} on behalf of FIU {@code fiu}. */
    HttpResponse<byte[]> deliver(TestNet.Party hop, TestNet.Party fiu) throws Exception {
        byte[] payload = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"ConsentDetail\":{}}").getBytes(StandardCharsets.UTF_8);
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode init = env.putObject("Initiator");
        init.put("type", "FIU");
        init.put("id", fiu.id);
        env.put("encryptedPayload", Jose.encrypt(Jose.signCompact(payload, fiu.sig, "RS256"), new PubKey(aa703.id + "-enc", aa703.encPub)));
        byte[] body = Json.bytes(env);
        return net.client.send(HttpRequest.newBuilder(URI.create(aa703.publicUrl() + "/iop/Consent"))
                .header("x-conn_aa_api_key", hop.apiKey())
                .header("x-jws-signature", Jose.signDetached(body, hop.sig, "RS256"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    @Test
    void keysInTheirWindowsWork() throws Exception {
        aa703.core.calls.clear();
        HttpResponse<byte[]> r = deliver(aa704, fiu701);
        assertEquals(200, r.statusCode(), new String(r.body()));
        assertEquals(1, aa703.core.calls.size());
    }

    @Test
    void aSenderKeyPastItsValidToGets401() throws Exception {
        aa703.core.calls.clear();
        HttpResponse<byte[]> r = deliver(aa702, fiu701);
        assertEquals(401, r.statusCode(), new String(r.body()));
        assertTrue(aa703.core.calls.isEmpty());
    }

    @Test
    void anInitiatorWhoseOnlyEncryptionKeyEndedGets500AndTheCoreIsNotCalled() throws Exception {
        aa703.core.calls.clear();
        HttpResponse<byte[]> r = deliver(aa704, fiu705);
        assertEquals(500, r.statusCode(), new String(r.body()));
        assertEquals("cannot encrypt response for Initiator", Json.text(Json.parseObject(r.body()), "errorMsg"));
        assertTrue(aa703.core.calls.isEmpty(), "the core is not called");
    }
}
