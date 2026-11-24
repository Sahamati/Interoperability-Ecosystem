package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.http.Json;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AA mode tokens: the token service is asked twice at {@code tokenService.path},
 * once without and once with {@code use=iop}; a forwarded {@code /iop} call carries the IopToken
 * as the role api-key; both tokens are persisted, under {@code token/<id>} and {@code iopToken/<id>}.
 *
 * <pre>
 * fiu-test-h03  FIU (sender, Initiator)
 * aa-test-h01   Connected-AA with tokenService (hop)
 * aa-test-h02   Customer-AA (accepts aa-test-h01's IopToken as its role api-key)
 * </pre>
 */
class AaTokensE2ETest {

    @Test
    void anAaAsksForBothTokensAndForwardsWithTheIopToken() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party hop = net.add("aa-test-h01", "AA", "AA");
            TestNet.Party target = net.add("aa-test-h02", "AA", "AA");
            TestNet.Party fiu = net.add("fiu-test-h03", "FIU", "FIU");
            List<String> forms = new CopyOnWriteArrayList<>();
            HttpServer ts = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            ts.createContext("/entity/token/generate", ex -> {
                String form = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                forms.add(form);
                // the IopToken is what aa-test-h02 accepts as aa-test-h01's role api-key
                String token = form.contains("use=iop") ? hop.apiKey() : "access-token-of-aa-test-h01";
                byte[] b = ("{\"accessToken\":\"" + token + "\",\"expiresIn\":86400}").getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, b.length);
                ex.getResponseBody().write(b);
                ex.close();
            });
            ts.start();
            try {
                Path creds = net.dir.resolve("aa-test-h01-credentials.json");
                Files.writeString(creds, "{\"entityId\":\"aa-test-h01\",\"entitySecret\":\"synthetic-secret-h01\"}");
                Path cache = net.dir.resolve("cache-h01");
                String tsBlock = "tokenService: {baseUrl: \"http://127.0.0.1:" + ts.getAddress().getPort()
                        + "\", credentialsFile: \"" + creds + "\"}\ncache: {dir: \"" + cache + "\", engine: file}\n";
                hop.yamlEdit = y -> y.replaceFirst("  outboundApiKey: \"\\$\\{K_AA_TEST_H01\\}\"\\n", "") + tsBlock;
                net.start(hop);
                net.start(target);

                byte[] payload = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"ConsentDetail\":{}}").getBytes(StandardCharsets.UTF_8);
                ObjectNode env = Json.object();
                env.put("ver", "2.0.0");
                env.put("timestamp", Json.now());
                env.put("txnid", UUID.randomUUID().toString());
                env.put("correlationId", UUID.randomUUID().toString());
                ObjectNode t = env.putObject("Target");
                t.put("type", "AA");
                t.put("id", target.id);
                env.put("encryptedPayload", Jose.encrypt(Jose.signCompact(payload, fiu.sig, "RS256"), target.encPubKey()));
                byte[] body = Json.bytes(env);
                HttpRequest req = HttpRequest.newBuilder(URI.create(hop.publicUrl() + "/iop/Consent"))
                        .header("client_api_key", fiu.apiKey())
                        .header("x-jws-signature", Jose.signDetached(body, fiu.sig, "RS256"))
                        .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
                HttpResponse<byte[]> r = net.client.send(req, HttpResponse.BodyHandlers.ofByteArray());
                assertEquals(200, r.statusCode(), "the Customer-AA accepted the IopToken: " + new String(r.body()));

                // the access token is requested at start-up for the hop's readiness or on first use;
                // the IopToken on the forwarded call: two requests in all, one of them with use=iop
                hop.gw.gateway.single().tokens.get();
                assertEquals(2, forms.size(), forms.toString());
                assertEquals(1, forms.stream().filter(f -> f.contains("use=iop")).count());
                assertTrue(forms.stream().allMatch(f -> f.contains("id=aa-test-h01") && f.contains("secret=")));
                assertTrue(Files.isRegularFile(cache.resolve("token_aa-test-h01.json")), "token/<id>");
                assertTrue(Files.isRegularFile(cache.resolve("iopToken_aa-test-h01.json")), "iopToken/<id>");
            } finally {
                ts.stop(0);
            }
        }
    }
}
