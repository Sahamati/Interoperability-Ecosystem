package org.sahamati.iopgw;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.sahamati.iopgw.config.ConfigLoader;
import org.sahamati.iopgw.crypto.Jose;

import java.net.InetSocketAddress;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two tokens: the access token for Direct API calls (and the
 * CR and AIG), the IopToken as the role api-key on {@code /iop} calls.
 *
 * <pre>
 * fiu-test-801  FIU with tokenService: access token "access-token-of-fiu-test-801",
 *               IopToken = the value the hops accept as fiu-test-801's role api-key
 * aa-test-802   Connected-AA (hop), linked
 * aa-test-803   Customer-AA (reached via aa-test-802)
 * aa-test-804   linked AA answering the Direct API /User/discover itself (records client_api_key)
 * </pre>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TokensE2ETest {

    TestNet net;
    TestNet.Party fiu;
    TestNet.Party aa802;
    TestNet.Party aa803;
    TestNet.Party aa804;
    HttpServer tokenService;
    HttpServer aa804Server;
    final Map<String, AtomicInteger> tokenCalls = new ConcurrentHashMap<>();
    final List<String> directKeys = new CopyOnWriteArrayList<>();
    Path cacheDir;

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        fiu = net.add("fiu-test-801", "FIU", "FIU");
        aa802 = net.add("aa-test-802", "AA", "AA");
        aa803 = net.add("aa-test-803", "AA", "AA");
        aa804 = net.add("aa-test-804", "AA", "AA");

        tokenService = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        tokenService.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath();
            tokenCalls.computeIfAbsent(path, k -> new AtomicInteger()).incrementAndGet();
            String token = switch (path) {
                case "/entity/token/generate" -> "access-token-of-fiu-test-801";
                case "/entity/iopToken/generate" -> fiu.apiKey(); // what the hops accept as fiu-test-801
                default -> null;
            };
            byte[] b = (token == null ? "{\"errorCode\":\"NotFound\",\"errorMsg\":\"unknown path\"}"
                    : "{\"accessToken\":\"" + token + "\",\"expiresIn\":86400}").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(token == null ? 404 : 200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        tokenService.start();
        Path creds = net.dir.resolve("fiu-test-801-credentials.json");
        Files.writeString(creds, "{\"entityId\":\"fiu-test-801\",\"entitySecret\":\"synthetic-secret-801\"}");
        cacheDir = net.dir.resolve("cache-801");

        fiu.aigYaml = "aig:\n  aa:\n    - aa-test-802: [aa-test-803]\n";
        fiu.linked = List.of("aa-test-802", "aa-test-804");
        fiu.interop.put("aa-test-802", true);
        String tsBlock = "tokenService: {baseUrl: \"http://127.0.0.1:" + tokenService.getAddress().getPort()
                + "\", credentialsFile: \"" + creds + "\"}\ncache: {dir: \"" + cacheDir + "\", engine: file}\n";
        fiu.yamlEdit = y -> y.replaceFirst("  outboundApiKey: \"\\$\\{K_FIU_TEST_801\\}\"\\n", "") + tsBlock;
        aa803.linked = List.of("aa-test-802");
        for (TestNet.Party p : List.of(aa802, aa803, fiu)) {
            net.start(p);
        }

        // aa-test-804 answers the Direct API /User/discover itself, signed, and records client_api_key.
        aa804Server = HttpServer.create(new InetSocketAddress("127.0.0.1", aa804.publicPort), 0);
        aa804Server.createContext("/User/discover", ex -> {
            directKeys.add(ex.getRequestHeaders().getFirst("client_api_key"));
            ex.getRequestBody().readAllBytes();
            byte[] b = "{\"ver\":\"2.0.0\",\"txnid\":\"t\",\"status\":\"User Not Found\",\"customerDiscoveryResponse\":[]}"
                    .getBytes(StandardCharsets.UTF_8);
            try {
                ex.getResponseHeaders().add("x-jws-signature", Jose.signDetached(b, aa804.sig, "RS256"));
            } catch (Exception e) {
                throw new java.io.IOException(e);
            }
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        aa804Server.start();
    }

    @AfterAll
    void stop() {
        net.close();
        tokenService.stop(0);
        aa804Server.stop(0);
    }

    static String payload() {
        return "{\"ver\":\"2.0.0\",\"timestamp\":\"2026-11-10T10:00:00.000Z\",\"txnid\":\"" + UUID.randomUUID()
                + "\",\"ConsentDetail\":{\"customer\":{\"id\":\"customer-test-801@aa-test-803\"}}}";
    }

    @Test
    void iopCallsCarryTheIopTokenAndDirectCallsTheAccessToken() throws Exception {
        // /iop: the hop accepts the call only with the IopToken as fiu-test-801's role api-key
        for (int i = 0; i < 3; i++) {
            HttpResponse<byte[]> r = net.call(fiu, "POST", "/fiu-dgw/Consent",
                    TestNet.coreHeaders("AA", "aa-test-803", UUID.randomUUID().toString()), payload());
            assertEquals(200, r.statusCode(), new String(r.body()));
        }

        // Direct API (the broadcast's /User/discover to a linked AA): the access token
        Map<String, String> h = new java.util.LinkedHashMap<>();
        h.put("Authorization", "Bearer " + TestNet.GW_TOKEN);
        h.put("Correlation-Id", UUID.randomUUID().toString());
        net.call(fiu, "POST", "/fiu-dgw/broadcast/User/discover", h,
                "{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\",\"customer\":{\"mobileHash\":\"synthetic\"}}");
        assertEquals(List.of("access-token-of-fiu-test-801"), directKeys, "the Direct API carries the access token, not the IopToken");

        // each token was asked for once, at its own path, however many calls were made
        assertEquals(1, tokenCalls.get("/entity/iopToken/generate").get());
        assertEquals(1, tokenCalls.get("/entity/token/generate").get());

        // both persisted, under different names
        assertTrue(Files.isRegularFile(cacheDir.resolve("token_fiu-test-801.json")), "token/<self.id>");
        assertTrue(Files.isRegularFile(cacheDir.resolve("iopToken_fiu-test-801.json")), "iopToken/<self.id>");
    }

    @Test
    void aRelativeIopPathIsRefused() throws Exception {
        String yaml = new String(Files.readAllBytes(net.dir.resolve("fiu-test-801-credentials.json")));
        assertTrue(yaml.contains("fiu-test-801"));
        java.lang.reflect.Method m = TestNet.Party.class.getDeclaredMethod("yaml", List.class);
        m.setAccessible(true);
        String base = (String) m.invoke(fiu, List.of(fiu, aa802, aa803, aa804));
        String relative = base.replace("credentialsFile:", "iopPath: \"entity/iopToken/generate\", credentialsFile:");
        ConfigLoader.ConfigException e = assertThrows(ConfigLoader.ConfigException.class, () -> new ConfigLoader(net.env()).parse(relative));
        assertTrue(String.join("\n", e.errors).contains("tokenService.iopPath must start with /"), String.join("\n", e.errors));
    }
}
