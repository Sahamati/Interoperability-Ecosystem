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
 * FIU mode: only the access token is requested (never {@code use=iop}); it is
 * the role api-key on {@code /iop} calls and the api-key on the Direct API.
 *
 * <pre>
 * fiu-test-801  FIU with tokenService: the access token is the value the hops accept as
 *               fiu-test-801's role api-key
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
    final List<String> tokenForms = new CopyOnWriteArrayList<>();
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
            String form = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            tokenForms.add(form);
            String token = !"/entity/token/generate".equals(path) ? null
                    : form.contains("use=iop") ? "iop-token-never-for-an-fiu"
                    : fiu.apiKey(); // the access token: what the hops accept as fiu-test-801
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
    void theAccessTokenIsTheRoleApiKeyAndTheDirectApiKey() throws Exception {
        // /iop: the hop accepts the call only with the access token as fiu-test-801's role api-key
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
        assertEquals(List.of(fiu.apiKey()), directKeys, "the Direct API carries the access token");

        // one token request at tokenService.path, however many calls were made, never with use=iop
        assertEquals(Map.of("/entity/token/generate", 1), Map.copyOf(tokenCalls.entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()))));
        assertEquals(1, tokenForms.size());
        assertTrue(tokenForms.get(0).contains("id=fiu-test-801") && tokenForms.get(0).contains("secret="), tokenForms.get(0));
        assertTrue(!tokenForms.get(0).contains("use="), "an FIU never asks for an IopToken");

        // persisted as token/<self.id>; no IopToken in FIU mode
        assertTrue(Files.isRegularFile(cacheDir.resolve("token_fiu-test-801.json")), "token/<self.id>");
        assertTrue(!Files.exists(cacheDir.resolve("iopToken_fiu-test-801.json")), "no iopToken in FIU mode");
    }

    @Test
    void iopPathIsNoLongerASetting() throws Exception {
        String yaml = new String(Files.readAllBytes(net.dir.resolve("fiu-test-801-credentials.json")));
        assertTrue(yaml.contains("fiu-test-801"));
        java.lang.reflect.Method m = TestNet.Party.class.getDeclaredMethod("yaml", List.class);
        m.setAccessible(true);
        String base = (String) m.invoke(fiu, List.of(fiu, aa802, aa803, aa804));
        // the IopToken comes from tokenService.path with use=iop: tokenService.iopPath is refused
        String withIopPath = base.replace("credentialsFile:", "iopPath: \"/entity/iopToken/generate\", credentialsFile:");
        ConfigLoader.ConfigException e = assertThrows(ConfigLoader.ConfigException.class, () -> new ConfigLoader(net.env()).parse(withIopPath));
        assertTrue(String.join("\n", e.errors).contains("unknown configuration key 'iopPath'"), String.join("\n", e.errors));
    }
}
