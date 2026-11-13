package org.sahamati.iopgw.mocks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The mock token service, Central Registry and AIG, over HTTPS with the truststore the mock writes. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MockServerTest {

    static final ObjectMapper JSON = new ObjectMapper();
    Path dir;
    MockServer mock;
    HttpClient client;
    String base;

    @BeforeAll
    void start() throws Exception {
        dir = Files.createTempDirectory("iopgw-mocks-test");
        for (String id : List.of("aa-test-001", "aa-test-002", "fiu-test-001", "fip-test-001")) {
            KeyPair kp = Pki.rsa();
            Files.writeString(dir.resolve(id + ".pub.pem"), Pki.pem("PUBLIC KEY", kp.getPublic().getEncoded()));
            Files.writeString(dir.resolve(id + ".creds.json"),
                    "{\"entityId\":\"" + id + "\",\"entitySecret\":\"synthetic-secret-" + id + "\"}");
        }
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        String yaml = """
                listenAddr: "127.0.0.1:%d"
                outDir: "%s"
                tokenService:
                  credentialsFiles: ["%s", "%s", "%s", "%s"]
                entities:
                  - {id: aa-test-001, type: AA, baseUrl: "http://127.0.0.1:1", signingPublicKeys: [{kid: aa1-sig, file: "%s", validFrom: "2026-01-01T00:00:00Z"}], encryptionPublicKeys: [{kid: aa1-enc, file: "%s"}]}
                  - {id: aa-test-002, type: AA, baseUrl: "http://127.0.0.1:2", interop: false, signingPublicKeys: [{kid: aa2-sig, file: "%s"}]}
                  - {id: fiu-test-001, type: FIU, signingPublicKeys: [{kid: fiu-sig, file: "%s"}]}
                  - {id: fip-test-001, type: FIP, signingPublicKeys: [{kid: fip-sig, file: "%s"}]}
                aig:
                  fiu: [{fiu-test-001: [aa-test-001]}]
                  fip: [{fip-test-001: [aa-test-002]}]
                  aa:  [{aa-test-001: [aa-test-002]}]
                """.formatted(port, dir.resolve("out"),
                dir.resolve("aa-test-001.creds.json"), dir.resolve("aa-test-002.creds.json"),
                dir.resolve("fiu-test-001.creds.json"), dir.resolve("fip-test-001.creds.json"),
                dir.resolve("aa-test-001.pub.pem"), dir.resolve("aa-test-001.pub.pem"),
                dir.resolve("aa-test-002.pub.pem"), dir.resolve("fiu-test-001.pub.pem"), dir.resolve("fip-test-001.pub.pem"));
        Files.writeString(dir.resolve("mocks.yaml"), yaml);
        mock = new MockServer(MockConfig.load(dir.resolve("mocks.yaml")));
        mock.start();
        base = "https://127.0.0.1:" + port;

        KeyStore ts = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(dir.resolve("out/truststore.p12"))) {
            ts.load(in, "changeit".toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        client = HttpClient.newBuilder().sslContext(ctx).build(); // hostname verification on: SAN 127.0.0.1
    }

    @AfterAll
    void stop() {
        mock.close();
    }

    private String token(String id) throws Exception {
        HttpResponse<String> r = post("/entity/token/generate", "id=" + id + "&secret=synthetic-secret-" + id);
        assertEquals(200, r.statusCode(), r.body());
        JsonNode b = JSON.readTree(r.body());
        assertTrue(b.get("expiresIn").asInt() > 0);
        return b.get("accessToken").asText();
    }

    private HttpResponse<String> post(String path, String form) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path)).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).GET();
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void tokenIsAJwtWithAzpVerifiableWithThePublishedIssuerKey() throws Exception {
        SignedJWT jwt = SignedJWT.parse(token("aa-test-001"));
        assertEquals("aa-test-001", jwt.getJWTClaimsSet().getStringClaim("azp"));
        String pem = Files.readString(dir.resolve("out/issuer-public.pem"));
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", ""));
        RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        assertTrue(jwt.verify(new RSASSAVerifier(pub)));
    }

    @Test
    void iopTokenIsIssuedAtItsOwnPathAndMarked() throws Exception {
        // a second token, at /entity/iopToken/generate, same form and response shape
        HttpResponse<String> r = post("/entity/iopToken/generate", "id=aa-test-001&secret=synthetic-secret-aa-test-001");
        assertEquals(200, r.statusCode(), r.body());
        String iop = JSON.readTree(r.body()).get("accessToken").asText();
        assertEquals("iop", com.nimbusds.jwt.SignedJWT.parse(iop).getJWTClaimsSet().getStringClaim("tokenUse"));
        assertEquals("access", com.nimbusds.jwt.SignedJWT.parse(token("aa-test-001")).getJWTClaimsSet().getStringClaim("tokenUse"));
        assertEquals("aa-test-001", com.nimbusds.jwt.SignedJWT.parse(iop).getJWTClaimsSet().getStringClaim("azp"));
        assertEquals(401, post("/entity/iopToken/generate", "id=aa-test-001&secret=wrong").statusCode());
    }

    @Test
    void tokenResponseIsShapedLikeTheSahamatiTokenService() throws Exception {
        HttpResponse<String> r = post("/entity/token/generate", "id=aa-test-001&secret=synthetic-secret-aa-test-001");
        assertEquals(200, r.statusCode(), r.body());
        com.fasterxml.jackson.databind.JsonNode b = JSON.readTree(r.body());
        for (String f : new String[]{"ver", "timestamp", "txnId", "accessToken", "expiresIn", "refreshExpiresIn", "tokenType", "notBeforePolicy", "scope"}) {
            assertTrue(b.has(f), f);
        }
        assertEquals("1.0.0", b.get("ver").asText());
        assertEquals("Bearer", b.get("tokenType").asText());
        com.nimbusds.jwt.JWTClaimsSet c = SignedJWT.parse(b.get("accessToken").asText()).getJWTClaimsSet();
        assertEquals("aa-test-001", c.getStringClaim("azp"));
        assertEquals("aa-test-001", c.getStringClaim("clientId"));
        assertEquals("AA", c.getStringClaim("roles"));
        assertEquals(java.util.List.of("account"), c.getAudience());
        assertEquals("Bearer", c.getStringClaim("typ"));
        // the issuer key at the Keycloak path too
        assertEquals(200, get("/auth/realms/sahamati/protocol/openid-connect/certs", null).statusCode());
    }

    @Test
    void tokenRefusals() throws Exception {
        HttpResponse<String> wrong = post("/entity/token/generate", "id=aa-test-001&secret=wrong");
        assertEquals(401, wrong.statusCode());
        assertEquals("TKN_2025", JSON.readTree(wrong.body()).get("errorCode").asText());
        assertEquals("Invalid id/secret", JSON.readTree(wrong.body()).get("errorMsg").asText());
        assertTrue(JSON.readTree(wrong.body()).has("txnId"));
        assertEquals(401, post("/entity/token/generate", "id=aa-test-404&secret=x").statusCode());
        HttpResponse<String> noSecret = post("/entity/token/generate", "id=aa-test-001");
        assertEquals(400, noSecret.statusCode());
        assertEquals("TKN_2014", JSON.readTree(noSecret.body()).get("errorCode").asText());
        assertEquals("secret is missing in the request", JSON.readTree(noSecret.body()).get("errorMsg").asText());
        assertEquals("id is missing in the request", JSON.readTree(post("/entity/token/generate", "secret=x").body()).get("errorMsg").asText());
        assertEquals(401, get("/v2/entityInfo/AA", null).statusCode());
        assertEquals(401, get("/v2/entityInfo/AA", "not-a-token").statusCode());
    }

    @Test
    void centralRegistryListsEntitiesWithJwksAndInteropFlag() throws Exception {
        HttpResponse<String> r = get("/v2/entityInfo/AA", token("fiu-test-001"));
        assertEquals(200, r.statusCode());
        JsonNode arr = JSON.readTree(r.body());
        assertTrue(arr.isArray());
        assertEquals(2, arr.size());
        JsonNode aa1 = arr.get(0).get("entityinfo");
        assertEquals("aa-test-001", aa1.get("id").asText());
        assertEquals("http://127.0.0.1:1", aa1.get("baseurl").asText());
        assertTrue(aa1.get("interop").asBoolean());
        // each item is {key: <JWK>, validFrom?, validTo?}
        assertEquals("aa1-sig", aa1.get("keys").get("signature").get(0).get("key").get("kid").asText());
        assertEquals("sig", aa1.get("keys").get("signature").get(0).get("key").get("use").asText());
        assertEquals("2026-01-01T00:00:00Z", aa1.get("keys").get("signature").get(0).get("validFrom").asText());
        assertEquals(null, aa1.get("keys").get("signature").get(0).get("validTo"));
        assertEquals("RSA-OAEP-256", aa1.get("keys").get("encryption").get(0).get("key").get("alg").asText());
        assertEquals("aa1-sig", aa1.get("certificate").get("kid").asText(), "certificate stays a bare JWK");
        assertTrue(!arr.get(1).get("entityinfo").get("interop").asBoolean());
        assertEquals(1, JSON.readTree(get("/v2/entityInfo/FIP", token("aa-test-001")).body()).size());
    }

    @Test
    void aigAccessFollowsTheSwagger() throws Exception {
        String aa = token("aa-test-001");
        String fiu = token("fiu-test-001");
        JsonNode fiuGraph = JSON.readTree(get("/v1/aig/fiu", aa).body());
        assertEquals("aa-test-001", fiuGraph.get("fiu").get(0).get("connected-AA").get(0).get("id").asText());
        JsonNode fipGraph = JSON.readTree(get("/v1/aig/fip", aa).body());
        assertEquals("aa-test-002", fipGraph.get("fip").get(0).get("inter-AA").get(0).get("id").asText());
        JsonNode aaGraph = JSON.readTree(get("/v1/aig/aa", fiu).body());
        assertEquals("aa-test-002", aaGraph.get("aa").get(0).get("peer-AA").get(0).get("id").asText());
        assertEquals(403, get("/v1/aig/aa", aa).statusCode(), "AA tokens may not read the AA graph");
        assertEquals(403, get("/v1/aig/fiu", fiu).statusCode(), "FIU tokens may not read the FIU graph");

        HttpResponse<String> put = client.send(HttpRequest.newBuilder(URI.create(base + "/v1/aig/update"))
                .header("Authorization", "Bearer " + aa)
                .PUT(HttpRequest.BodyPublishers.ofString("{\"ver\":\"1.0.0\",\"fip\":[\"fip-test-001\"]}")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, put.statusCode());
        JsonNode after = JSON.readTree(get("/v1/aig/fip", aa).body());
        assertEquals(2, after.get("fip").get(0).get("inter-AA").size(), "aa-test-001 published its link to fip-test-001");
        assertTrue(mock.knownIds().containsAll(List.of("aa-test-001", "fiu-test-001")));
        assertEquals(Map.of(), Map.of());
    }
}
