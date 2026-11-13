package org.sahamati.iopgw.mocks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** With a TLS certificate and a token-signing key from files, a restart keeps both. */
class StableKeysTest {

    static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void restartKeepsCertificateAndSigningKey() throws Exception {
        Path dir = Files.createTempDirectory("iopgw-mocks-stable");
        KeyPair tls = Pki.rsa();
        X509Certificate cert = Pki.selfSigned(tls, List.of("127.0.0.1"));
        Files.writeString(dir.resolve("tls.crt"), Pki.pem("CERTIFICATE", cert.getEncoded()));
        Files.writeString(dir.resolve("tls.key"), Pki.pem("PRIVATE KEY", tls.getPrivate().getEncoded()));
        KeyPair signing = Pki.rsa();
        Files.writeString(dir.resolve("signing.pem"), Pki.pem("PRIVATE KEY", signing.getPrivate().getEncoded()));
        Files.writeString(dir.resolve("creds.json"), "{\"entityId\":\"aa-test-001\",\"entitySecret\":\"synthetic-secret\"}");

        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        Files.writeString(dir.resolve("mocks.yaml"), """
                listenAddr: "127.0.0.1:%d"
                outDir: "%s"
                tls: {certFile: "%s", keyFile: "%s"}
                tokenService:
                  signingKeyFile: "%s"
                  signingKeyId: mocks-test-ts
                  credentialsFiles: ["%s"]
                entities:
                  - {id: aa-test-001, type: AA}
                """.formatted(port, dir.resolve("out"), dir.resolve("tls.crt"), dir.resolve("tls.key"),
                dir.resolve("signing.pem"), dir.resolve("creds.json")));

        // A client that trusts only the certificate from the file, with hostname verification on.
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("mocks", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        HttpClient client = HttpClient.newBuilder().sslContext(ctx).build();
        String base = "https://127.0.0.1:" + port;

        String firstToken;
        MockServer first = new MockServer(MockConfig.load(dir.resolve("mocks.yaml")));
        first.start();
        try {
            firstToken = token(client, base);
        } finally {
            first.close();
        }

        MockServer second = new MockServer(MockConfig.load(dir.resolve("mocks.yaml")));
        second.start();
        try {
            // the same certificate (the client above trusts only it), and the same signing key
            String jwks = client.send(HttpRequest.newBuilder(URI.create(base + "/tokenservice/jwks")).build(),
                    HttpResponse.BodyHandlers.ofString()).body();
            RSAKey published = (RSAKey) JWKSet.parse(jwks).getKeyByKeyId("mocks-test-ts");
            SignedJWT before = SignedJWT.parse(firstToken);
            assertEquals("mocks-test-ts", before.getHeader().getKeyID());
            assertTrue(before.verify(new RSASSAVerifier(published.toRSAPublicKey())),
                    "a token from before the restart verifies with the key published after it");
            // the truststore written to outDir holds the certificate from the file
            KeyStore written = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(dir.resolve("out/truststore.p12"))) {
                written.load(in, "changeit".toCharArray());
            }
            assertEquals(cert, written.getCertificate("iop-gw-mocks"));
        } finally {
            second.close();
        }
    }

    private static String token(HttpClient client, String base) throws Exception {
        HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(base + "/entity/token/generate"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("id=aa-test-001&secret=synthetic-secret")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode(), r.body());
        return JSON.readTree(r.body()).get("accessToken").asText();
    }
}
