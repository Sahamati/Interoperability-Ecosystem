package org.sahamati.iopgw;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.sources.ApiKeyVerifier;
import org.sahamati.iopgw.sources.IssuerKeys;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Issuer keys from the issuer's JWKS URL. */
class IssuerKeysTest {

    TestNet net;
    HttpsServer jwks;
    final List<RSAKey> published = new CopyOnWriteArrayList<>();
    final AtomicInteger fetches = new AtomicInteger();
    volatile boolean down;

    @BeforeEach
    void start() throws Exception {
        net = new TestNet();
        jwks = net.httpsServer();
        jwks.createContext("/jwks", ex -> {
            fetches.incrementAndGet();
            if (down) {
                ex.sendResponseHeaders(503, -1);
                ex.close();
                return;
            }
            byte[] b = new JWKSet(published.stream().map(k -> (com.nimbusds.jose.jwk.JWK) k.toPublicJWK()).toList())
                    .toString().getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        jwks.start();
    }

    @AfterEach
    void stop() {
        jwks.stop(0);
        net.close();
    }

    String url() {
        return "https://127.0.0.1:" + jwks.getAddress().getPort() + "/jwks";
    }

    static RSAKey rsa(String kid) throws Exception {
        return new RSAKeyGenerator(2048).keyID(kid).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
    }

    static String token(RSAKey signer, String kid, String azp) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                new JWTClaimsSet.Builder().claim("azp", azp).issuer("https://issuer.test")
                        .expirationTime(new Date(System.currentTimeMillis() + 600_000)).build());
        jwt.sign(new RSASSASigner(signer));
        return jwt.serialize();
    }

    ApiKeyVerifier verifier(IssuerKeys keys) {
        Config.ApiKey conf = new Config.ApiKey();
        conf.mode = "jwt";
        return new ApiKeyVerifier(conf, keys, Map.of());
    }

    @Test
    void onlyRsaSigningKeysWithAKidOfAtLeast2048BitsAreTaken() throws Exception {
        String body = "{\"keys\":["
                + rsa("good").toPublicJWK().toJSONString() + ","
                + new RSAKeyGenerator(2048).keyID("enc").keyUse(KeyUse.ENCRYPTION).generate().toPublicJWK().toJSONString() + ","
                + new ECKeyGenerator(Curve.P_256).keyID("ec").generate().toPublicJWK().toJSONString() + ","
                + new RSAKeyGenerator(2048).keyID("hmac-alg").algorithm(JWSAlgorithm.HS256).generate().toPublicJWK().toJSONString() + ","
                + new RSAKeyGenerator(2048).generate().toPublicJWK().toJSONString() + ","               // no kid
                + new RSAKeyGenerator(1024, true).keyID("small").generate().toPublicJWK().toJSONString() + ","
                + "{\"kty\":\"RSA\",\"kid\":\"bad\",\"n\":\"!!\",\"e\":\"AQAB\"}"
                + "]}";
        List<PubKey> keys = IssuerKeys.parse(body.getBytes(StandardCharsets.UTF_8));
        assertEquals(List.of("good"), keys.stream().map(PubKey::kid).toList());
    }

    @Test
    void rotationIsPickedUpByOneRefetchOnAnUnknownKid() throws Exception {
        RSAKey a = rsa("issuer-a");
        RSAKey b = rsa("issuer-b");
        published.add(a);
        IssuerKeys keys = IssuerKeys.fromJwks(url(), net.gatewayHttp(), Duration.ofSeconds(5));
        assertTrue(keys.fetch());
        ApiKeyVerifier v = verifier(keys);
        assertEquals(Optional.of("aa-test-401"), v.senderId(token(a, "issuer-a", "aa-test-401")));
        assertEquals(1, fetches.get());

        // the issuer rotates to b: the first token naming b triggers one refetch and is accepted
        published.add(b);
        assertEquals(Optional.of("aa-test-401"), v.senderId(token(b, "issuer-b", "aa-test-401")));
        assertEquals(2, fetches.get());

        // a second unknown kid within a minute: no refetch, rejected
        RSAKey c = rsa("issuer-c");
        published.add(c);
        assertTrue(v.senderId(token(c, "issuer-c", "aa-test-401")).isEmpty());
        assertEquals(2, fetches.get());

        // a forged token with a known kid never triggers a refetch
        assertTrue(v.senderId(token(rsa("forger"), "issuer-a", "aa-test-401")).isEmpty());
        assertEquals(2, fetches.get());
    }

    @Test
    void jwksDownAtStartUpRejectsApiKeysUntilLoaded() throws Exception {
        RSAKey a = rsa("issuer-a");
        published.add(a);
        down = true;
        IssuerKeys keys = IssuerKeys.fromJwks(url(), net.gatewayHttp(), Duration.ofSeconds(5));
        assertFalse(keys.fetch());
        assertFalse(keys.loaded());
        assertEquals(30, keys.retrySeconds(3600), "retried every 30 s while none is loaded");
        assertTrue(verifier(keys).senderId(token(a, "issuer-a", "aa-test-401")).isEmpty());

        down = false;
        assertTrue(keys.fetch());
        assertEquals(3600, keys.retrySeconds(3600));
        assertEquals(Optional.of("aa-test-401"), verifier(keys).senderId(token(a, "issuer-a", "aa-test-401")));

        // a failed refresh keeps the current keys
        down = true;
        assertFalse(keys.fetch());
        assertTrue(keys.loaded());
    }
}
