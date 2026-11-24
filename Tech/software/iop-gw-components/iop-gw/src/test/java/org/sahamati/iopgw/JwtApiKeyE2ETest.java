package org.sahamati.iopgw;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.http.Json;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Role api-keys checked as JWTs ({@code apiKey.mode: jwt}, the production setting) with tokens from
 * a test issuer: the AA role api-keys must be IopTokens ({@code token_use: iop});
 * a regular token there gets {@code 400 InvalidSecurity}. {@code client_api_key} and
 * {@code fip_api_key} carry regular tokens. (With {@code apiKey.mode: static} the static test
 * api-keys are accepted on these headers: every other end-to-end test relies on it.)
 *
 * <pre>
 * aa-test-g01   AA gateway, apiKey.mode jwt (receiver)
 * aa-test-g02   AA sender (Connected-AA, Customer-AA, Origin-AA, Inter-AA as needed)
 * fiu-test-g03  FIU (Initiator, and sender of client_api_key)
 * fip-test-g04  FIP (Initiator)
 * </pre>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JwtApiKeyE2ETest {

    TestNet net;
    TestNet.Party aa;
    TestNet.Party aa2;
    TestNet.Party fiu;
    TestNet.Party fip;
    KeyPair issuer;

    @BeforeAll
    void start() throws Exception {
        net = new TestNet();
        aa = net.add("aa-test-g01", "AA", "AA");
        aa2 = net.add("aa-test-g02", "AA", "AA");
        fiu = net.add("fiu-test-g03", "FIU", "FIU");
        fip = net.add("fip-test-g04", "FIP", "FIP");
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        issuer = g.generateKeyPair();
        net.write("issuer.pub.pem", TestNet.pem("PUBLIC KEY", issuer.getPublic().getEncoded()));
        String jwt = "apiKey:\n  mode: jwt\n  issuerPublicKeys: [\"" + net.dir.resolve("issuer.pub.pem") + "\"]\n";
        aa.yamlEdit = y -> y.replaceFirst("apiKey:\\n  mode: static\\n  static:\\n(    [^\\n]*\\n)*", java.util.regex.Matcher.quoteReplacement(jwt));
        net.start(aa);
    }

    @AfterAll
    void stop() {
        net.close();
    }

    /** A token as the token service issues it: RS256, azp = the entity, exp; token_use only on an IopToken. */
    private String token(TestNet.Party who, boolean iop) throws Exception {
        JWTClaimsSet.Builder c = new JWTClaimsSet.Builder().claim("azp", who.id)
                .expirationTime(Date.from(Instant.now().plusSeconds(300)));
        if (iop) {
            c.claim("token_use", "iop");
        }
        SignedJWT t = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), c.build());
        t.sign(new RSASSASigner(issuer.getPrivate()));
        return t.serialize();
    }

    /** An envelope: terminating (Initiator) with a payload for aa-test-g01, or forwarding (Target). */
    private byte[] envelope(String partyField, String type, String id, TestNet.Party innerSigner) throws Exception {
        ObjectNode env = Json.object();
        env.put("ver", "2.0.0");
        env.put("timestamp", Json.now());
        env.put("txnid", UUID.randomUUID().toString());
        env.put("correlationId", UUID.randomUUID().toString());
        ObjectNode p = env.putObject(partyField);
        p.put("type", type);
        p.put("id", id);
        byte[] payload = ("{\"ver\":\"2.0.0\",\"txnid\":\"" + UUID.randomUUID() + "\"}").getBytes(StandardCharsets.UTF_8);
        env.put("encryptedPayload", Jose.encrypt(Jose.signCompact(payload, innerSigner.sig, "RS256"), aa.encPubKey()));
        return Json.bytes(env);
    }

    private HttpResponse<byte[]> send(String path, String keyHeader, String apiKey, TestNet.Party sender, byte[] body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(aa.publicUrl() + path))
                .header(keyHeader, apiKey)
                .header("x-jws-signature", Jose.signDetached(body, sender.sig, "RS256"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
        return net.client.send(req, HttpResponse.BodyHandlers.ofByteArray());
    }

    private static void notAnIopToken(HttpResponse<byte[]> r) {
        assertEquals(400, r.statusCode(), new String(r.body()));
        assertEquals("InvalidSecurity", Json.text(Json.parseObject(r.body()), "errorCode"));
        assertEquals("api-key is not an IopToken", Json.text(Json.parseObject(r.body()), "errorMsg"));
    }

    private static void passedTheIopTokenCheck(HttpResponse<byte[]> r) {
        assertNotEquals("api-key is not an IopToken", Json.text(Json.parseObject(r.body()), "errorMsg"), new String(r.body()));
        assertNotEquals("invalid api-key", Json.text(Json.parseObject(r.body()), "errorMsg"), new String(r.body()));
    }

    @Test
    void connectedAaKeyMustBeAnIopToken() throws Exception {
        notAnIopToken(send("/iop/Consent", "x-conn_aa_api_key", token(aa2, false), aa2, envelope("Initiator", "FIU", fiu.id, fiu)));
        HttpResponse<byte[]> ok = send("/iop/Consent", "x-conn_aa_api_key", token(aa2, true), aa2, envelope("Initiator", "FIU", fiu.id, fiu));
        assertEquals(200, ok.statusCode(), new String(ok.body()));
    }

    @Test
    void interAaKeyMustBeAnIopToken() throws Exception {
        notAnIopToken(send("/iop/Account/link/Notification", "x-inter_aa_api_key", token(aa2, false), aa2,
                envelope("Initiator", "FIP", fip.id, fip)));
        HttpResponse<byte[]> ok = send("/iop/Account/link/Notification", "x-inter_aa_api_key", token(aa2, true), aa2,
                envelope("Initiator", "FIP", fip.id, fip));
        assertEquals(200, ok.statusCode(), new String(ok.body()));
    }

    @Test
    void customerAndOriginAaKeysMustBeIopTokens() throws Exception {
        notAnIopToken(send("/iop/FI/Notification", "x-cust_aa_api_key", token(aa2, false), aa2, envelope("Target", "FIU", fiu.id, aa2)));
        passedTheIopTokenCheck(send("/iop/FI/Notification", "x-cust_aa_api_key", token(aa2, true), aa2, envelope("Target", "FIU", fiu.id, aa2)));
        notAnIopToken(send("/iop/Consent", "x-orig_aa_api_key", token(aa2, false), aa2, envelope("Target", "FIP", fip.id, aa2)));
        passedTheIopTokenCheck(send("/iop/Consent", "x-orig_aa_api_key", token(aa2, true), aa2, envelope("Target", "FIP", fip.id, aa2)));
    }

    @Test
    void clientApiKeyCarriesARegularToken() throws Exception {
        passedTheIopTokenCheck(send("/iop/Consent", "client_api_key", token(fiu, false), fiu, envelope("Target", "AA", aa2.id, fiu)));
    }

    @Test
    void anExpiredOrForeignTokenIsRefused() throws Exception {
        SignedJWT foreign = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), new JWTClaimsSet.Builder()
                .claim("azp", aa2.id).claim("token_use", "iop").expirationTime(Date.from(Instant.now().plusSeconds(300))).build());
        foreign.sign(new RSASSASigner(aa2.sig.key()));
        HttpResponse<byte[]> r = send("/iop/Consent", "x-conn_aa_api_key", foreign.serialize(), aa2, envelope("Initiator", "FIU", fiu.id, fiu));
        assertEquals(400, r.statusCode());
        assertEquals("invalid api-key", Json.text(Json.parseObject(r.body()), "errorMsg"));
    }
}
