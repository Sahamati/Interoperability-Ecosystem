package org.sahamati.iopgw.mocks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Local mock of the three Sahamati services the IOP Gateway uses in production (token service,
 * Central Registry, AIG), so the gateway can run with its API sources and no connections.
 * <b>Testing only.</b>
 *
 * <ul>
 *   <li>Token service, shaped like the Sahamati token service: {@code POST /entity/token/generate}
 *       (the access token) and {@code POST /entity/iopToken/generate} (the IopToken; not yet in the
 *       Sahamati token service), form {@code id}, {@code secret} → {@code {ver, timestamp, txnId,
 *       accessToken, expiresIn, refreshExpiresIn, tokenType, notBeforePolicy, scope}}. The token is
 *       an RS256 JWT with {@code azp}, {@code clientId} and {@code client_id} = the entity id,
 *       {@code roles} = its type, {@code aud} "account" and {@code typ} "Bearer", plus
 *       {@code tokenUse} = {@code access} or {@code iop} (this mock's own marker: how a receiver
 *       tells an IopToken apart is not yet specified). Errors: {@code 400 TKN_2014} "&lt;param&gt; is
 *       missing in the request", {@code 401 TKN_2025} "Invalid id/secret", as {@code {ver,
 *       timestamp, txnId, errorCode, errorMsg}}. The issuer key is published at
 *       {@code GET /tokenservice/jwks} and at the Keycloak path
 *       {@code /auth/realms/sahamati/protocol/openid-connect/certs}.</li>
 *   <li>Central Registry: {@code GET /v2/entityInfo/{AA|FIP|FIU}} → a top-level array of
 *       {@code {ver, timestamp, txnid, entityinfo}} with the {@code interop} flag; each item of
 *       {@code keys.signature} / {@code keys.encryption} is {@code {key: <JWK>, validFrom, validTo}}
 *, {@code certificate} a bare JWK.</li>
 *   <li>AIG: {@code GET /v1/aig/fiu}, {@code /v1/aig/fip} (AA token),
 *       {@code GET /v1/aig/aa} (FIU or FIP token), {@code PUT /v1/aig/update} (AA token).</li>
 * </ul>
 *
 * At start-up it writes to {@code outDir}: {@code tls.crt} and {@code truststore.p12} (password
 * {@code changeit}) for the gateway's JVM, {@code issuer-public.pem} for the gateway's
 * {@code apiKey.issuerPublicKeys}, and {@code jwks.json}.
 */
public final class MockServer implements AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .withZone(ZoneOffset.UTC);

    private final MockConfig cfg;
    private final HttpsServer server;
    private final RSAKey issuerKey;
    private final Map<String, MockConfig.Entity> entities = new LinkedHashMap<>();
    private final Map<String, String> credentialsFileById = new LinkedHashMap<>();
    // AIG graph: kind (fiu, fip, aa) -> id -> AA ids
    private final Map<String, Map<String, Set<String>>> graph = new ConcurrentHashMap<>();

    public MockServer(MockConfig cfg) throws Exception {
        this.cfg = cfg;
        for (MockConfig.Entity e : cfg.entities) {
            entities.put(e.id, e);
        }
        for (String f : cfg.tokenService.credentialsFiles) {
            JsonNode n = JSON.readTree(Files.readAllBytes(Path.of(f)));
            String id = n.path("entityId").asText(null);
            if (id == null) {
                throw new IOException("credentials file without entityId: " + f);
            }
            credentialsFileById.put(id, f);
        }
        graph.put("fiu", load(cfg.aig.fiu));
        graph.put("fip", load(cfg.aig.fip));
        graph.put("aa", load(cfg.aig.aa));

        // Keys from files when configured (they survive a restart), else generated for this run.
        KeyPair issuer = cfg.tokenService.signingKeyFile != null
                ? Pki.readRsaKey(Path.of(cfg.tokenService.signingKeyFile)) : Pki.rsa();
        issuerKey = new RSAKey.Builder((RSAPublicKey) issuer.getPublic()).privateKey((RSAPrivateKey) issuer.getPrivate())
                .keyID(cfg.tokenService.signingKeyId).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();

        KeyPair tlsKey;
        X509Certificate cert;
        if (cfg.tls != null) {
            cert = Pki.readCertificate(Path.of(cfg.tls.certFile));
            tlsKey = new KeyPair(cert.getPublicKey(), Pki.readRsaKey(Path.of(cfg.tls.keyFile)).getPrivate());
        } else {
            tlsKey = Pki.rsa();
            cert = Pki.selfSigned(tlsKey, cfg.tlsHosts);
        }
        Path out = Path.of(cfg.outDir);
        Files.createDirectories(out);
        Files.writeString(out.resolve("tls.crt"), Pki.pem("CERTIFICATE", cert.getEncoded()));
        Pki.writeTruststore(cert, out.resolve("truststore.p12"));
        Files.writeString(out.resolve("issuer-public.pem"), Pki.pem("PUBLIC KEY", issuer.getPublic().getEncoded()));
        Files.writeString(out.resolve("jwks.json"), new JWKSet(issuerKey.toPublicJWK()).toString());

        int i = cfg.listenAddr.lastIndexOf(':');
        String host = cfg.listenAddr.substring(0, i);
        int port = Integer.parseInt(cfg.listenAddr.substring(i + 1));
        server = HttpsServer.create(new InetSocketAddress(host.isEmpty() ? "0.0.0.0" : host, port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(Pki.serverContext(tlsKey, cert)));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/", this::handle);
    }

    private static Map<String, Set<String>> load(List<Map<String, List<String>>> entries) {
        Map<String, Set<String>> m = new ConcurrentHashMap<>();
        if (entries != null) {
            for (Map<String, List<String>> e : entries) {
                e.forEach((k, v) -> m.computeIfAbsent(k, x -> ConcurrentHashMap.newKeySet()).addAll(v));
            }
        }
        return m;
    }

    public void start() {
        server.start();
        log("INFO", "iop-gw-mocks started (testing only)", Map.of("listenAddr", cfg.listenAddr,
                "outDir", cfg.outDir, "entities", entities.size()));
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    // ------------------------------------------------------------------------------------

    private record Reply(int status, byte[] body) {
        static Reply json(int status, JsonNode n) {
            try {
                return new Reply(status, JSON.writeValueAsBytes(n));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static final Pattern ENTITY_INFO = Pattern.compile("^/v2/entityInfo/(AA|FIP|FIU)$");

    private void handle(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        byte[] body = ex.getRequestBody().readNBytes(1 << 20);
        String caller = null;
        Reply r;
        try {
            if ("/healthz".equals(path)) {
                r = new Reply(200, "ok".getBytes(StandardCharsets.UTF_8));
            } else if (cfg.tokenService.path.equals(path)) {
                r = "POST".equals(method) ? token(body, "access") : error(405, "InvalidRequest", "method not allowed");
            } else if (cfg.tokenService.iopPath.equals(path)) {
                r = "POST".equals(method) ? token(body, "iop") : error(405, "InvalidRequest", "method not allowed");
            } else if ("/tokenservice/jwks".equals(path) || "/.well-known/jwks.json".equals(path)
                    || "/auth/realms/sahamati/protocol/openid-connect/certs".equals(path)) {
                r = new Reply(200, new JWKSet(issuerKey.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8));
            } else {
                Optional<MockConfig.Entity> who = bearer(ex.getRequestHeaders().getFirst("Authorization"));
                caller = who.map(e -> e.id).orElse(null);
                Matcher m = ENTITY_INFO.matcher(path);
                if (m.matches() || path.startsWith("/v1/aig/")) {
                    if (who.isEmpty()) {
                        r = error(401, "Unauthorized", "Invalid or expired token");
                    } else if (m.matches()) {
                        r = "GET".equals(method) ? entityInfo(m.group(1)) : error(405, "InvalidRequest", "method not allowed");
                    } else {
                        r = aig(method, path, who.get(), body);
                    }
                } else {
                    r = error(404, "InvalidRequest", "unknown path");
                }
            }
        } catch (Exception e) {
            r = error(500, "InternalError", "mock error: " + e.getClass().getSimpleName());
        }
        if (r.body.length > 0 && r.body[0] == '{' || r.body.length > 0 && r.body[0] == '[') {
            ex.getResponseHeaders().set("Content-Type", "application/json");
        }
        ex.sendResponseHeaders(r.status, r.body.length == 0 ? -1 : r.body.length);
        if (r.body.length > 0) {
            ex.getResponseBody().write(r.body);
        }
        ex.close();
        if (!"/healthz".equals(path)) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("method", method);
            f.put("path", path);
            f.put("status", r.status);
            if (caller != null) {
                f.put("caller", caller);
            }
            log("INFO", "request", f);
        }
    }

    // ---------------- token service ----------------

    private Reply token(byte[] body, String use) throws Exception {
        Map<String, String> form = new LinkedHashMap<>();
        for (String pair : new String(body, StandardCharsets.UTF_8).split("&")) {
            int i = pair.indexOf('=');
            if (i > 0) {
                form.put(URLDecoder.decode(pair.substring(0, i), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8));
            }
        }
        String id = form.get("id");
        String secret = form.get("secret");
        if (id == null) {
            return tsError(400, "TKN_2014", "id is missing in the request");
        }
        if (secret == null) {
            return tsError(400, "TKN_2014", "secret is missing in the request");
        }
        String file = credentialsFileById.get(id);
        if (file == null) {
            return tsError(401, "TKN_2025", "Invalid id/secret");
        }
        // Read afresh, so a rotated secret is picked up (as the gateway does).
        JsonNode creds = JSON.readTree(Files.readAllBytes(Path.of(file)));
        String expected = creds.path("entitySecret").asText("");
        if (expected.isEmpty() || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), secret.getBytes(StandardCharsets.UTF_8))) {
            return tsError(401, "TKN_2025", "Invalid id/secret");
        }
        Instant now = Instant.now();
        int ttl = cfg.tokenService.ttlSeconds;
        MockConfig.Entity e = entities.get(id);
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(cfg.tokenService.issuer).audience("account")
                .subject(UUID.nameUUIDFromBytes(id.getBytes(StandardCharsets.UTF_8)).toString())
                .claim("typ", "Bearer").claim("azp", id).claim("clientId", id).claim("client_id", id)
                .claim("scope", SCOPE).claim("tokenUse", use)
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(ttl))).jwtID(UUID.randomUUID().toString());
        if (e != null) {
            claims.claim("roles", e.type);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(com.nimbusds.jose.JOSEObjectType.JWT)
                .keyID(cfg.tokenService.signingKeyId).build(), claims.build());
        jwt.sign(new RSASSASigner(issuerKey));
        ObjectNode o = JSON.createObjectNode();
        o.put("ver", "1.0.0");
        o.put("timestamp", now.toString());
        o.put("txnId", UUID.randomUUID().toString());
        o.put("accessToken", jwt.serialize());
        o.put("expiresIn", ttl);
        o.put("refreshExpiresIn", 0);
        o.put("tokenType", "Bearer");
        o.put("notBeforePolicy", 0);
        o.put("scope", SCOPE);
        return Reply.json(200, o);
    }

    private static final String SCOPE = "email microprofile-jwt profile address phone offline_access";

    /** An error as the Sahamati token service answers it. */
    private static Reply tsError(int status, String code, String msg) {
        ObjectNode o = JSON.createObjectNode();
        o.put("ver", "1.0.0");
        o.put("timestamp", Instant.now().toString());
        o.put("txnId", UUID.randomUUID().toString());
        o.put("errorCode", code);
        o.put("errorMsg", msg);
        return Reply.json(status, o);
    }

    /** The entity a bearer token from this mock names, if the token is valid. */
    private Optional<MockConfig.Entity> bearer(String auth) {
        if (auth == null || !auth.startsWith("Bearer ")) {
            return Optional.empty();
        }
        try {
            SignedJWT jwt = SignedJWT.parse(auth.substring(7));
            if (!jwt.verify(new RSASSAVerifier(issuerKey.toRSAPublicKey()))) {
                return Optional.empty();
            }
            JWTClaimsSet c = jwt.getJWTClaimsSet();
            if (!cfg.tokenService.issuer.equals(c.getIssuer()) || c.getExpirationTime() == null
                    || c.getExpirationTime().before(new Date())) {
                return Optional.empty();
            }
            return Optional.ofNullable(entities.get(String.valueOf(c.getClaim("azp"))));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    // ---------------- Central Registry ----------------

    private Reply entityInfo(String type) throws Exception {
        ArrayNode arr = JSON.createArrayNode();
        for (MockConfig.Entity e : entities.values()) {
            if (!type.equals(e.type)) {
                continue;
            }
            ObjectNode el = base();
            ObjectNode info = el.putObject("entityinfo");
            info.put("id", e.id);
            info.put("name", e.id);
            if (e.baseUrl != null) {
                info.put("baseurl", e.baseUrl);
            }
            info.put("interop", e.interop == null || e.interop);
            ArrayNode sig = JSON.createArrayNode();
            for (MockConfig.KeyFile k : e.signingPublicKeys) {
                sig.add(windowed(k, jwk(k, KeyUse.SIGNATURE, JWSAlgorithm.RS256.getName())));
            }
            ArrayNode enc = JSON.createArrayNode();
            for (MockConfig.KeyFile k : e.encryptionPublicKeys) {
                enc.add(windowed(k, jwk(k, KeyUse.ENCRYPTION, "RSA-OAEP-256")));
            }
            if (!sig.isEmpty()) {
                info.set("certificate", sig.get(0).get("key")); // a bare JWK, no window
            }
            ObjectNode keys = info.putObject("keys");
            keys.set("signature", sig);
            keys.set("encryption", enc);
            arr.add(el);
        }
        return Reply.json(200, arr);
    }

    /** A CR key item: {@code {key, validFrom?, validTo?}}. */
    private static ObjectNode windowed(MockConfig.KeyFile k, JsonNode jwk) {
        ObjectNode item = JSON.createObjectNode();
        item.set("key", jwk);
        if (k.validFrom != null) {
            item.put("validFrom", k.validFrom);
        }
        if (k.validTo != null) {
            item.put("validTo", k.validTo);
        }
        return item;
    }

    private static JsonNode jwk(MockConfig.KeyFile k, KeyUse use, String alg) throws Exception {
        RSAPublicKey pub = publicKey(Path.of(k.file));
        RSAKey key = new RSAKey.Builder(pub).keyID(k.kid).keyUse(use)
                .algorithm(new com.nimbusds.jose.Algorithm(alg)).build();
        return JSON.readTree(key.toPublicJWK().toJSONString());
    }

    private static RSAPublicKey publicKey(Path file) throws Exception {
        String pem = Files.readString(file);
        if (pem.contains("BEGIN CERTIFICATE")) {
            byte[] der = Base64.getMimeDecoder().decode(between(pem, "CERTIFICATE"));
            X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            return (RSAPublicKey) c.getPublicKey();
        }
        byte[] der = Base64.getMimeDecoder().decode(between(pem, "PUBLIC KEY"));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    private static String between(String pem, String type) throws IOException {
        int a = pem.indexOf("-----BEGIN " + type + "-----");
        int b = pem.indexOf("-----END " + type + "-----");
        if (a < 0 || b < 0) {
            throw new IOException("no " + type + " in PEM");
        }
        return pem.substring(a + type.length() + 16, b);
    }

    // ---------------- AIG ----------------

    private Reply aig(String method, String path, MockConfig.Entity who, byte[] body) throws Exception {
        switch (path) {
            case "/v1/aig/fiu", "/v1/aig/fip" -> {
                if (!"GET".equals(method)) {
                    return error(405, "InvalidRequest", "method not allowed");
                }
                if (!"AA".equals(who.type)) {
                    return error(403, "Forbidden", "Cannot access resource");
                }
                String kind = path.substring("/v1/aig/".length());
                return Reply.json(200, graphResponse(kind, "fiu".equals(kind) ? "connected-AA" : "inter-AA"));
            }
            case "/v1/aig/aa" -> {
                if (!"GET".equals(method)) {
                    return error(405, "InvalidRequest", "method not allowed");
                }
                if (!"FIU".equals(who.type) && !"FIP".equals(who.type)) {
                    return error(403, "Forbidden", "Cannot access resource");
                }
                return Reply.json(200, graphResponse("aa", "peer-AA"));
            }
            case "/v1/aig/update" -> {
                if (!"PUT".equals(method)) {
                    return error(405, "InvalidRequest", "method not allowed");
                }
                if (!"AA".equals(who.type)) {
                    return error(403, "Forbidden", "Cannot access resource");
                }
                JsonNode req = JSON.readTree(body);
                if (req == null || !req.isObject()) {
                    return error(400, "InvalidRequest", "body must be a JSON object");
                }
                update("fip", who.id, req.get("fip"));
                update("fiu", who.id, req.get("fiu"));
                updatePeers(who.id, req.get("aa"));
                ObjectNode o = base();
                o.put("responseText", "Uploaded");
                return Reply.json(200, o);
            }
            default -> {
                return error(404, "InvalidRequest", "unknown path");
            }
        }
    }

    /** The caller AA's published links replace its previous ones. */
    private void update(String kind, String aa, JsonNode ids) {
        if (ids == null || !ids.isArray()) {
            return;
        }
        Map<String, Set<String>> g = graph.get(kind);
        g.values().forEach(s -> s.remove(aa));
        ids.forEach(n -> g.computeIfAbsent(n.asText(), x -> ConcurrentHashMap.newKeySet()).add(aa));
    }

    private void updatePeers(String aa, JsonNode ids) {
        if (ids == null || !ids.isArray()) {
            return;
        }
        Set<String> peers = ConcurrentHashMap.newKeySet();
        ids.forEach(n -> peers.add(n.asText()));
        graph.get("aa").put(aa, peers);
    }

    private ObjectNode graphResponse(String kind, String linkKey) {
        ObjectNode o = base();
        ArrayNode list = o.putArray(kind);
        graph.get(kind).forEach((id, aas) -> {
            ObjectNode node = list.addObject();
            node.put("id", id);
            ArrayNode links = node.putArray(linkKey);
            for (String aa : new LinkedHashSet<>(aas)) {
                ObjectNode l = links.addObject();
                l.put("id", aa);
                l.put("verified", true);
            }
        });
        return o;
    }

    // ---------------- helpers ----------------

    private static ObjectNode base() {
        ObjectNode o = JSON.createObjectNode();
        o.put("ver", "1.0.0");
        o.put("timestamp", TS.format(Instant.now().truncatedTo(ChronoUnit.MILLIS)));
        o.put("txnid", UUID.randomUUID().toString());
        return o;
    }

    private static Reply error(int status, String code, String msg) {
        ObjectNode o = base();
        o.put("errorCode", code);
        o.put("errorMsg", msg);
        return Reply.json(status, o);
    }

    private static void log(String level, String msg, Map<String, Object> fields) {
        ObjectNode o = JSON.createObjectNode();
        o.put("time", TS.format(Instant.now().truncatedTo(ChronoUnit.MILLIS)));
        o.put("level", level);
        o.put("msg", msg);
        fields.forEach((k, v) -> o.set(k, JSON.valueToTree(v)));
        System.out.println(o);
    }

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "mocks.yaml");
        MockConfig cfg;
        try {
            cfg = MockConfig.load(file);
        } catch (Exception e) {
            log("CRITICAL", "invalid mock configuration", Map.of("error", String.valueOf(e.getMessage())));
            System.exit(2);
            return;
        }
        MockServer s = new MockServer(cfg);
        s.start();
        Runtime.getRuntime().addShutdownHook(new Thread(s::close));
        Thread.currentThread().join();
    }

    /** For tests: the ids the token service knows. */
    List<String> knownIds() {
        return new ArrayList<>(credentialsFileById.keySet());
    }
}
