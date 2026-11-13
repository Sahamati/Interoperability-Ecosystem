package org.sahamati.iopgw;

import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.config.ConfigLoader;
import org.sahamati.iopgw.crypto.KeyRing;
import org.sahamati.iopgw.crypto.Pem;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.obs.Logs;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/** A small network of synthetic participants with real gateways and fake cores, for end-to-end tests. */
public final class TestNet implements AutoCloseable {

    static {
        Logs.configure("WARN");
    }

    public static final String GW_TOKEN = "test-gw-api-token-0001";

    /** One request received by a fake core. */
    public record CoreCall(String method, String path, Map<String, String> headers, byte[] body) {
        public String header(String name) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    return e.getValue();
                }
            }
            return null;
        }
    }

    /** A canned core answer. */
    public record CoreAnswer(int status, byte[] body, Map<String, String> headers) {
        public static CoreAnswer json(int status, String body) {
            return new CoreAnswer(status, body.getBytes(StandardCharsets.UTF_8), Map.of());
        }
    }

    /** A fake core: records calls, echoes Correlation-Id, answers with {@link #answer}. */
    public static final class FakeCore implements AutoCloseable {
        public final HttpServer server;
        public final List<CoreCall> calls = new CopyOnWriteArrayList<>();
        public volatile Function<CoreCall, CoreAnswer> answer =
                c -> CoreAnswer.json(200, "{\"ver\":\"2.0.0\",\"txnid\":\"" + java.util.UUID.randomUUID() + "\",\"ok\":true}");
        public volatile boolean echoCorrelation = true;

        FakeCore(int port) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            server.createContext("/", ex -> {
                Map<String, String> h = new LinkedHashMap<>();
                ex.getRequestHeaders().forEach((k, v) -> h.put(k, v.get(0)));
                CoreCall call = new CoreCall(ex.getRequestMethod(), ex.getRequestURI().getPath(), h,
                        ex.getRequestBody().readAllBytes());
                calls.add(call);
                CoreAnswer a = answer.apply(call);
                if (echoCorrelation && call.header("Correlation-Id") != null) {
                    ex.getResponseHeaders().add("Correlation-Id", call.header("Correlation-Id"));
                }
                a.headers().forEach((k, v) -> ex.getResponseHeaders().add(k, v));
                ex.sendResponseHeaders(a.status(), a.body().length == 0 ? -1 : a.body().length);
                if (a.body().length > 0) {
                    ex.getResponseBody().write(a.body());
                }
                ex.close();
            });
            server.start();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    /** One participant: keys, ports, and (once started) its gateway and fake core. */
    public final class Party {
        public final String id;
        public final String mode;
        public final String type;
        public final int publicPort = freePort();
        public final int gwHttpsPort = freePort();
        public final int gwHttpPort = freePort();
        public final int corePort = freePort();
        public final KeyRing.PrivKey sig;
        public final KeyRing.PrivKey enc;
        public final RSAPublicKey sigPub;
        public final RSAPublicKey encPub;
        public FakeCore core;
        public Bootstrap.Running gw;
        /** Extra YAML appended to the generated configuration (top-level keys). */
        public final Map<String, String> overrides = new LinkedHashMap<>();
        public List<String> linked = new ArrayList<>();
        public String aigYaml = "";
        public String hopPreferenceYaml = "";
        /** Last edit applied to the generated YAML (e.g. to switch a source). */
        public java.util.function.UnaryOperator<String> yamlEdit = y -> y;
        /** Entities this party does not know (to provoke InvalidRoute). */
        public final List<String> unknown = new ArrayList<>();
        public final Map<String, Boolean> interop = new HashMap<>();

        Party(String id, String mode, String type) throws Exception {
            this.id = id;
            this.mode = mode;
            this.type = type;
            KeyPair s = rsa();
            KeyPair e = rsa();
            sig = new KeyRing.PrivKey(id + "-sig", (RSAPrivateKey) s.getPrivate(), true, null, null);
            enc = new KeyRing.PrivKey(id + "-enc", (RSAPrivateKey) e.getPrivate(), true, null, null);
            sigPub = (RSAPublicKey) s.getPublic();
            encPub = (RSAPublicKey) e.getPublic();
            write(id + "-sig.pem", pem("PRIVATE KEY", s.getPrivate().getEncoded()));
            write(id + "-enc.pem", pem("PRIVATE KEY", e.getPrivate().getEncoded()));
            write(id + "-sig.pub.pem", pem("PUBLIC KEY", s.getPublic().getEncoded()));
            write(id + "-enc.pub.pem", pem("PUBLIC KEY", e.getPublic().getEncoded()));
        }

        public String envKey() {
            return "K_" + id.toUpperCase().replace('-', '_');
        }

        public String apiKey() {
            return "api-key-of-" + id;
        }

        public PubKey sigPubKey() {
            return new PubKey(id + "-sig", sigPub);
        }

        public String publicUrl() {
            return "http://127.0.0.1:" + publicPort;
        }

        public String gwUrl() {
            return "http://127.0.0.1:" + gwHttpPort;
        }

        String yaml(List<Party> all) {
            StringBuilder y = new StringBuilder();
            y.append("mode: ").append(mode).append('\n');
            y.append("logging: {level: WARN, audit: true, statsIntervalSeconds: 0}\n");
            y.append("listenAddr: \"127.0.0.1:").append(publicPort).append("\"\n");
            y.append("self:\n  id: ").append(id).append('\n');
            y.append("  signingKey: {source: file, kid: ").append(id).append("-sig, file: ").append(dir.resolve(id + "-sig.pem")).append("}\n");
            y.append("  decryptionKeys: {source: file, keys: [{kid: ").append(id).append("-enc, file: ")
                    .append(dir.resolve(id + "-enc.pem")).append("}]}\n");
            y.append("  outboundApiKey: \"${").append(envKey()).append("}\"\n");
            y.append("core: {baseUrl: \"http://127.0.0.1:").append(corePort).append("\", timeoutSeconds: 5}\n");
            y.append("apiKey:\n  mode: static\n  static:\n");
            for (Party p : all) {
                if (p != this) {
                    y.append("    \"${").append(p.envKey()).append("}\": ").append(p.id).append('\n');
                }
            }
            y.append("jws: {algorithm: RS256}\n");
            y.append("cr: {source: config}\n");
            y.append("entities:\n");
            for (Party p : all) {
                if (p == this || unknown.contains(p.id) || (!"AA".equals(mode) && !"AA".equals(p.type))) {
                    continue;
                }
                y.append("  - id: ").append(p.id).append('\n');
                y.append("    type: ").append(p.type).append('\n');
                y.append("    baseUrl: \"").append(p.publicUrl()).append("\"\n");
                y.append("    signingPublicKeys: [{kid: ").append(p.id).append("-sig, file: ").append(dir.resolve(p.id + "-sig.pub.pem")).append("}]\n");
                y.append("    encryptionPublicKeys: [{kid: ").append(p.id).append("-enc, file: ").append(dir.resolve(p.id + "-enc.pub.pem")).append("}]\n");
                if (interop.containsKey(p.id)) {
                    y.append("    interop: ").append(interop.get(p.id)).append('\n');
                }
            }
            if (!overrides.containsKey("aigSource")) {
                y.append("aigSource: config\n");
                y.append(aigYaml.isEmpty() ? defaultAig(all) : aigYaml);
            }
            y.append("gwApi:\n  listenAddr: \"127.0.0.1:").append(gwHttpsPort).append("\"\n");
            y.append("  httpListenAddr: \"127.0.0.1:").append(gwHttpPort).append("\"\n");
            y.append("  tls: {certFile: ").append(dir.resolve("tls.crt")).append(", keyFile: ").append(dir.resolve("tls.key")).append("}\n");
            y.append("  token: \"${GW_TOKEN}\"\n");
            if (!overrides.containsKey("linkedAAs")) {
                y.append("linkedAAs: {source: config, aas: [").append(String.join(", ", linked.isEmpty() ? defaultLinked(all) : linked)).append("]}\n");
            }
            y.append(hopPreferenceYaml);
            y.append("forwarding: {timeoutSeconds: 3").append("AA".equals(mode) && overrides.containsKey("httpRetries")
                    ? ", httpRetries: " + overrides.get("httpRetries") : "").append("}\n");
            overrides.forEach((k, v) -> {
                if (!"httpRetries".equals(k)) {
                    y.append(v).append('\n');
                }
            });
            return yamlEdit.apply(y.toString());
        }

        /**
         * Default graph. AA mode: this AA is a Connected-AA of every FIU and an Inter-AA of every FIP
         * in the net, so it may forward to them as a hop. FIU/FIP mode: a placeholder.
         */
        private String defaultAig(List<Party> all) {
            if (!"AA".equals(mode)) {
                return "aig:\n  aa:\n    - aa-unused: [aa-unused-2]\n";
            }
            StringBuilder fiu = new StringBuilder();
            StringBuilder fip = new StringBuilder();
            for (Party p : all) {
                if ("FIU".equals(p.type) && !unknown.contains(p.id)) {
                    fiu.append("    - ").append(p.id).append(": [").append(id).append("]\n");
                } else if ("FIP".equals(p.type) && !unknown.contains(p.id)) {
                    fip.append("    - ").append(p.id).append(": [").append(id).append("]\n");
                }
            }
            return "aig:\n  fiu:\n" + (fiu.isEmpty() ? "    - fiu-unused: [aa-unused]\n" : fiu)
                    + "  fip:\n" + (fip.isEmpty() ? "    - fip-unused: [aa-unused]\n" : fip);
        }

        /** Default linkedAAs: in AA mode every other known AA (so AA Targets are linked to it as a hop); else none. */
        private List<String> defaultLinked(List<Party> all) {
            List<String> out = new ArrayList<>();
            if ("AA".equals(mode)) {
                for (Party p : all) {
                    if (p != this && "AA".equals(p.type) && !unknown.contains(p.id)) {
                        out.add(p.id);
                    }
                }
            }
            return out.isEmpty() ? List.of("none") : out;
        }
    }

    public final Path dir;
    private final Map<String, Party> parties = new LinkedHashMap<>();
    private final Map<String, String> env = new ConcurrentHashMap<>();

    public TestNet() throws Exception {
        dir = Files.createTempDirectory("iopgw-test");
        writeTls();
        env.put("GW_TOKEN", GW_TOKEN);
    }

    public Party add(String id, String mode, String type) throws Exception {
        Party p = new Party(id, mode, type);
        parties.put(id, p);
        env.put(p.envKey(), p.apiKey());
        return p;
    }

    public Party get(String id) {
        return parties.get(id);
    }

    public Map<String, String> env() {
        return env;
    }

    public Config config(Party p) throws ConfigLoader.ConfigException {
        return new ConfigLoader(env).parse(p.yaml(new ArrayList<>(parties.values())));
    }

    /** Starts every party's fake core and gateway. */
    public void start() throws Exception {
        for (Party p : parties.values()) {
            start(p);
        }
    }

    public void start(Party p) throws Exception {
        if (p.core == null) {
            p.core = new FakeCore(p.corePort);
        }
        p.gw = Bootstrap.start(config(p), gatewayHttp());
    }

    // ---------------- TLS: one test certificate (127.0.0.1) for every HTTPS endpoint ----------------

    private javax.net.ssl.SSLContext ssl;

    /** Server and client TLS context with the test certificate as the only trust anchor. */
    public synchronized javax.net.ssl.SSLContext ssl() throws Exception {
        if (ssl == null) {
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory
                    .getInstance("X.509").generateCertificate(Files.newInputStream(dir.resolve("tls.crt")));
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("tls", Pem.privateKey(dir.resolve("tls.key")), "x".toCharArray(), new java.security.cert.Certificate[]{cert});
            java.security.KeyStore ts = java.security.KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            ts.setCertificateEntry("tls", cert);
            javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "x".toCharArray());
            javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("PKIX");
            tmf.init(ts);
            javax.net.ssl.SSLContext c = javax.net.ssl.SSLContext.getInstance("TLS");
            c.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            ssl = c;
        }
        return ssl;
    }

    /** The gateways' outbound HTTP: as in production, but trusting the test certificate. */
    public org.sahamati.iopgw.http.Http gatewayHttp() throws Exception {
        return new org.sahamati.iopgw.http.Http(HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(5)).sslContext(ssl()).build());
    }

    /** An HTTPS server on 127.0.0.1 with the test certificate. */
    public com.sun.net.httpserver.HttpsServer httpsServer() throws Exception {
        com.sun.net.httpserver.HttpsServer s = com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(ssl()));
        return s;
    }

    /** Calls a party's internal HTTPS listener (key push). */
    public HttpResponse<byte[]> callHttps(Party p, String method, String path, Map<String, String> headers, String body)
            throws Exception {
        HttpClient c = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).sslContext(ssl()).build();
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("https://127.0.0.1:" + p.gwHttpsPort + path)).timeout(Duration.ofSeconds(30));
        headers.forEach(b::header);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return c.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    public void stopGateway(Party p) {
        if (p.gw != null) {
            p.gw.close();
            p.gw = null;
        }
    }

    // ---------------- calling the internal APIs as the core ----------------

    public final HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5)).build();

    public HttpResponse<byte[]> call(Party p, String method, String path, Map<String, String> headers, String body)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(p.gwUrl() + path)).timeout(Duration.ofSeconds(60));
        headers.forEach(b::header);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    public static Map<String, String> coreHeaders(String targetType, String targetId, String correlationId) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Authorization", "Bearer " + GW_TOKEN);
        h.put("Target-Entity", "{\"type\":\"" + targetType + "\",\"id\":\"" + targetId + "\"}");
        h.put("Correlation-Id", correlationId);
        return h;
    }

    // ---------------- helpers ----------------

    static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    void write(String name, String content) throws IOException {
        Files.writeString(dir.resolve(name), content);
    }

    private void writeTls() throws Exception {
        KeyPair kp = rsa();
        X500Name name = new X500Name("CN=localhost");
        Date from = new Date(System.currentTimeMillis() - 60_000);
        Date to = new Date(System.currentTimeMillis() + 86_400_000L);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(System.nanoTime()),
                from, to, name, kp.getPublic());
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
        write("tls.crt", pem("CERTIFICATE", cert.getEncoded()));
        write("tls.key", pem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        // sanity: the key reads back
        Pem.privateKey(dir.resolve("tls.key"));
    }

    @Override
    public void close() {
        for (Party p : parties.values()) {
            if (p.gw != null) {
                p.gw.close();
            }
            if (p.core != null) {
                p.core.close();
            }
        }
    }
}
