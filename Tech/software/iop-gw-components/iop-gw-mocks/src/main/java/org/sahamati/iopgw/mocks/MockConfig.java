package org.sahamati.iopgw.mocks;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Mock configuration (strict YAML). Testing only: everything here is synthetic.
 * Entity secrets are not in this file: they are read from the same credentials
 * files ({@code {"entityId","entitySecret"}}) the gateways mount.
 */
public final class MockConfig {
    /** One HTTPS listener serves the token service, the Central Registry and the AIG. */
    public String listenAddr = "127.0.0.1:9443";
    /** Names the generated TLS certificate is valid for (e.g. the service name the gateways use in compose). */
    public List<String> tlsHosts = new ArrayList<>(List.of("localhost", "127.0.0.1"));
    /**
     * Optional: a TLS certificate and key (PEM) to serve instead of generating one at every start,
     * so that a restart keeps the certificate the gateways trust. tlsHosts is then not used.
     */
    public Tls tls;
    /** Where the mock writes its TLS certificate, truststore, issuer key and JWKS. */
    public String outDir = "./mock-out";
    public TokenService tokenService = new TokenService();
    public List<Entity> entities = new ArrayList<>();
    public Graph aig = new Graph();

    public static final class TokenService {
        public String path = "/entity/token/generate";
        /** Where the IopToken is generated. */
        public String iopPath = "/entity/iopToken/generate";
        public String issuer = "https://mock-token-service.local/realms/sahamati";
        public Integer ttlSeconds = 86400; // as the Sahamati token service
        /** Credentials files of the entities that may get a token. */
        public List<String> credentialsFiles = new ArrayList<>();
        /**
         * Optional: the token-signing private key (PEM, RSA) to use instead of generating one at
         * every start, so that a restart keeps tokens and the published JWKS valid.
         */
        public String signingKeyFile;
        /** The key id of the token-signing key in the JWKS and in token headers. */
        public String signingKeyId = "iop-gw-mocks-ts-1";
    }

    public static final class Tls {
        public String certFile;
        public String keyFile;
    }

    public static final class Entity {
        public String id;
        public String type;
        public String baseUrl;
        public Boolean interop = true;
        public List<KeyFile> signingPublicKeys = new ArrayList<>();
        public List<KeyFile> encryptionPublicKeys = new ArrayList<>();
    }

    public static final class KeyFile {
        public String kid;
        public String file;
        /** Optional validity window served with the key: RFC 3339 timestamps with a time zone. */
        public String validFrom;
        public String validTo;
    }

    /** AIG graph: lists of single-entry maps {@code id: [AA ids]}, as in the gateway's configured graph. */
    public static final class Graph {
        public List<Map<String, List<String>>> fiu = new ArrayList<>();
        public List<Map<String, List<String>>> fip = new ArrayList<>();
        public List<Map<String, List<String>>> aa = new ArrayList<>();
    }

    public static MockConfig load(Path file) throws IOException {
        ObjectMapper yaml = new ObjectMapper(new YAMLFactory())
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        MockConfig c = yaml.readValue(file.toFile(), MockConfig.class);
        if (c == null) {
            throw new IOException("mock configuration is empty");
        }
        if (c.tls != null && (c.tls.certFile == null || c.tls.keyFile == null)) {
            throw new IOException("tls: both certFile and keyFile are required");
        }
        for (Entity e : c.entities) {
            if (e.id == null || !List.of("AA", "FIU", "FIP").contains(e.type)) {
                throw new IOException("entities: every entity needs an id and a type of AA, FIU or FIP");
            }
        }
        return c;
    }
}
