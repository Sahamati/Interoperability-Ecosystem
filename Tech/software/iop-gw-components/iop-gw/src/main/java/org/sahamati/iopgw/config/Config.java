package org.sahamati.iopgw.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The gateway configuration. Field names are the YAML keys. Unknown keys are rejected by
 * {@link ConfigLoader}. Secret values are {@code ${ENV}} references, resolved by the loader into
 * the {@code resolved*} fields, never logged.
 */
public final class Config {
    public String mode = "AA";
    /**
     * {@code on} or {@code off} ({@code true} / {@code false} accepted too); default {@code off}.
     * Kept as the scalar written in the file, so that YAML 1.1 spellings such as {@code yes} are refused.
     */
    @com.fasterxml.jackson.databind.annotation.JsonDeserialize(using = RawScalar.class)
    public String multiTenant;
    /** Multi-tenant mode: the folder holding one entity file per entity. */
    public String entityConfigPath;
    /** Multi-tenant mode: how often the entity folder is read again; default 60. */
    public Integer entityRescanSeconds;
    public String listenAddr;
    public Tls tls;
    public Self self = new Self();
    public Core core = new Core();
    public ApiKey apiKey = new ApiKey();
    public Jws jws = new Jws();
    public List<EntityConf> entities = new ArrayList<>();
    public Forwarding forwarding = new Forwarding();
    public TokenServiceConf tokenService;

    public String aigSource = "config";
    public String aigBaseUrl;
    public String fipAigPath = "/v1/aig/fip";
    public String fiuAigPath = "/v1/aig/fiu";
    public String aaAigPath = "/v1/aig/aa";
    public String aigToken;
    public Integer aigRefreshSeconds = 21600;
    public Integer aigRetrySeconds = 300;
    public Integer aigTimeoutSeconds = 30;
    public AigGraph aig;

    public Cr cr = new Cr();
    public Cache cache;
    public Logging logging = new Logging();
    public GwApi gwApi;
    public LinkedAAsConf linkedAAs = new LinkedAAsConf();
    public HopPreference hopPreference = new HopPreference();
    public Limits limits = new Limits();

    public static final class Tls {
        public String certFile;
        public String keyFile;
    }

    public static final class Self {
        public String id;
        public SigningKey signingKey = new SigningKey();
        public DecryptionKeys decryptionKeys = new DecryptionKeys();
        public String outboundApiKey;
    }

    public static final class SigningKey {
        public String source = "file";
        public String kid;
        public String file;
        public Boolean active;
        public String applied;
        public String expiry;
        public String url;
        public String token;
        public Integer refreshSeconds;
    }

    public static final class DecryptionKeys {
        public String source = "file";
        public List<KeyFile> keys = new ArrayList<>();
        public String url;
        public String token;
        public Integer refreshSeconds;
    }

    public static final class KeyFile {
        public String kid;
        public String file;
        public Boolean active;
        public String applied;
        public String expiry;
    }

    public static final class Core {
        public String baseUrl;
        public String keysBaseUrl;
        public String pathPrefix;
        public Integer timeoutSeconds = 30;
        public String token;
    }

    public static final class ApiKey {
        public String mode = "jwt";
        public String senderIdClaim = "azp";
        public String issuer;
        public String audience;
        public Integer clockSkewSeconds = 60;
        public List<String> issuerPublicKeys = new ArrayList<>();
        public String issuerKeysUrl;
        public Integer issuerKeysRefreshSeconds;
        /** Static mode: {@code "${ENV}": entity-id}. Development and tests only. */
        @com.fasterxml.jackson.annotation.JsonProperty("static")
        public Map<String, String> staticKeys = new LinkedHashMap<>();
    }

    public static final class Jws {
        public String algorithm = "RS256";
    }

    public static final class EntityConf {
        public String id;
        public String type;
        public String baseUrl;
        public List<KeyFile> signingPublicKeys = new ArrayList<>();
        public List<KeyFile> encryptionPublicKeys = new ArrayList<>();
        public String outboundApiKey;
        public Boolean interop;
    }

    public static final class Forwarding {
        public Integer timeoutSeconds = 30;
        public Integer httpRetries;
        public Boolean skipUpstreamResponseSignature = false;
        public List<PathRewrite> pathRewrite;
        public Boolean preserveUnknownEnvelopeFields;
    }

    public static final class PathRewrite {
        public String targetType;
        public String from;
        public String to;
    }

    public static final class TokenServiceConf {
        public String baseUrl;
        public String path = "/entity/token/generate";
        public String credentialsFile;
        public Integer refreshBeforeSeconds = 3600;
        public Integer timeoutSeconds = 30;
    }

    /** Configured AIG graph: each list holds single-entry maps {@code id: [hop ids]}. */
    public static final class AigGraph {
        public List<Map<String, List<String>>> fiu;
        public List<Map<String, List<String>>> fip;
        public List<Map<String, List<String>>> aa;
    }

    public static final class Cr {
        public String source = "config";
        public String baseUrl;
        public String entityInfoPath = "/v2/entityInfo";
        public String token;
        public Integer refreshSeconds = 21600;
        public Integer retrySeconds = 300;
        public Integer timeoutSeconds = 30;
    }

    public static final class Cache {
        public String dir;
        /** rocksdb (default) or file. */
        public String engine = "rocksdb";
    }

    public static final class Logging {
        public String level = "INFO";
        public Boolean audit = true;
        public Integer statsIntervalSeconds = 60;
    }

    public static final class GwApi {
        public String listenAddr;
        public String httpListenAddr;
        public Tls tls;
        public String token;
        public String ver = "1.1.0";
        public Integer maxRetries = 3;
        public Integer maxRouteRetries = 2;
        /** FIU mode: how long /fiu-dgw/broadcast/User/discover waits for the AAs; default 10. */
        public Integer broadcastTimeoutSeconds;
    }

    public static final class LinkedAAsConf {
        public String source = "config";
        public List<String> aas;
        public String url;
        public String token;
        public Integer refreshSeconds = 3600;
    }

    public static final class HopPreference {
        public List<String> connectedAAs = new ArrayList<>();
        public List<String> interAAs = new ArrayList<>();
    }

    public static final class Limits {
        public Long maxBodyBytes = 2L * 1024 * 1024;
        public Long maxUpstreamBytes = 64L * 1024 * 1024;
    }

    // ---- resolved at load time (not YAML keys) ----

    /** Resolved secrets of the main file (shared settings), keyed by a descriptive name; never logged. */
    @com.fasterxml.jackson.annotation.JsonIgnore
    public final Map<String, String> secrets = new LinkedHashMap<>();

    /** Single-tenant mode: the one entity's settings, read from the main file. Null in multi-tenant mode. */
    @com.fasterxml.jackson.annotation.JsonIgnore
    public EntitySettings single;

    public String secret(String name) {
        return secrets.get(name);
    }

    /** True with {@code multiTenant: on} (or {@code true}). */
    public boolean isMultiTenant() {
        return "on".equals(multiTenant) || "true".equals(multiTenant);
    }

    /** A scalar as written in the YAML file ({@code on} stays {@code "on"}, not {@code true}). */
    public static final class RawScalar extends com.fasterxml.jackson.databind.JsonDeserializer<String> {
        @Override
        public String deserialize(com.fasterxml.jackson.core.JsonParser p,
                                  com.fasterxml.jackson.databind.DeserializationContext ctx) throws java.io.IOException {
            if (!p.currentToken().isScalarValue()) {
                p.skipChildren();
                return "<not a scalar>";
            }
            return p.getText();
        }
    }
}
