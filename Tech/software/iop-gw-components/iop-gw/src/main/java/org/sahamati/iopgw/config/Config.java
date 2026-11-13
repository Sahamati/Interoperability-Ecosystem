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
    public Integer aigRefreshSeconds = 43200;
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
        /** Where the IopToken is generated. */
        public String iopPath = "/entity/iopToken/generate";
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
        public Integer refreshSeconds = 14400;
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
        public String ver = "2.0.0";
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

    /** Resolved secrets, keyed by a descriptive name; never logged. */
    @com.fasterxml.jackson.annotation.JsonIgnore
    public final Map<String, String> secrets = new LinkedHashMap<>();

    public String secret(String name) {
        return secrets.get(name);
    }

    /**
     * The URL keys of {@code kind} ("signing" or "decryption") are fetched from with source api
     *: the key's own {@code url}, else
     * {@code <core.keysBaseUrl or core.baseUrl><core.pathPrefix>/keys/<kind>}.
     */
    public String keyUrl(String kind) {
        String explicit = "signing".equals(kind) ? self.signingKey.url : self.decryptionKeys.url;
        if (explicit != null) {
            return explicit;
        }
        String base = core.keysBaseUrl != null ? core.keysBaseUrl : core.baseUrl;
        if (base == null) {
            return null;
        }
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + (core.pathPrefix == null ? "" : core.pathPrefix) + "/keys/" + kind;
    }
}
