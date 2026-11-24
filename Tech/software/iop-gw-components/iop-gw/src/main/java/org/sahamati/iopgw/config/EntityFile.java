package org.sahamati.iopgw.config;

/**
 * One entity file (multi-tenant mode): the settings of one entity. Field names are the
 * YAML keys; unknown keys are rejected, as in the main file.
 */
public final class EntityFile {
    public String entityId;
    /** Only {@code true} loads the entity; kept as written. */
    @com.fasterxml.jackson.databind.annotation.JsonDeserialize(using = Config.RawScalar.class)
    public String enable;
    public Config.SigningKey signingKey = new Config.SigningKey();
    public Config.DecryptionKeys decryptionKeys = new Config.DecryptionKeys();
    /** Testing only: a fixed api-key instead of the token service. */
    public String outboundApiKey;
    public TokenService tokenService;
    /** Testing only: a fixed AIG token instead of the access token. */
    public String aigToken;
    public Config.Core core = new Config.Core();
    public GwApi gwApi;
    public Config.LinkedAAsConf linkedAAs = new Config.LinkedAAsConf();
    public Config.HopPreference hopPreference = new Config.HopPreference();

    /** The entity's own token service credentials; the other token service settings are in the main file. */
    public static final class TokenService {
        public String credentialsFile;
    }

    /** The entity's internal API token; the other internal API settings are in the main file. */
    public static final class GwApi {
        public String token;
    }
}
