package org.sahamati.iopgw.config;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The validated settings of one entity: from the main file in single-tenant mode
 * ({@code self} and the top-level per-entity settings), or from one entity file in multi-tenant
 * mode. Secret values are resolved into {@link #secrets}, never logged.
 */
public final class EntitySettings {
    public String id;
    public Config.SigningKey signingKey = new Config.SigningKey();
    public Config.DecryptionKeys decryptionKeys = new Config.DecryptionKeys();
    public String credentialsFile;
    public Config.Core core = new Config.Core();
    public Config.LinkedAAsConf linkedAAs = new Config.LinkedAAsConf();
    public Config.HopPreference hopPreference = new Config.HopPreference();

    /** Multi-tenant mode: the entity file it was read from (name only), and a hash of its content. */
    public String file;
    public String contentHash;

    /**
     * Resolved secrets: {@code outboundApiKey}, {@code aigToken}, {@code core.token},
     * {@code gwApi.token}, {@code linkedAAs.token}, {@code signingKey.token}, {@code decryptionKeys.token}.
     */
    public final Map<String, String> secrets = new LinkedHashMap<>();

    public String secret(String name) {
        return secrets.get(name);
    }

    /**
     * The URL keys of {@code kind} ("signing" or "decryption") are fetched from with source api: the
     * key's own {@code url}, else {@code <core.keysBaseUrl or core.baseUrl><core.pathPrefix>/keys/<kind>}.
     */
    public String keyUrl(String kind) {
        String explicit = "signing".equals(kind) ? signingKey.url : decryptionKeys.url;
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

    /** {@code GET <linkedAAs.url>}, default {@code <core.baseUrl><core.pathPrefix>/linkedAAs}. */
    public String linkedAAsUrl() {
        if (linkedAAs.url != null) {
            return linkedAAs.url;
        }
        String base = core.baseUrl;
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + core.pathPrefix + "/linkedAAs";
    }
}
