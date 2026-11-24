package org.sahamati.iopgw.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.sahamati.iopgw.model.Roles;
import org.sahamati.iopgw.obs.Logs;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Loads and validates the configuration: strict YAML (unknown keys, empty files and
 * multi-document files rejected), all errors reported together, secrets only as {@code ${ENV}}
 * references.
 * <p>
 * The main file holds the shared settings and, with {@code multiTenant: off} (the default), the
 * one entity's settings ({@code self} and the top-level per-entity settings). With
 * {@code multiTenant: on} each entity's settings are in an entity file, read by
 * {@link #entity(Config, String, String)}; the same per-entity rules apply to both.
 */
public final class ConfigLoader {

    public static final class ConfigException extends Exception {
        public final List<String> errors;

        public ConfigException(List<String> errors) {
            super("invalid configuration: " + String.join("; ", errors));
            this.errors = List.copyOf(errors);
        }
    }

    /** One entity file read in multi-tenant mode. */
    public record EntityLoad(String file, String entityId, boolean enabled, EntitySettings settings, List<String> errors) {
        public boolean valid() {
            return errors.isEmpty();
        }
    }

    private static final Pattern ENV_REF = Pattern.compile("^\\$\\{([A-Za-z_][A-Za-z0-9_]*)}$");
    private static final Set<String> MULTI_TENANT_VALUES = Set.of("on", "off", "true", "false");
    /** Main-file keys that belong in the entity files with {@code multiTenant: on}. */
    private static final List<String> ENTITY_KEYS = List.of("self", "core", "linkedAAs", "hopPreference", "aigToken");

    private final Map<String, String> env;
    private final List<String> errors = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    public ConfigLoader(Map<String, String> env) {
        this.env = env;
    }

    public List<String> warnings() {
        return warnings;
    }

    private static ObjectMapper yaml() {
        return new ObjectMapper(new YAMLFactory())
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public Config load(Path file) throws ConfigException {
        String text;
        try {
            text = Files.readString(file, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new ConfigException(List.of("cannot read configuration file " + file));
        }
        return parse(text);
    }

    public Config parse(String text) throws ConfigException {
        Config c = read(text, Config.class, "configuration");
        JsonNode tree;
        try {
            tree = yaml().readTree(text);
        } catch (Exception e) {
            throw new ConfigException(List.of("configuration is not valid YAML"));
        }
        validate(c, tree);
        if (!errors.isEmpty()) {
            throw new ConfigException(errors);
        }
        return c;
    }

    /** Strict YAML into {@code type}; the errors name {@code what} ("configuration" or "entity file"). */
    private static <T> T read(String text, Class<T> type, String what) throws ConfigException {
        if (text == null || text.isBlank()) {
            throw new ConfigException(List.of(what + " file is empty"));
        }
        T c;
        try (MappingIterator<T> it = yaml().readerFor(type).readValues(text)) {
            if (!it.hasNext()) {
                throw new ConfigException(List.of(what + " file is empty"));
            }
            c = it.next();
            if (it.hasNext()) {
                throw new ConfigException(List.of(what + " must be a single YAML document"));
            }
        } catch (ConfigException e) {
            throw e;
        } catch (Exception e) {
            for (Throwable t = e; t != null; t = t.getCause()) {
                if (t instanceof UnrecognizedPropertyException u) {
                    throw new ConfigException(List.of("unknown " + ("configuration".equals(what) ? "configuration" : "entity file")
                            + " key '" + u.getPropertyName() + "' at " + path(u)));
                }
            }
            throw new ConfigException(List.of(what + " is not valid YAML for this gateway: "
                    + String.valueOf(e.getMessage()).lines().findFirst().orElse("")));
        }
        if (c == null) {
            throw new ConfigException(List.of(what + " file is empty"));
        }
        return c;
    }

    private static String path(UnrecognizedPropertyException e) {
        StringBuilder sb = new StringBuilder();
        e.getPath().forEach(r -> {
            if (r.getFieldName() != null) {
                sb.append(sb.isEmpty() ? "" : ".").append(r.getFieldName());
            } else if (r.getIndex() >= 0) {
                sb.append('[').append(r.getIndex()).append(']');
            }
        });
        return sb.isEmpty() ? "top level" : sb.toString();
    }

    // ------------------------------------------------------------------------------------
    // Entity files (multi-tenant mode)
    // ------------------------------------------------------------------------------------

    /**
     * Reads one entity file against the validated main configuration {@code main}. A disabled file
     * is read but not validated further. Never throws: the result carries the errors.
     */
    public EntityLoad entity(Config main, String fileName, String text) {
        String hash = sha256(text == null ? "" : text);
        EntityFile f;
        try {
            f = read(text, EntityFile.class, "entity file");
        } catch (ConfigException e) {
            return new EntityLoad(fileName, lenientEntityId(text), true, null, prefixed(fileName, e.errors));
        }
        boolean enabled = "true".equals(f.enable);
        if (f.enable != null && !"true".equals(f.enable) && !"false".equals(f.enable)) {
            warnings.add("entity file " + fileName + ": enable is '" + f.enable + "', not true: the entity is not loaded");
        }
        if (!enabled) {
            return new EntityLoad(fileName, f.entityId, false, null, List.of());
        }
        EntitySettings s = new EntitySettings();
        s.id = f.entityId;
        s.signingKey = f.signingKey;
        s.decryptionKeys = f.decryptionKeys;
        s.credentialsFile = f.tokenService == null ? null : f.tokenService.credentialsFile;
        s.core = f.core;
        s.linkedAAs = f.linkedAAs;
        s.hopPreference = f.hopPreference;
        s.file = fileName;
        s.contentHash = hash;
        Roles.Mode mode = Roles.Mode.valueOf(main.mode);
        Names n = new Names("entityId", "signingKey", "decryptionKeys", "outboundApiKey", "entity file " + fileName + ": ");
        if (f.tokenService != null && f.tokenService.credentialsFile == null) {
            errors.add(n.label + "tokenService must set credentialsFile");
        }
        if (f.gwApi != null && main.gwApi == null) {
            errors.add(n.label + "gwApi.token is set but the main file has no gwApi (internal APIs)");
        }
        validateEntity(main, mode, s, new Refs(f.outboundApiKey, f.aigToken, f.gwApi == null ? null : f.gwApi.token), n);
        List<String> errs = List.copyOf(errors);
        errors.clear();
        return new EntityLoad(fileName, f.entityId, true, errs.isEmpty() ? s : null, errs);
    }

    /** The entityId of a file that is not valid for this gateway, when it can still be read as YAML; else null. */
    private static String lenientEntityId(String text) {
        try {
            JsonNode n = new ObjectMapper(new YAMLFactory()).readTree(text == null ? "" : text);
            JsonNode id = n == null ? null : n.get("entityId");
            return id != null && id.isTextual() && !id.asText().isBlank() ? id.asText() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static List<String> prefixed(String file, List<String> errs) {
        return errs.stream().map(e -> "entity file " + file + ": " + e).toList();
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------------------------
    // Main file
    // ------------------------------------------------------------------------------------

    private void validate(Config c, JsonNode tree) {
        Roles.Mode mode;
        try {
            mode = Roles.Mode.valueOf(c.mode);
        } catch (Exception e) {
            errors.add("mode must be AA, FIU or FIP");
            return;
        }
        boolean connector = mode != Roles.Mode.AA;

        // single-tenant or multi-tenant
        if (c.multiTenant != null && !MULTI_TENANT_VALUES.contains(c.multiTenant)) {
            errors.add("multiTenant must be on or off (true or false are accepted too), not '" + c.multiTenant + "'");
            return;
        }
        boolean multi = c.isMultiTenant();
        if (multi) {
            if (mode == Roles.Mode.AA) {
                errors.add("multiTenant: on is not allowed in AA mode (AA mode is single-tenant)");
            }
            if (blank(c.entityConfigPath)) {
                errors.add("entityConfigPath is required with multiTenant: on");
            } else if (!Files.isDirectory(Path.of(c.entityConfigPath))) {
                errors.add("entityConfigPath: folder not found: " + c.entityConfigPath);
            }
            if (c.entityRescanSeconds == null) {
                c.entityRescanSeconds = 60;
            } else if (c.entityRescanSeconds <= 0) {
                errors.add("entityRescanSeconds must be positive");
            }
            for (String key : ENTITY_KEYS) {
                if (tree != null && tree.has(key)) {
                    errors.add(key + " is not allowed in the main file with multiTenant: on (it belongs in the entity files)");
                }
            }
            if (tree != null && tree.path("tokenService").has("credentialsFile")) {
                errors.add("tokenService.credentialsFile is not allowed in the main file with multiTenant: on (it belongs in the entity files)");
            }
            if (tree != null && tree.path("gwApi").has("token")) {
                errors.add("gwApi.token is not allowed in the main file with multiTenant: on (it belongs in the entity files)");
            }
        } else {
            if (c.entityConfigPath != null) {
                warnings.add("entityConfigPath is ignored with multiTenant: off (single-tenant: the main file holds the entity's settings)");
            }
            if (c.entityRescanSeconds != null) {
                warnings.add("entityRescanSeconds is ignored with multiTenant: off");
            }
        }

        String level = Logs.normalise(c.logging.level);
        if (level == null) {
            errors.add("logging.level must be TRACE, DEBUG, INFO, WARN, ERROR or CRITICAL");
        } else {
            c.logging.level = level;
        }
        if (c.logging.statsIntervalSeconds == null || c.logging.statsIntervalSeconds < 0) {
            errors.add("logging.statsIntervalSeconds must be 0 or more");
        }

        addr("listenAddr", c.listenAddr, true);
        tls("tls", c.tls, false);

        // api-key checking
        switch (String.valueOf(c.apiKey.mode)) {
            case "jwt" -> {
                boolean url = c.apiKey.issuerKeysUrl != null;
                boolean files = !c.apiKey.issuerPublicKeys.isEmpty();
                if (url && files) {
                    errors.add("apiKey: issuerKeysUrl and issuerPublicKeys are exclusive (one source)");
                } else if (!url && !files) {
                    errors.add("apiKey: jwt mode needs issuerKeysUrl or issuerPublicKeys");
                }
                if (url && !httpsUrl(c.apiKey.issuerKeysUrl)) {
                    errors.add("apiKey.issuerKeysUrl must be an absolute https URL");
                }
                if (c.apiKey.issuerKeysRefreshSeconds != null) {
                    if (!url) {
                        errors.add("apiKey.issuerKeysRefreshSeconds is only allowed with issuerKeysUrl");
                    } else {
                        positive("apiKey.issuerKeysRefreshSeconds", c.apiKey.issuerKeysRefreshSeconds);
                    }
                } else if (url) {
                    c.apiKey.issuerKeysRefreshSeconds = 3600;
                }
                if (c.apiKey.clockSkewSeconds == null || c.apiKey.clockSkewSeconds < 0) {
                    errors.add("apiKey.clockSkewSeconds must be 0 or more");
                }
                for (String f : c.apiKey.issuerPublicKeys) {
                    exists("apiKey.issuerPublicKeys", f);
                }
                if (!c.apiKey.staticKeys.isEmpty()) {
                    errors.add("apiKey.static is only allowed with mode: static");
                }
            }
            case "static" -> {
                warnings.add("apiKey.mode static is for development and tests only");
                if (c.apiKey.issuerKeysUrl != null || c.apiKey.issuerKeysRefreshSeconds != null || !c.apiKey.issuerPublicKeys.isEmpty()) {
                    errors.add("apiKey: issuer keys (issuerKeysUrl, issuerKeysRefreshSeconds, issuerPublicKeys) belong to mode jwt");
                }
                if (c.apiKey.staticKeys.isEmpty()) {
                    errors.add("apiKey.static must list at least one api-key");
                }
                c.apiKey.staticKeys.forEach((ref, entity) -> {
                    String v = resolve("apiKey.static", ref);
                    if (v != null) {
                        c.secrets.put("apiKey.static:" + entity, v);
                    }
                });
            }
            default -> errors.add("apiKey.mode must be jwt or static");
        }
        if (!"RS256".equals(c.jws.algorithm)) {
            errors.add("jws.algorithm must be RS256");
        }

        // forwarding
        positive("forwarding.timeoutSeconds", c.forwarding.timeoutSeconds);
        if (connector) {
            if (c.forwarding.httpRetries != null) {
                errors.add("forwarding.httpRetries is only allowed in AA mode");
            }
            if (c.forwarding.pathRewrite != null) {
                errors.add("forwarding.pathRewrite is only allowed in AA mode");
            }
            if (c.forwarding.preserveUnknownEnvelopeFields != null) {
                errors.add("forwarding.preserveUnknownEnvelopeFields is only allowed in AA mode");
            }
        } else if (c.forwarding.httpRetries != null && c.forwarding.httpRetries < 0) {
            errors.add("forwarding.httpRetries must be 0 or more");
        }

        // token service (shared settings; the credentials file is per entity)
        if (c.tokenService != null) {
            if (blank(c.tokenService.baseUrl) || !httpUrl(c.tokenService.baseUrl)) {
                errors.add("tokenService.baseUrl must be an absolute http(s) URL");
            }
            if (c.tokenService.path == null || !c.tokenService.path.startsWith("/")) {
                errors.add("tokenService.path must start with /");
            }
        }

        validateRegistry(c, mode);
        validateAig(c, mode);
        validateGwApi(c, mode);

        if (c.cache != null) {
            if (blank(c.cache.dir)) {
                errors.add("cache.dir must not be empty (omit cache for memory only)");
            }
            if (!"rocksdb".equals(c.cache.engine) && !"file".equals(c.cache.engine)) {
                errors.add("cache.engine must be rocksdb or file");
            }
        }
        if (c.limits.maxBodyBytes == null || c.limits.maxBodyBytes <= 0
                || c.limits.maxUpstreamBytes == null || c.limits.maxUpstreamBytes <= 0) {
            errors.add("limits must be positive");
        }

        if (!multi) {
            // single-tenant: the entity's settings are in the main file (self and top-level settings)
            EntitySettings s = new EntitySettings();
            s.id = c.self.id;
            s.signingKey = c.self.signingKey;
            s.decryptionKeys = c.self.decryptionKeys;
            s.credentialsFile = c.tokenService == null ? null : c.tokenService.credentialsFile;
            s.core = c.core;
            s.linkedAAs = c.linkedAAs;
            s.hopPreference = c.hopPreference;
            validateEntity(c, mode, s, new Refs(c.self.outboundApiKey, c.aigToken, c.gwApi == null ? null : c.gwApi.token),
                    new Names("self.id", "self.signingKey", "self.decryptionKeys", "self.outboundApiKey", ""));
            c.single = s;
        }
    }

    // ------------------------------------------------------------------------------------
    // Per-entity settings (both modes)
    // ------------------------------------------------------------------------------------

    /** The secret references of one entity's settings. */
    private record Refs(String outboundApiKey, String aigToken, String gwApiToken) {}

    /** How the per-entity settings are named in the messages: {@code self.*} or entity-file keys. */
    private record Names(String id, String signingKey, String decryptionKeys, String outboundApiKey, String label) {}

    private void validateEntity(Config c, Roles.Mode mode, EntitySettings s, Refs r, Names n) {
        String l = n.label;
        if (blank(s.id)) {
            errors.add(l + n.id + " is required");
        }
        secret(s, "outboundApiKey", l + n.outboundApiKey, r.outboundApiKey);

        // core
        if (blank(s.core.baseUrl) || !httpUrl(s.core.baseUrl)) {
            errors.add(l + "core.baseUrl must be an absolute http(s) URL");
        }
        if (s.core.pathPrefix == null) {
            s.core.pathPrefix = Roles.defaultCorePrefix(mode);
        } else if (!s.core.pathPrefix.startsWith("/")) {
            errors.add(l + "core.pathPrefix must start with /");
        }
        if (s.core.keysBaseUrl != null && !httpsUrl(s.core.keysBaseUrl)) {
            errors.add(l + "core.keysBaseUrl must be an absolute https URL (private keys are in transit)");
        }
        validateKeys(c, s, n);
        secret(s, "core.token", l + "core.token", s.core.token);
        positive(l + "core.timeoutSeconds", s.core.timeoutSeconds);

        // token service: the entity's credentials file
        if (c.tokenService != null) {
            if (blank(s.credentialsFile)) {
                errors.add(l + "tokenService.credentialsFile is required");
            } else if (!Files.isRegularFile(Path.of(s.credentialsFile))) {
                errors.add(l + "tokenService.credentialsFile: file not found: " + s.credentialsFile);
            } else if (s.id != null) {
                String id = credentialsEntityId(s.credentialsFile);
                if (id == null) {
                    errors.add(l + "tokenService.credentialsFile is not a JSON object with entityId");
                } else if (!id.equals(s.id)) {
                    errors.add(l + "tokenService.credentialsFile is for another entity, not " + s.id);
                }
            }
            if (r.outboundApiKey != null) {
                errors.add(l + n.outboundApiKey + " is not allowed with tokenService (one source)");
            }
            if (r.aigToken != null) {
                errors.add(l + "aigToken is not allowed with tokenService (one source)");
            }
        } else if (s.credentialsFile != null) {
            errors.add(l + "tokenService.credentialsFile is set but the main file has no tokenService");
        }

        // AIG token (testing only, without tokenService)
        if ("config".equals(c.aigSource)) {
            if (r.aigToken != null) {
                errors.add(l + "aigToken belongs to aigSource api");
            }
        } else if ("api".equals(c.aigSource)) {
            if (c.tokenService == null && r.aigToken == null) {
                errors.add(l + "AIG: a token source is required (tokenService or aigToken)");
            }
            secret(s, "aigToken", l + "aigToken", r.aigToken);
        }

        // internal API token
        secret(s, "gwApi.token", l + "gwApi.token", r.gwApiToken);
        if (c.gwApi != null && r.gwApiToken == null) {
            warnings.add(l + "gwApi.token is not set: internal API calls" + (l.isEmpty() ? "" : " for this entity")
                    + " need no Authorization");
        }

        // linkedAAs: required
        Config.LinkedAAsConf la = s.linkedAAs;
        switch (String.valueOf(la.source)) {
            case "config" -> {
                if (la.url != null || la.token != null) {
                    errors.add(l + "linkedAAs: url and token belong to source api");
                }
                if (la.aas == null || la.aas.isEmpty()) {
                    errors.add(l + "linkedAAs.aas is required (source config)");
                } else if (new HashSet<>(la.aas).size() != la.aas.size()) {
                    errors.add(l + "linkedAAs.aas has a repeated id");
                }
            }
            case "api" -> {
                if (la.aas != null) {
                    errors.add(l + "linkedAAs.aas belongs to source config");
                }
                if (la.token == null) {
                    errors.add(l + "linkedAAs.token is required with source api");
                }
                secret(s, "linkedAAs.token", l + "linkedAAs.token", la.token);
                if (la.url != null && !httpUrl(la.url)) {
                    errors.add(l + "linkedAAs.url must be an absolute http(s) URL");
                }
                positive(l + "linkedAAs.refreshSeconds", la.refreshSeconds);
            }
            default -> errors.add(l + "linkedAAs.source must be config or api");
        }

        // hopPreference
        if (mode == Roles.Mode.FIU && !s.hopPreference.interAAs.isEmpty()) {
            errors.add(l + "hopPreference.interAAs is not allowed in FIU mode");
        }
        if (mode == Roles.Mode.FIP && !s.hopPreference.connectedAAs.isEmpty()) {
            errors.add(l + "hopPreference.connectedAAs is not allowed in FIP mode");
        }
        for (List<String> p : List.of(s.hopPreference.connectedAAs, s.hopPreference.interAAs)) {
            if (new HashSet<>(p).size() != p.size()) {
                errors.add(l + "hopPreference: duplicate entry");
            }
        }
    }

    /** The {@code entityId} of a credentials file, or null when it cannot be read as one. */
    private static String credentialsEntityId(String file) {
        try {
            JsonNode n = new ObjectMapper().readTree(Files.readAllBytes(Path.of(file)));
            JsonNode id = n == null ? null : n.get("entityId");
            return id != null && id.isTextual() ? id.asText() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private void validateKeys(Config c, EntitySettings s, Names n) {
        String l = n.label;
        String skName = n.signingKey;
        Config.SigningKey sk = s.signingKey;
        switch (String.valueOf(sk.source)) {
            case "file" -> {
                if (blank(sk.kid)) {
                    errors.add(l + skName + ".kid is required");
                }
                exists(l + skName + ".file", sk.file);
                if (sk.url != null || sk.token != null || sk.refreshSeconds != null) {
                    errors.add(l + skName + ": url, token and refreshSeconds belong to source api");
                }
                validity(l + skName, sk.applied, sk.expiry);
            }
            case "api" -> {
                if (sk.kid != null || sk.file != null || sk.active != null || sk.applied != null || sk.expiry != null) {
                    errors.add(l + skName + ": kid, file, active, applied and expiry belong to source file");
                }
                apiKeySource(c, s, l + skName, "signing", sk.url, sk.token, sk.refreshSeconds);
                secret(s, "signingKey.token", l + skName + ".token", sk.token);
                if (sk.refreshSeconds == null) {
                    sk.refreshSeconds = 3600;
                }
            }
            default -> errors.add(l + skName + ".source must be file or api");
        }
        String dkName = n.decryptionKeys;
        Config.DecryptionKeys dk = s.decryptionKeys;
        switch (String.valueOf(dk.source)) {
            case "file" -> {
                if (dk.keys.isEmpty()) {
                    errors.add(l + dkName + ".keys must list at least one key");
                }
                Set<String> kids = new HashSet<>();
                for (Config.KeyFile k : dk.keys) {
                    if (blank(k.kid) || !kids.add(k.kid)) {
                        errors.add(l + dkName + ".keys: kids must be present and unique");
                    }
                    exists(l + dkName + ".keys.file", k.file);
                    validity(l + dkName + ".keys[" + k.kid + "]", k.applied, k.expiry);
                }
                if (dk.url != null || dk.token != null || dk.refreshSeconds != null) {
                    errors.add(l + dkName + ": url, token and refreshSeconds belong to source api");
                }
            }
            case "api" -> {
                if (!dk.keys.isEmpty()) {
                    errors.add(l + dkName + ".keys belongs to source file");
                }
                apiKeySource(c, s, l + dkName, "decryption", dk.url, dk.token, dk.refreshSeconds);
                secret(s, "decryptionKeys.token", l + dkName + ".token", dk.token);
                if (dk.refreshSeconds == null) {
                    dk.refreshSeconds = 3600;
                }
            }
            default -> errors.add(l + dkName + ".source must be file or api");
        }
    }

    /** Keys from the core: https only, a bearer token as an ${ENV} secret, the HTTPS internal listener for push. */
    private void apiKeySource(Config c, EntitySettings s, String name, String kind, String url, String token, Integer refresh) {
        if (url != null && !httpUrl(url)) {
            errors.add(name + ".url must be an absolute https URL");
        } else {
            String effective = s.keyUrl(kind);
            if (effective != null && !httpsUrl(effective)) {
                errors.add(name + ": the key URL " + (url != null ? "(url)" : s.core.keysBaseUrl != null
                        ? "(core.keysBaseUrl)" : "(core.baseUrl, the default)") + " must be https: private keys are in transit");
            }
        }
        if (token == null) {
            errors.add(name + ".token is required with source api");
        }
        if (refresh != null && refresh <= 0) {
            errors.add(name + ".refreshSeconds must be positive");
        }
        if (c.gwApi == null || c.gwApi.tls == null) {
            errors.add(name + ": source api needs gwApi with tls (key push is accepted only over HTTPS)");
        }
    }

    /** File-key validity dates: RFC 3339 or YYYY-MM-DD, expiry after applied; bad values stop start-up. */
    private void validity(String name, String applied, String expiry) {
        java.time.Instant from = null;
        java.time.Instant to = null;
        try {
            if (applied != null) {
                from = org.sahamati.iopgw.sources.CoreKeys.date(applied, name + ".applied");
            }
            if (expiry != null) {
                to = org.sahamati.iopgw.sources.CoreKeys.date(expiry, name + ".expiry");
            }
        } catch (IllegalArgumentException e) {
            errors.add(e.getMessage());
            return;
        }
        if (from != null && to != null && !to.isAfter(from)) {
            errors.add(name + ".expiry must be after applied");
        }
    }

    static boolean httpsUrl(String s) {
        return s != null && s.startsWith("https://") && httpUrl(s);
    }

    private void validateRegistry(Config c, Roles.Mode mode) {
        Set<String> ids = new HashSet<>();
        for (Config.EntityConf e : c.entities) {
            if (blank(e.id) || !ids.add(e.id)) {
                errors.add("entities: ids must be present and unique");
                continue;
            }
            String p = "entities[" + e.id + "]";
            secret(c, "entity:" + e.id + ".outboundApiKey", e.outboundApiKey);
            if (e.baseUrl != null && !httpUrl(e.baseUrl)) {
                errors.add(p + ".baseUrl must be an absolute http(s) URL");
            }
            if ("config".equals(c.cr.source)) {
                try {
                    Roles.EntityType t = Roles.EntityType.valueOf(String.valueOf(e.type));
                    if (mode != Roles.Mode.AA && t != Roles.EntityType.AA) {
                        errors.add(p + ": entities may list AAs only in " + mode + " mode");
                    }
                } catch (IllegalArgumentException ex) {
                    errors.add(p + ".type must be AA, FIU or FIP");
                }
                if (e.signingPublicKeys.isEmpty()) {
                    errors.add(p + ".signingPublicKeys must list at least one key");
                }
                for (Config.KeyFile k : e.signingPublicKeys) {
                    exists(p + ".signingPublicKeys", k.file);
                }
                for (Config.KeyFile k : e.encryptionPublicKeys) {
                    exists(p + ".encryptionPublicKeys", k.file);
                }
            } else {
                if (!e.signingPublicKeys.isEmpty() || !e.encryptionPublicKeys.isEmpty()) {
                    errors.add(p + ": CR overrides may not carry keys");
                }
                if (e.interop != null) {
                    errors.add(p + ".interop is not allowed on CR overrides");
                }
            }
        }
        switch (String.valueOf(c.cr.source)) {
            case "config" -> {
                if (c.cr.baseUrl != null || c.cr.token != null) {
                    errors.add("cr: baseUrl and token belong to cr.source api");
                }
                if (c.entities.isEmpty()) {
                    errors.add("entities: cr.source config needs at least one entity");
                }
            }
            case "api" -> {
                if (blank(c.cr.baseUrl) || !c.cr.baseUrl.startsWith("https://") || !httpUrl(c.cr.baseUrl)) {
                    errors.add("cr.baseUrl must be an absolute https URL");
                }
                if (c.cr.entityInfoPath == null || !c.cr.entityInfoPath.startsWith("/")) {
                    errors.add("cr.entityInfoPath must start with /");
                }
                if (c.tokenService == null && c.cr.token == null) {
                    errors.add("cr: a token source is required (tokenService or cr.token)");
                }
                if (c.tokenService != null && c.cr.token != null) {
                    errors.add("cr.token is not allowed with tokenService (one source)");
                }
                secret(c, "cr.token", c.cr.token);
            }
            default -> errors.add("cr.source must be config or api");
        }
    }

    private void validateAig(Config c, Roles.Mode mode) {
        switch (String.valueOf(c.aigSource)) {
            case "config" -> {
                if (c.aigBaseUrl != null) {
                    errors.add("aigBaseUrl belongs to aigSource api");
                }
                if (c.gwApi != null && c.aig == null) {
                    errors.add("aig: aigSource config needs a configured graph");
                }
                if (c.aig != null) {
                    if (mode == Roles.Mode.AA) {
                        if (c.aig.aa != null) {
                            errors.add("aig.aa is not allowed in AA mode");
                        }
                        graph("aig.fiu", c.aig.fiu);
                        graph("aig.fip", c.aig.fip);
                    } else {
                        if (c.aig.fiu != null || c.aig.fip != null) {
                            errors.add("aig.fiu and aig.fip are not allowed in " + mode + " mode");
                        }
                        graph("aig.aa", c.aig.aa);
                    }
                }
            }
            case "api" -> {
                if (c.aig != null) {
                    errors.add("aig: a configured graph is not allowed with aigSource api");
                }
                if (blank(c.aigBaseUrl) || !httpUrl(c.aigBaseUrl)) {
                    errors.add("aigBaseUrl must be an absolute http(s) URL");
                }
                for (String p : List.of(c.fiuAigPath, c.fipAigPath, c.aaAigPath)) {
                    if (p == null || !p.startsWith("/")) {
                        errors.add("AIG paths must start with /");
                    }
                }
            }
            default -> errors.add("aigSource must be config or api");
        }
        positive("aigRefreshSeconds", c.aigRefreshSeconds);
        positive("aigRetrySeconds", c.aigRetrySeconds);
        positive("aigTimeoutSeconds", c.aigTimeoutSeconds);
    }

    private void graph(String name, List<Map<String, List<String>>> entries) {
        if (entries == null) {
            return;
        }
        Set<String> seen = new HashSet<>();
        for (Map<String, List<String>> e : entries) {
            if (e == null || e.size() != 1) {
                errors.add(name + ": each entry must name exactly one id");
                continue;
            }
            Map.Entry<String, List<String>> only = e.entrySet().iterator().next();
            if (!seen.add(only.getKey())) {
                errors.add(name + ": id " + only.getKey() + " appears more than once");
            }
            if (only.getValue() == null || only.getValue().isEmpty()) {
                errors.add(name + ": " + only.getKey() + " has an empty list");
            }
        }
    }

    private void validateGwApi(Config c, Roles.Mode mode) {
        if (c.gwApi == null) {
            return;
        }
        Config.GwApi g = c.gwApi;
        addr("gwApi.listenAddr", g.listenAddr, true);
        tls("gwApi.tls", g.tls, true);
        if (g.httpListenAddr != null) {
            addr("gwApi.httpListenAddr", g.httpListenAddr, true);
            if (g.httpListenAddr.equals(g.listenAddr)) {
                errors.add("gwApi.httpListenAddr must differ from gwApi.listenAddr");
            }
        }
        if (g.listenAddr != null && g.listenAddr.equals(c.listenAddr)
                || g.httpListenAddr != null && g.httpListenAddr.equals(c.listenAddr)) {
            if (!c.listenAddr.endsWith(":0")) {
                errors.add("internal API listeners must not use the public listenAddr");
            }
        }
        if (g.maxRetries == null || g.maxRetries < 0) {
            errors.add("gwApi.maxRetries must be 0 or more");
        }
        if (g.maxRouteRetries == null || g.maxRouteRetries < 0) {
            errors.add("gwApi.maxRouteRetries must be 0 or more");
        }
        if (blank(g.ver)) {
            errors.add("gwApi.ver is required");
        }
        if (g.broadcastTimeoutSeconds != null) {
            if (mode != Roles.Mode.FIU) {
                errors.add("gwApi.broadcastTimeoutSeconds is only allowed in FIU mode");
            } else if (g.broadcastTimeoutSeconds < 0) {
                errors.add("gwApi.broadcastTimeoutSeconds must not be negative");
            }
        } else if (mode == Roles.Mode.FIU) {
            g.broadcastTimeoutSeconds = 10;
        }
    }

    // ---------------- helpers ----------------

    private void secret(Config c, String name, String ref) {
        if (ref == null) {
            return;
        }
        String v = resolve(name, ref);
        if (v != null) {
            c.secrets.put(name, v);
        }
    }

    /** Resolves {@code ref} into the entity's secrets under {@code key}; {@code name} is used in messages. */
    private void secret(EntitySettings s, String key, String name, String ref) {
        if (ref == null) {
            return;
        }
        String v = resolve(name, ref);
        if (v != null) {
            s.secrets.put(key, v);
        }
    }

    private String resolve(String name, String ref) {
        Matcher m = ENV_REF.matcher(ref);
        if (!m.matches()) {
            errors.add(name + " must be an ${ENV_VAR} reference, not a literal value");
            return null;
        }
        String v = env.get(m.group(1));
        if (v == null || v.isEmpty()) {
            errors.add(name + ": environment variable " + m.group(1) + " is not set or empty");
            return null;
        }
        return v;
    }

    private void addr(String name, String value, boolean required) {
        if (value == null) {
            if (required) {
                errors.add(name + " is required (host:port)");
            }
            return;
        }
        int i = value.lastIndexOf(':');
        try {
            int port = Integer.parseInt(value.substring(i + 1));
            if (i < 0 || port < 0 || port > 65535) {
                throw new NumberFormatException();
            }
        } catch (RuntimeException e) {
            errors.add(name + " must be host:port");
        }
    }

    private void tls(String name, Config.Tls tls, boolean required) {
        if (tls == null) {
            if (required) {
                errors.add(name + " is required (the internal APIs always run on HTTPS)");
            }
            return;
        }
        exists(name + ".certFile", tls.certFile);
        exists(name + ".keyFile", tls.keyFile);
    }

    private void exists(String name, String file) {
        if (blank(file)) {
            errors.add(name + " is required");
        } else if (!Files.isRegularFile(Path.of(file))) {
            errors.add(name + ": file not found: " + file);
        }
    }

    private void positive(String name, Integer v) {
        if (v == null || v <= 0) {
            errors.add(name + " must be positive");
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    static boolean httpUrl(String s) {
        try {
            URI u = URI.create(s);
            return u.isAbsolute() && ("http".equals(u.getScheme()) || "https".equals(u.getScheme())) && u.getHost() != null;
        } catch (Exception e) {
            return false;
        }
    }
}
