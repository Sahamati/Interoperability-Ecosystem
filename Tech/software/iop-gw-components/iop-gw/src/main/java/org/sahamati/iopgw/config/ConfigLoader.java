package org.sahamati.iopgw.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
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
import java.util.ArrayList;
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
 */
public final class ConfigLoader {

    public static final class ConfigException extends Exception {
        public final List<String> errors;

        public ConfigException(List<String> errors) {
            super("invalid configuration: " + String.join("; ", errors));
            this.errors = List.copyOf(errors);
        }
    }

    private static final Pattern ENV_REF = Pattern.compile("^\\$\\{([A-Za-z_][A-Za-z0-9_]*)}$");

    private final Map<String, String> env;
    private final List<String> errors = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    public ConfigLoader(Map<String, String> env) {
        this.env = env;
    }

    public List<String> warnings() {
        return warnings;
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
        if (text == null || text.isBlank()) {
            throw new ConfigException(List.of("configuration file is empty"));
        }
        ObjectMapper yaml = new ObjectMapper(new YAMLFactory())
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        Config c;
        try (MappingIterator<Config> it = yaml.readerFor(Config.class).readValues(text)) {
            if (!it.hasNext()) {
                throw new ConfigException(List.of("configuration file is empty"));
            }
            c = it.next();
            if (it.hasNext()) {
                throw new ConfigException(List.of("configuration must be a single YAML document"));
            }
        } catch (ConfigException e) {
            throw e;
        } catch (Exception e) {
            for (Throwable t = e; t != null; t = t.getCause()) {
                if (t instanceof UnrecognizedPropertyException u) {
                    throw new ConfigException(List.of("unknown configuration key '" + u.getPropertyName() + "' at " + path(u)));
                }
            }
            throw new ConfigException(List.of("configuration is not valid YAML for this gateway: "
                    + String.valueOf(e.getMessage()).lines().findFirst().orElse("")));
        }
        if (c == null) {
            throw new ConfigException(List.of("configuration file is empty"));
        }
        validate(c);
        if (!errors.isEmpty()) {
            throw new ConfigException(errors);
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

    private void validate(Config c) {
        Roles.Mode mode;
        try {
            mode = Roles.Mode.valueOf(c.mode);
        } catch (Exception e) {
            errors.add("mode must be AA, FIU or FIP");
            return;
        }
        boolean connector = mode != Roles.Mode.AA;

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

        if (blank(c.self.id)) {
            errors.add("self.id is required");
        }
        secret(c, "self.outboundApiKey", c.self.outboundApiKey);

        // core
        if (blank(c.core.baseUrl) || !httpUrl(c.core.baseUrl)) {
            errors.add("core.baseUrl must be an absolute http(s) URL");
        }
        if (c.core.pathPrefix == null) {
            c.core.pathPrefix = Roles.defaultCorePrefix(mode);
        } else if (!c.core.pathPrefix.startsWith("/")) {
            errors.add("core.pathPrefix must start with /");
        }
        if (c.core.keysBaseUrl != null && !httpsUrl(c.core.keysBaseUrl)) {
            errors.add("core.keysBaseUrl must be an absolute https URL (private keys are in transit)");
        }
        validateKeys(c);
        secret(c, "core.token", c.core.token);
        positive("core.timeoutSeconds", c.core.timeoutSeconds);

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

        // token service
        if (c.tokenService != null) {
            if (blank(c.tokenService.baseUrl) || !httpUrl(c.tokenService.baseUrl)) {
                errors.add("tokenService.baseUrl must be an absolute http(s) URL");
            }
            if (c.tokenService.path == null || !c.tokenService.path.startsWith("/")) {
                errors.add("tokenService.path must start with /");
            }
            if (c.tokenService.iopPath == null || !c.tokenService.iopPath.startsWith("/")) {
                errors.add("tokenService.iopPath must start with /");
            }
            if (blank(c.tokenService.credentialsFile)) {
                errors.add("tokenService.credentialsFile is required");
            } else {
                exists("tokenService.credentialsFile", c.tokenService.credentialsFile);
            }
            if (c.self.outboundApiKey != null) {
                errors.add("self.outboundApiKey is not allowed with tokenService (one source)");
            }
            if (c.aigToken != null) {
                errors.add("aigToken is not allowed with tokenService (one source)");
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
    }

    private void validateKeys(Config c) {
        Config.SigningKey sk = c.self.signingKey;
        switch (String.valueOf(sk.source)) {
            case "file" -> {
                if (blank(sk.kid)) {
                    errors.add("self.signingKey.kid is required");
                }
                exists("self.signingKey.file", sk.file);
                if (sk.url != null || sk.token != null || sk.refreshSeconds != null) {
                    errors.add("self.signingKey: url, token and refreshSeconds belong to source api");
                }
                validity("self.signingKey", sk.applied, sk.expiry);
            }
            case "api" -> {
                if (sk.kid != null || sk.file != null || sk.active != null || sk.applied != null || sk.expiry != null) {
                    errors.add("self.signingKey: kid, file, active, applied and expiry belong to source file");
                }
                apiKeySource(c, "self.signingKey", "signing", sk.url, sk.token, sk.refreshSeconds);
                if (sk.refreshSeconds == null) {
                    sk.refreshSeconds = 3600;
                }
            }
            default -> errors.add("self.signingKey.source must be file or api");
        }
        Config.DecryptionKeys dk = c.self.decryptionKeys;
        switch (String.valueOf(dk.source)) {
            case "file" -> {
                if (dk.keys.isEmpty()) {
                    errors.add("self.decryptionKeys.keys must list at least one key");
                }
                Set<String> kids = new HashSet<>();
                for (Config.KeyFile k : dk.keys) {
                    if (blank(k.kid) || !kids.add(k.kid)) {
                        errors.add("self.decryptionKeys.keys: kids must be present and unique");
                    }
                    exists("self.decryptionKeys.keys.file", k.file);
                    validity("self.decryptionKeys.keys[" + k.kid + "]", k.applied, k.expiry);
                }
                if (dk.url != null || dk.token != null || dk.refreshSeconds != null) {
                    errors.add("self.decryptionKeys: url, token and refreshSeconds belong to source api");
                }
            }
            case "api" -> {
                if (!dk.keys.isEmpty()) {
                    errors.add("self.decryptionKeys.keys belongs to source file");
                }
                apiKeySource(c, "self.decryptionKeys", "decryption", dk.url, dk.token, dk.refreshSeconds);
                if (dk.refreshSeconds == null) {
                    dk.refreshSeconds = 3600;
                }
            }
            default -> errors.add("self.decryptionKeys.source must be file or api");
        }
    }

    /** Keys from the core: https only, a bearer token as an ${ENV} secret, the HTTPS internal listener for push. */
    private void apiKeySource(Config c, String name, String kind, String url, String token, Integer refresh) {
        if (url != null && !httpUrl(url)) {
            errors.add(name + ".url must be an absolute https URL");
        } else {
            String effective = c.keyUrl(kind);
            if (effective != null && !httpsUrl(effective)) {
                errors.add(name + ": the key URL " + (url != null ? "(url)" : c.core.keysBaseUrl != null
                        ? "(core.keysBaseUrl)" : "(core.baseUrl, the default)") + " must be https: private keys are in transit");
            }
        }
        if (token == null) {
            errors.add(name + ".token is required with source api");
        } else {
            secret(c, name + ".token", token);
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
                if (c.aigBaseUrl != null || c.aigToken != null) {
                    errors.add("aigBaseUrl and aigToken belong to aigSource api");
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
                if (c.tokenService == null && c.aigToken == null) {
                    errors.add("AIG: a token source is required (tokenService or aigToken)");
                }
                secret(c, "aigToken", c.aigToken);
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
        secret(c, "gwApi.token", g.token);
        if (g.token == null) {
            warnings.add("gwApi.token is not set: internal API calls need no Authorization");
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

        Config.LinkedAAsConf l = c.linkedAAs;
        switch (String.valueOf(l.source)) {
            case "config" -> {
                if (l.url != null || l.token != null) {
                    errors.add("linkedAAs: url and token belong to source api");
                }
                if (l.aas == null || l.aas.isEmpty()) {
                    errors.add("linkedAAs.aas is required with the internal APIs (source config)");
                } else if (new HashSet<>(l.aas).size() != l.aas.size()) {
                    errors.add("linkedAAs.aas has a repeated id");
                }
            }
            case "api" -> {
                if (l.aas != null) {
                    errors.add("linkedAAs.aas belongs to source config");
                }
                if (l.token == null) {
                    errors.add("linkedAAs.token is required with source api");
                }
                secret(c, "linkedAAs.token", l.token);
                if (l.url != null && !httpUrl(l.url)) {
                    errors.add("linkedAAs.url must be an absolute http(s) URL");
                }
                positive("linkedAAs.refreshSeconds", l.refreshSeconds);
            }
            default -> errors.add("linkedAAs.source must be config or api");
        }

        if (mode == Roles.Mode.FIU && !c.hopPreference.interAAs.isEmpty()) {
            errors.add("hopPreference.interAAs is not allowed in FIU mode");
        }
        if (mode == Roles.Mode.FIP && !c.hopPreference.connectedAAs.isEmpty()) {
            errors.add("hopPreference.connectedAAs is not allowed in FIP mode");
        }
        for (List<String> p : List.of(c.hopPreference.connectedAAs, c.hopPreference.interAAs)) {
            if (new HashSet<>(p).size() != p.size()) {
                errors.add("hopPreference: duplicate entry");
            }
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
