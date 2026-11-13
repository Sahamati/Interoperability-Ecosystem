package org.sahamati.iopgw.sources;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.crypto.Pem;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.model.Roles.EntityType;
import org.sahamati.iopgw.model.Roles.Mode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/** The entity registry: participants, their keys and interop flags, from configuration or the Central Registry. */
public final class Registry {
    private static final Logger LOG = LoggerFactory.getLogger(Registry.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * A participant. {@code allSigningKeys} / {@code allEncryptionKeys} are every key the source
     * gave, with their validity windows: what the cache persists. Every use goes through
     * {@link #signingKeys()} and {@link #encryptionKey()}, which see only the keys usable now, so a
     * key comes into use at its validFrom and drops out at its validTo without a CR refresh.
     */
    public record Entity(String id, EntityType type, String baseUrl, boolean interop,
                         List<PubKey> allSigningKeys, List<PubKey> allEncryptionKeys, String outboundApiKey) {

        /** The signature-verification keys usable now. */
        public List<PubKey> signingKeys() {
            return PubKey.usableNow(allSigningKeys);
        }

        /** One encryption key usable now, chosen at random, or empty. */
        public Optional<PubKey> encryptionKey() {
            List<PubKey> usable = PubKey.usableNow(allEncryptionKeys);
            if (usable.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(usable.get(RANDOM.nextInt(usable.size())));
        }
    }

    /** Local overrides applied on top of Central Registry entries. */
    public record Override(String baseUrl, String outboundApiKey) {}

    private volatile Map<String, Entity> entities;
    /** The lists as fetched (or configured), without local settings: what the cache persists. */
    private volatile Map<String, Entity> raw;
    private final Map<String, Override> overrides;
    private volatile java.util.function.Consumer<java.util.Collection<Entity>> onReplace = x -> {};

    private Registry(Map<String, Entity> entities, Map<String, Override> overrides) {
        this.entities = entities;
        this.raw = entities;
        this.overrides = overrides;
    }

    /** Called with the raw lists whenever they are replaced from the source (for the persistent cache). */
    public void onReplace(java.util.function.Consumer<java.util.Collection<Entity>> c) {
        this.onReplace = c;
    }

    /** The lists without local settings (no outboundApiKey, no baseUrl overrides). */
    public java.util.Collection<Entity> rawEntities() {
        Map<String, Entity> m = raw;
        return m == null ? List.of() : m.values();
    }

    /** Serves a persisted copy; local overrides are applied again. */
    public void restore(Map<String, Entity> persisted) {
        if (persisted.isEmpty()) {
            return;
        }
        install(persisted);
        LOG.atInfo().addKeyValue("entities", persisted.size()).log("CR lists restored from the cache");
    }

    private void install(Map<String, Entity> next) {
        Map<String, Entity> withLocal = new LinkedHashMap<>();
        next.forEach((id, e) -> {
            Override o = overrides.get(id);
            withLocal.put(id, o == null ? e : new Entity(e.id(), e.type(),
                    o.baseUrl() != null ? trimSlash(o.baseUrl()) : e.baseUrl(), e.interop(),
                    e.allSigningKeys(), e.allEncryptionKeys(), o.outboundApiKey()));
        });
        this.raw = Map.copyOf(next);
        this.entities = Map.copyOf(withLocal);
    }

    public boolean loaded() {
        return entities != null;
    }

    /** Every entity held now (with local settings applied); empty before the first load. */
    public java.util.Collection<Entity> all() {
        Map<String, Entity> m = entities;
        return m == null ? List.of() : m.values();
    }

    public Optional<Entity> get(String id) {
        Map<String, Entity> m = entities;
        return m == null || id == null ? Optional.empty() : Optional.ofNullable(m.get(id));
    }

    // ---------------- configuration source ----------------

    public static Registry fromConfig(List<Config.EntityConf> confs, Map<String, String> outboundKeys) throws Exception {
        Map<String, Entity> m = new LinkedHashMap<>();
        for (Config.EntityConf e : confs) {
            List<PubKey> sig = new ArrayList<>();
            for (Config.KeyFile k : e.signingPublicKeys) {
                sig.add(new PubKey(k.kid, Pem.publicKey(Path.of(k.file))));
            }
            List<PubKey> enc = new ArrayList<>();
            for (Config.KeyFile k : e.encryptionPublicKeys) {
                enc.add(new PubKey(k.kid, Pem.publicKey(Path.of(k.file))));
            }
            m.put(e.id, new Entity(e.id, EntityType.valueOf(e.type), trimSlash(e.baseUrl),
                    e.interop == null || e.interop, List.copyOf(sig), List.copyOf(enc), null));
        }
        Map<String, Override> local = new LinkedHashMap<>();
        outboundKeys.forEach((id, key) -> local.put(id, new Override(null, key)));
        Registry r = new Registry(null, Map.copyOf(local));
        r.install(m);
        return r;
    }

    // ---------------- Central Registry source ----------------

    public static Registry fromCentralRegistry(Map<String, Override> overrides) {
        return new Registry(null, Map.copyOf(overrides));
    }

    /** Types fetched per mode: all three in AA mode, only AA in FIU and FIP mode. */
    public static List<EntityType> typesFor(Mode mode) {
        return mode == Mode.AA ? List.of(EntityType.AA, EntityType.FIP, EntityType.FIU) : List.of(EntityType.AA);
    }

    /** One CR load. Replaces the registry only if every list for the mode is fetched and parsed. */
    public boolean loadFromCr(Config.Cr cr, Mode mode, Http http, Supplier<Optional<String>> bearer) {
        Optional<String> token = bearer.get();
        if (token.isEmpty()) {
            LOG.atWarn().log("CR load skipped: no access token");
            return false;
        }
        Map<String, Entity> next = new LinkedHashMap<>();
        for (EntityType type : typesFor(mode)) {
            String url = cr.baseUrl + cr.entityInfoPath + "/" + type.name();
            try {
                Http.Response r = http.send("GET", url, Map.of("Authorization", "Bearer " + token.get()), null,
                        Duration.ofSeconds(cr.timeoutSeconds), 64L << 20);
                if (r.status() != 200) {
                    LOG.atWarn().addKeyValue("type", type).addKeyValue("status", r.status()).log("CR load failed");
                    return false;
                }
                JsonNode arr = Json.MAPPER.readTree(r.body());
                if (arr == null || !arr.isArray() || arr.isEmpty()) {
                    LOG.atWarn().addKeyValue("type", type).log("CR list is not a non-empty JSON array");
                    return false;
                }
                for (JsonNode el : arr) {
                    JsonNode info = el.get("entityinfo");
                    JsonNode interop = info == null ? null : info.get("interop");
                    if (interop != null && !interop.isNull() && !interop.isBoolean()) {
                        // interop must be a JSON boolean; anything else fails the fetch.
                        LOG.atWarn().addKeyValue("type", type).log("CR entry has a non-boolean interop; load failed");
                        return false;
                    }
                    Entity e = parse(info, type);
                    if (e != null && !next.containsKey(e.id())) {
                        next.put(e.id(), e);
                    }
                }
            } catch (Http.NoResponse e) {
                LOG.atWarn().addKeyValue("type", type).addKeyValue("noResponse", e.kind).log("CR load failed");
                return false;
            } catch (Exception e) {
                LOG.atWarn().addKeyValue("type", type).addKeyValue("error", e.getClass().getSimpleName()).log("CR load failed");
                return false;
            }
        }
        for (String id : overrides.keySet()) {
            if (!next.containsKey(id)) {
                LOG.atWarn().addKeyValue("entity", id).log("override for an id absent from the CR ignored");
            }
        }
        install(next);
        onReplace.accept(raw.values());
        LOG.atInfo().addKeyValue("entities", next.size()).log("CR loaded");
        return true;
    }

    private Entity parse(JsonNode info, EntityType type) {
        String id = Json.text(info, "id");
        if (id == null || id.isEmpty()) {
            return null;
        }
        String baseUrl = trimSlash(Json.text(info, "baseurl"));
        if (baseUrl != null && !isHttpUrl(baseUrl)) {
            baseUrl = null;
        }
        JsonNode interopNode = info.get("interop");
        boolean interop = interopNode != null && interopNode.isBoolean() && interopNode.asBoolean();
        JsonNode keys = info.get("keys");
        List<PubKey> sig = windowedKeys(keys == null ? null : keys.get("signature"), "sig", id);
        if (sig.isEmpty()) {
            sig = jwks(info.get("certificate"), "sig", id); // a bare JWK, no window
        }
        List<PubKey> enc = windowedKeys(keys == null ? null : keys.get("encryption"), "enc", id);
        return new Entity(id, type, baseUrl, interop, sig, enc, null);
    }

    /**
     * {@code keys.signature} / {@code keys.encryption}: a list of
     * {@code {"key": <JWK>, "validFrom", "validTo"}}. A bare JWK in these lists is skipped. Each
     * bound is an RFC 3339 timestamp with its time zone; absent, null or empty means no limit. A key
     * with a bound that is not such a timestamp (a date alone included), or with validTo before
     * validFrom, is skipped with a warning; the load does not fail.
     */
    private static List<PubKey> windowedKeys(JsonNode node, String use, String id) {
        List<PubKey> out = new ArrayList<>();
        if (node == null || node.isNull() || !node.isArray()) {
            return out;
        }
        for (JsonNode item : node) {
            JsonNode jwk = item.get("key");
            if (!item.isObject() || jwk == null || !jwk.isObject()) {
                LOG.atWarn().addKeyValue("entity", id).log("key skipped: not {key, validFrom, validTo} (a bare JWK is not accepted here)");
                continue;
            }
            java.time.Instant from;
            java.time.Instant to;
            try {
                from = bound(item.get("validFrom"));
                to = bound(item.get("validTo"));
            } catch (RuntimeException e) {
                LOG.atWarn().addKeyValue("entity", id).log("key skipped: validFrom/validTo is not an RFC 3339 timestamp with a time zone");
                continue;
            }
            if (from != null && to != null && to.isBefore(from)) {
                LOG.atWarn().addKeyValue("entity", id).log("key skipped: validTo is before validFrom");
                continue;
            }
            for (PubKey k : jwks(jwk, use, id)) {
                out.add(new PubKey(k.kid(), k.key(), from, to));
            }
        }
        return List.copyOf(out);
    }

    /** One window bound: null when absent, null or empty; else an RFC 3339 timestamp with an offset. */
    private static java.time.Instant bound(JsonNode n) {
        if (n == null || n.isNull() || (n.isTextual() && n.asText().isEmpty())) {
            return null;
        }
        if (!n.isTextual()) {
            throw new IllegalArgumentException("not a timestamp");
        }
        return java.time.OffsetDateTime.parse(n.asText(), java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
    }

    private static List<PubKey> jwks(JsonNode node, String use, String id) {
        List<PubKey> out = new ArrayList<>();
        if (node == null || node.isNull()) {
            return out;
        }
        List<JsonNode> items = new ArrayList<>();
        if (node.isArray()) {
            node.forEach(items::add);
        } else if (node.isObject()) {
            items.add(node);
        }
        for (JsonNode item : items) {
            try {
                JWK jwk = JWK.parse(item.toString());
                if (!(jwk instanceof RSAKey rsa) || jwk.getKeyID() == null || rsa.size() < Pem.MIN_RSA_BITS) {
                    LOG.atWarn().addKeyValue("entity", id).log("key skipped: not RSA >= 2048 with a kid");
                    continue;
                }
                if (jwk.getKeyUse() != null && !use.equals(jwk.getKeyUse().identifier())) {
                    LOG.atWarn().addKeyValue("entity", id).log("key skipped: wrong use");
                    continue;
                }
                if (jwk.getAlgorithm() != null) {
                    String alg = jwk.getAlgorithm().getName();
                    boolean ok = "sig".equals(use) ? ("RS256".equals(alg) || "PS256".equals(alg)) : "RSA-OAEP-256".equals(alg);
                    if (!ok) {
                        LOG.atWarn().addKeyValue("entity", id).log("key skipped: wrong alg");
                        continue;
                    }
                }
                out.add(new PubKey(jwk.getKeyID(), rsa.toRSAPublicKey()));
            } catch (Exception e) {
                LOG.atWarn().addKeyValue("entity", id).log("key skipped: undecodable");
            }
        }
        return List.copyOf(out);
    }

    /** A base URL with trailing '/' removed, so that '/iop/<api>' is appended cleanly. */
    static String trimSlash(String url) {
        if (url == null) {
            return null;
        }
        String s = url.trim();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    static boolean isHttpUrl(String s) {
        try {
            URI u = URI.create(s);
            return u.isAbsolute() && ("http".equals(u.getScheme()) || "https".equals(u.getScheme())) && u.getHost() != null;
        } catch (Exception e) {
            return false;
        }
    }
}
