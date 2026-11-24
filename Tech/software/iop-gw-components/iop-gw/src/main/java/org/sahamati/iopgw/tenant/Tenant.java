package org.sahamati.iopgw.tenant;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.config.EntitySettings;
import org.sahamati.iopgw.crypto.KeyRing;
import org.sahamati.iopgw.crypto.Pem;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.model.Roles;
import org.sahamati.iopgw.sources.CoreKeys;
import org.sahamati.iopgw.sources.LinkedAAs;
import org.sahamati.iopgw.sources.Periodic;
import org.sahamati.iopgw.sources.Store;
import org.sahamati.iopgw.sources.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * One entity this gateway serves: its keys, tokens, {@code linkedAAs}, route
 * preference, core settings and internal API token. In single-tenant mode there is exactly one,
 * built from the main file; in multi-tenant mode one per loaded entity file.
 */
public final class Tenant implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(Tenant.class);

    public final String id;
    public final EntitySettings settings;
    public final KeyRing signing;
    public final KeyRing decryption;
    /** Keys from the core; null with source file. */
    public final CoreKeys coreSigning;
    public final CoreKeys coreDecryption;
    /** The access token; null without tokenService. */
    public final TokenService tokens;
    /** The IopToken (AA mode only); null otherwise. */
    public final TokenService iopTokens;
    public final LinkedAAs linkedAAs;
    /** Headers sent on every request to the core: {@code Core-Entity-Id} in multi-tenant mode, none otherwise. */
    public final Map<String, String> coreEntityHeader;
    private final List<AutoCloseable> closeables;
    /** Set while loading when the first key set fetched holds another entity's decryption {@code kid}. */
    private volatile String kidConflict;

    private Tenant(EntitySettings s, KeyRing signing, KeyRing decryption, CoreKeys coreSigning, CoreKeys coreDecryption,
                   TokenService tokens, TokenService iopTokens, LinkedAAs linkedAAs, Map<String, String> coreEntityHeader,
                   List<AutoCloseable> closeables) {
        this.id = s.id;
        this.settings = s;
        this.signing = signing;
        this.decryption = decryption;
        this.coreSigning = coreSigning;
        this.coreDecryption = coreDecryption;
        this.tokens = tokens;
        this.iopTokens = iopTokens;
        this.linkedAAs = linkedAAs;
        this.coreEntityHeader = coreEntityHeader;
        this.closeables = closeables;
    }

    /** What a tenant needs from the gateway to load. */
    public record Context(Config config, Roles.Mode mode, boolean multiTenant, Store cache, Http http) {}

    /**
     * Loads an entity: file keys are read now; keys from the core, tokens and an API {@code linkedAAs}
     * list each start on their own schedule, with the first fetch made now.
     * {@code kidOwner} names the other loaded entity that already uses a decryption {@code kid}, or
     * null. Throws when a key file cannot be read.
     */
    public static Tenant load(Context ctx, EntitySettings s, Function<String, String> kidOwner) throws Exception {
        Config c = ctx.config();
        List<AutoCloseable> closeables = new ArrayList<>();
        Map<String, String> header = ctx.multiTenant() ? Map.of("Core-Entity-Id", s.id) : Map.of();

        KeyRing signing;
        if ("api".equals(s.signingKey.source)) {
            signing = new KeyRing(List.of());
        } else {
            signing = new KeyRing(List.of(new KeyRing.PrivKey(s.signingKey.kid, Pem.privateKey(Path.of(s.signingKey.file)),
                    s.signingKey.active == null || s.signingKey.active, date(s.signingKey.applied), date(s.signingKey.expiry))));
        }
        KeyRing decryption;
        if ("api".equals(s.decryptionKeys.source)) {
            decryption = new KeyRing(List.of());
        } else {
            List<KeyRing.PrivKey> dec = new ArrayList<>();
            for (Config.KeyFile k : s.decryptionKeys.keys) {
                dec.add(new KeyRing.PrivKey(k.kid, Pem.privateKey(Path.of(k.file)), k.active == null || k.active,
                        date(k.applied), date(k.expiry)));
            }
            decryption = new KeyRing(dec);
        }

        // Tokens: the access token in every mode; the IopToken in AA mode only.
        TokenService tokens = null;
        TokenService iopTokens = null;
        if (c.tokenService != null) {
            tokens = new TokenService(c.tokenService, s.credentialsFile, s.id, ctx.http());
            if (ctx.mode() == Roles.Mode.AA) {
                iopTokens = TokenService.iopToken(c.tokenService, s.credentialsFile, s.id, ctx.http());
            }
            if (ctx.cache() != null) {
                tokens.persistIn(ctx.cache());
                if (iopTokens != null) {
                    iopTokens.persistIn(ctx.cache());
                }
            }
        }

        // linkedAAs: persisted as linked/aas/<entity id>.
        LinkedAAs linked = new LinkedAAs();
        String linkedKey = "linked/aas/" + s.id;
        Store cache = ctx.cache();
        if (cache != null) {
            linked.onReplace(list -> {
                ObjectNode o = Json.object();
                o.set("linkedAAs", Json.MAPPER.valueToTree(list));
                cache.save(linkedKey, o);
            });
        }

        // a set holding another loaded entity's decryption kid is refused. A conflict in
        // the first set, fetched while loading, stops the entity from loading (see kidConflict()).
        java.util.concurrent.atomic.AtomicReference<String> loadConflict = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicBoolean loading = new java.util.concurrent.atomic.AtomicBoolean(true);
        Function<List<KeyRing.PrivKey>, String> guard = set -> {
            for (KeyRing.PrivKey k : set) {
                String owner = kidOwner.apply(k.kid());
                if (owner != null) {
                    String reason = "decryption key kid " + k.kid() + " is already used by entity " + owner;
                    if (loading.get()) {
                        loadConflict.compareAndSet(null, reason);
                    }
                    return reason;
                }
            }
            return null;
        };

        CoreKeys coreSigning = null;
        CoreKeys coreDecryption = null;
        Duration coreTimeout = Duration.ofSeconds(s.core.timeoutSeconds);
        try {
            if ("api".equals(s.signingKey.source)) {
                coreSigning = new CoreKeys("signing", signing, s.keyUrl("signing"), s.secret("signingKey.token"),
                        ctx.http(), coreTimeout, s.id, header, set -> null);
                start(coreSigning, s.signingKey.refreshSeconds, closeables);
            }
            if ("api".equals(s.decryptionKeys.source)) {
                coreDecryption = new CoreKeys("decryption", decryption, s.keyUrl("decryption"), s.secret("decryptionKeys.token"),
                        ctx.http(), coreTimeout, s.id, header, guard);
                start(coreDecryption, s.decryptionKeys.refreshSeconds, closeables);
            }
            if ("api".equals(s.linkedAAs.source)) {
                if (cache != null) {
                    cache.load(linkedKey).ifPresent(snap -> {
                        try {
                            linked.set(LinkedAAs.parse(Json.bytes(snap.data())));
                        } catch (RuntimeException e) {
                            LOG.atWarn().addKeyValue("entity", s.id).log("persisted linkedAAs malformed; ignored");
                        }
                    });
                }
                String url = s.linkedAAsUrl();
                String token = s.secret("linkedAAs.token");
                Periodic p = new Periodic("linkedAAs-" + s.id, () -> linked.pull(url, token, header, ctx.http(), coreTimeout),
                        s.linkedAAs.refreshSeconds, 30);
                closeables.add(p);
                p.start();
            } else {
                linked.set(s.linkedAAs.aas);
                if (cache != null) {
                    ObjectNode o = Json.object();
                    o.set("linkedAAs", Json.MAPPER.valueToTree(linked.get()));
                    cache.save(linkedKey, o);
                }
            }
        } catch (RuntimeException e) {
            closeAll(closeables);
            throw e;
        }
        Tenant t = new Tenant(s, signing, decryption, coreSigning, coreDecryption, tokens, iopTokens, linked, header,
                closeables);
        t.kidConflict = loadConflict.get();
        loading.set(false);
        return t;
    }

    private static void start(CoreKeys k, int refresh, List<AutoCloseable> closeables) {
        Periodic p = new Periodic("keys", k::pull, refresh, () -> k.retrySeconds(refresh));
        closeables.add(p);
        p.start();
    }

    /** Set when the first decryption key set fetched while loading held another entity's {@code kid}. */
    public String kidConflict() {
        return kidConflict;
    }

    /**
     * True when this version can take over from a previous one: signing and decryption keys, a
     * {@code linkedAAs} list and, with {@code tokenService}, an access token (and the IopToken in AA mode).
     */
    public boolean ready() {
        if (!signing.loaded() || !decryption.loaded() || !linkedAAs.loaded()) {
            return false;
        }
        if (tokens != null && tokens.get().isEmpty()) {
            return false;
        }
        return iopTokens == null || iopTokens.get().isPresent();
    }

    public String corePrefix() {
        return settings.core.pathPrefix;
    }

    public String coreBaseUrl() {
        String b = settings.core.baseUrl;
        while (b.endsWith("/")) {
            b = b.substring(0, b.length() - 1);
        }
        return b;
    }

    public Duration coreTimeout() {
        return Duration.ofSeconds(settings.core.timeoutSeconds);
    }

    /** {@code core.token} towards the core, or null. */
    public String coreToken() {
        return settings.secret("core.token");
    }

    /** The internal API token the core sends, or null. */
    public String gwApiToken() {
        return settings.secret("gwApi.token");
    }

    /** Testing only: the fixed api-key used without the token service, or null. */
    public String outboundApiKey() {
        return settings.secret("outboundApiKey");
    }

    /** Testing only: the fixed AIG token used without the token service, or null. */
    public String aigToken() {
        return settings.secret("aigToken");
    }

    public Config.HopPreference hopPreference() {
        return settings.hopPreference;
    }

    /** Headers for a request to the core: {@code extra} plus {@code Core-Entity-Id} in multi-tenant mode. */
    public Map<String, String> coreHeaders(Map<String, String> extra) {
        Map<String, String> h = new LinkedHashMap<>(coreEntityHeader);
        h.putAll(extra);
        return h;
    }

    /** Unloading drops the keys and tokens from memory; calls in progress keep their references. */
    @Override
    public void close() {
        closeAll(closeables);
    }

    private static void closeAll(List<AutoCloseable> closeables) {
        for (AutoCloseable c : closeables) {
            try {
                c.close();
            } catch (Exception ignored) {
                // unloading
            }
        }
    }

    private static Instant date(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return CoreKeys.date(s, "key date");
    }
}
