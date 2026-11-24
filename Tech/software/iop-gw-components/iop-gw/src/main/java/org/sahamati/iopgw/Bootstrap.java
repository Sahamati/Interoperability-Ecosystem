package org.sahamati.iopgw;

import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.crypto.Pem;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.gateway.Gateway;
import org.sahamati.iopgw.gateway.GwApiHandler;
import org.sahamati.iopgw.gateway.IopHandler;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.model.Roles;
import org.sahamati.iopgw.obs.Audit;
import org.sahamati.iopgw.obs.Stats;
import org.sahamati.iopgw.server.GatewayServer;
import org.sahamati.iopgw.sources.Aig;
import org.sahamati.iopgw.sources.ApiKeyVerifier;
import org.sahamati.iopgw.sources.CacheCodec;
import org.sahamati.iopgw.sources.CoreKeys;
import org.sahamati.iopgw.tenant.Tenant;
import org.sahamati.iopgw.tenant.TenantManager;
import org.sahamati.iopgw.tenant.Tenants;
import org.sahamati.iopgw.sources.IssuerKeys;
import org.sahamati.iopgw.sources.Store;
import org.sahamati.iopgw.sources.Periodic;
import org.sahamati.iopgw.sources.Registry;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/** Builds and starts a gateway from a validated configuration. */
public final class Bootstrap {
    private Bootstrap() {}

    /** A running gateway. */
    public static final class Running implements AutoCloseable {
        public final Gateway gateway;
        public final GatewayServer server;
        private final List<AutoCloseable> closeables;

        Running(Gateway gateway, GatewayServer server, List<AutoCloseable> closeables) {
            this.gateway = gateway;
            this.server = server;
            this.closeables = closeables;
        }

        @Override
        public void close() {
            server.close();
            // reverse start order: the last stats records are written while every entity is still
            // loaded, then the entities, the shared sources and the cache are closed
            for (AutoCloseable c : closeables.reversed()) {
                try {
                    c.close();
                } catch (Exception ignored) {
                    // shutting down
                }
            }
        }
    }

    public static Running start(Config c) throws Exception {
        return start(c, new Http());
    }

    public static Running start(Config c, Http http) throws Exception {
        return start(c, http, System.getenv());
    }

    /** {@code env} resolves the {@code ${ENV}} references of entity files (multi-tenant mode). */
    public static Running start(Config c, Http http, Map<String, String> env) throws Exception {
        Roles.Mode mode = Roles.Mode.valueOf(c.mode);
        boolean multi = c.isMultiTenant();
        List<AutoCloseable> closeables = new ArrayList<>();
        try {
            return start(c, http, env, mode, multi, closeables);
        } catch (Exception e) {
            for (int i = closeables.size() - 1; i >= 0; i--) {
                try {
                    closeables.get(i).close();
                } catch (Exception ignored) {
                    // failed start-up
                }
            }
            throw e;
        }
    }

    private static Running start(Config c, Http http, Map<String, String> env, Roles.Mode mode, boolean multi,
                                 List<AutoCloseable> closeables) throws Exception {
        // Persistent cache: a store that cannot be opened stops start-up.
        Store store = null;
        if (c.cache != null && c.cache.dir != null) {
            store = Store.open(Path.of(c.cache.dir), c.cache.engine);
            closeables.add(store);
        }
        final Store cache = store;

        Tenants tenants = new Tenants(multi);
        // The Central Registry and AIG are loaded with the access token of one loaded entity that
        // has a usable token, or with cr.token and an entity's aigToken without tokenService.
        Supplier<Optional<String>> anyAccessToken = () -> {
            for (Tenant t : tenants.all()) {
                if (t.tokens != null) {
                    Optional<String> tok = t.tokens.get();
                    if (tok.isPresent()) {
                        return tok;
                    }
                }
            }
            return Optional.empty();
        };
        Supplier<Optional<String>> anyAigToken = () -> {
            for (Tenant t : tenants.all()) {
                if (t.aigToken() != null) {
                    return Optional.of(t.aigToken());
                }
            }
            return anyAccessToken.get();
        };

        // Entity registry
        Map<String, String> outbound = new LinkedHashMap<>();
        for (Config.EntityConf e : c.entities) {
            String v = c.secret("entity:" + e.id + ".outboundApiKey");
            if (v != null) {
                outbound.put(e.id, v);
            }
        }
        Registry registry;
        Periodic crLoad = null;
        Instant crSavedAt = null;
        if ("api".equals(c.cr.source)) {
            Map<String, Registry.Override> overrides = new LinkedHashMap<>();
            for (Config.EntityConf e : c.entities) {
                overrides.put(e.id, new Registry.Override(e.baseUrl, outbound.get(e.id)));
            }
            registry = Registry.fromCentralRegistry(overrides);
            if (cache != null) {
                var snap = cache.load("cr/entities");
                if (snap.isPresent()) {
                    try {
                        registry.restore(CacheCodec.entities(snap.get().data()));
                        crSavedAt = snap.get().savedAt();
                    } catch (RuntimeException e) {
                        org.slf4j.LoggerFactory.getLogger(Bootstrap.class).atWarn().log("persisted CR lists malformed; ignored");
                    }
                }
                registry.onReplace(list -> cache.save("cr/entities", CacheCodec.entities(list)));
            }
            String crToken = c.secret("cr.token");
            crLoad = new Periodic("cr", () -> registry.loadFromCr(c.cr, mode, http,
                    () -> crToken != null ? Optional.of(crToken) : anyAccessToken.get()),
                    c.cr.refreshSeconds, c.cr.retrySeconds);
            closeables.add(crLoad);
        } else {
            registry = Registry.fromConfig(c.entities, outbound);
            if (cache != null) {
                cache.save("cr/entities", CacheCodec.entities(registry.rawEntities()));
            }
        }

        // AIG
        Aig aig = new Aig(mode);
        if (cache != null) {
            aig.onReplace(g -> cache.save("aig/graph", g));
        }
        Periodic aigLoad = null;
        Instant aigSavedAt = null;
        if ("api".equals(c.aigSource)) {
            if (cache != null) {
                var snap = cache.load("aig/graph");
                if (snap.isPresent()) {
                    try {
                        aig.restore(snap.get().data());
                        aigSavedAt = snap.get().savedAt();
                    } catch (RuntimeException e) {
                        org.slf4j.LoggerFactory.getLogger(Bootstrap.class).atWarn().log("persisted AIG graph malformed; ignored");
                    }
                }
            }
            aigLoad = new Periodic("aig", () -> aig.loadFromApi(c, http, anyAigToken), c.aigRefreshSeconds, c.aigRetrySeconds);
            closeables.add(aigLoad);
        } else if (c.aig != null) {
            aig.loadConfigured(c.aig);
        }

        // Api-key checking: issuer keys from PEM files or the issuer's JWKS URL.
        IssuerKeys issuerKeys;
        if (c.apiKey.issuerKeysUrl != null) {
            issuerKeys = IssuerKeys.fromJwks(c.apiKey.issuerKeysUrl, http, Duration.ofSeconds(30));
            Instant savedAt = null;
            if (cache != null) {
                var snap = cache.load("issuer/keys");
                if (snap.isPresent()) {
                    try {
                        issuerKeys.restore(CacheCodec.pubKeys(snap.get().data()));
                        savedAt = snap.get().savedAt();
                    } catch (RuntimeException e) {
                        org.slf4j.LoggerFactory.getLogger(Bootstrap.class).atWarn().log("persisted issuer keys malformed; ignored");
                    }
                }
                issuerKeys.onReplace(keys -> cache.save("issuer/keys", CacheCodec.pubKeys(keys)));
            }
            long refresh = c.apiKey.issuerKeysRefreshSeconds;
            Periodic p = new Periodic("issuerKeys", issuerKeys::fetch, refresh, () -> issuerKeys.retrySeconds(refresh));
            closeables.add(p);
            p.startRestored(savedAt);
        } else {
            List<PubKey> fixed = new ArrayList<>();
            for (String f : c.apiKey.issuerPublicKeys) {
                fixed.add(new PubKey(null, Pem.publicKey(Path.of(f))));
            }
            issuerKeys = IssuerKeys.fixed(fixed);
        }
        Map<String, String> staticKeys = new LinkedHashMap<>();
        c.secrets.forEach((name, value) -> {
            if (name.startsWith("apiKey.static:")) {
                staticKeys.put(value, name.substring("apiKey.static:".length()));
            }
        });
        ApiKeyVerifier apiKeys = new ApiKeyVerifier(c.apiKey, issuerKeys, staticKeys);

        // The entities: the one in the main file, or the entity folder (multi-tenant mode).
        Tenant.Context tctx = new Tenant.Context(c, mode, multi, cache, http);
        if (multi) {
            TenantManager manager = new TenantManager(c, env, tenants, tctx);
            closeables.add(manager);
            manager.start();
        } else {
            Tenant t = Tenant.load(tctx, c.single, kid -> null);
            tenants.put(t);
            closeables.add(t);
        }

        // Shared loads start once the entities can supply a token.
        if (crLoad != null) {
            crLoad.startRestored(crSavedAt);
        }
        if (aigLoad != null) {
            aigLoad.startRestored(aigSavedAt);
        }

        Audit audit = new Audit(c.logging.audit == null || c.logging.audit, c.mode);
        Stats stats = new Stats(c.mode, c.logging.statsIntervalSeconds, () -> {
            List<String> ids = tenants.ids();
            if (multi) {
                ids.add(Stats.UNKNOWN);
            }
            return ids;
        });
        stats.start();

        Gateway gw = new Gateway(c, registry, aig, apiKeys, tenants, http, audit, stats);
        GatewayServer server = new GatewayServer(c, new IopHandler(gw), new GwApiHandler(gw));
        server.start();
        closeables.add(stats);
        return new Running(gw, server, closeables);
    }

    private static Instant date(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return CoreKeys.date(s, "key date");
    }
}
