package org.sahamati.iopgw;

import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.crypto.KeyRing;
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
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.sources.ApiKeyVerifier;
import org.sahamati.iopgw.sources.CacheCodec;
import org.sahamati.iopgw.sources.CoreKeys;
import org.sahamati.iopgw.sources.IssuerKeys;
import org.sahamati.iopgw.sources.Store;
import org.sahamati.iopgw.sources.LinkedAAs;
import org.sahamati.iopgw.sources.Periodic;
import org.sahamati.iopgw.sources.Registry;
import org.sahamati.iopgw.sources.TokenService;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
            for (AutoCloseable c : closeables) {
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
        Roles.Mode mode = Roles.Mode.valueOf(c.mode);
        List<AutoCloseable> closeables = new ArrayList<>();

        // Signing and decryption keys: from mounted PEM files, or from the core.
        KeyRing signing;
        if ("api".equals(c.self.signingKey.source)) {
            signing = new KeyRing(List.of());
        } else {
            signing = new KeyRing(List.of(new KeyRing.PrivKey(c.self.signingKey.kid,
                    Pem.privateKey(Path.of(c.self.signingKey.file)),
                    c.self.signingKey.active == null || c.self.signingKey.active,
                    date(c.self.signingKey.applied), date(c.self.signingKey.expiry))));
        }
        KeyRing decryption;
        if ("api".equals(c.self.decryptionKeys.source)) {
            decryption = new KeyRing(List.of());
        } else {
            List<KeyRing.PrivKey> dec = new ArrayList<>();
            for (Config.KeyFile k : c.self.decryptionKeys.keys) {
                dec.add(new KeyRing.PrivKey(k.kid, Pem.privateKey(Path.of(k.file)), k.active == null || k.active,
                        date(k.applied), date(k.expiry)));
            }
            decryption = new KeyRing(dec);
        }

        // Persistent cache: a store that cannot be opened stops start-up.
        Store store = null;
        if (c.cache != null && c.cache.dir != null) {
            store = Store.open(Path.of(c.cache.dir), c.cache.engine);
            closeables.add(store);
        }
        final Store cache = store;

        // Two tokens: the access token (Direct API, CR, AIG) and the IopToken (/iop calls).
        TokenService tokens = c.tokenService == null ? null : new TokenService(c.tokenService, c.self.id, http);
        TokenService iopTokens = c.tokenService == null ? null : TokenService.iopToken(c.tokenService, c.self.id, http);
        if (tokens != null && cache != null) {
            tokens.persistIn(cache);
            iopTokens.persistIn(cache);
        }

        // Entity registry
        Map<String, String> outbound = new LinkedHashMap<>();
        for (Config.EntityConf e : c.entities) {
            String v = c.secret("entity:" + e.id + ".outboundApiKey");
            if (v != null) {
                outbound.put(e.id, v);
            }
        }
        Registry registry;
        if ("api".equals(c.cr.source)) {
            Map<String, Registry.Override> overrides = new LinkedHashMap<>();
            for (Config.EntityConf e : c.entities) {
                overrides.put(e.id, new Registry.Override(e.baseUrl, outbound.get(e.id)));
            }
            registry = Registry.fromCentralRegistry(overrides);
            Instant savedAt = null;
            if (cache != null) {
                var snap = cache.load("cr/entities");
                if (snap.isPresent()) {
                    try {
                        registry.restore(CacheCodec.entities(snap.get().data()));
                        savedAt = snap.get().savedAt();
                    } catch (RuntimeException e) {
                        org.slf4j.LoggerFactory.getLogger(Bootstrap.class).atWarn().log("persisted CR lists malformed; ignored");
                    }
                }
                registry.onReplace(list -> cache.save("cr/entities", CacheCodec.entities(list)));
            }
            String crToken = c.secret("cr.token");
            Periodic p = new Periodic("cr", () -> registry.loadFromCr(c.cr, mode, http,
                    () -> crToken != null ? java.util.Optional.of(crToken) : tokens.get()),
                    c.cr.refreshSeconds, c.cr.retrySeconds);
            closeables.add(p);
            p.startRestored(savedAt);
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
        if ("api".equals(c.aigSource)) {
            Instant savedAt = null;
            if (cache != null) {
                var snap = cache.load("aig/graph");
                if (snap.isPresent()) {
                    try {
                        aig.restore(snap.get().data());
                        savedAt = snap.get().savedAt();
                    } catch (RuntimeException e) {
                        org.slf4j.LoggerFactory.getLogger(Bootstrap.class).atWarn().log("persisted AIG graph malformed; ignored");
                    }
                }
            }
            String aigToken = c.secret("aigToken");
            Periodic p = new Periodic("aig", () -> aig.loadFromApi(c, http,
                    () -> aigToken != null ? java.util.Optional.of(aigToken) : tokens.get()),
                    c.aigRefreshSeconds, c.aigRetrySeconds);
            closeables.add(p);
            p.startRestored(savedAt);
        } else if (c.aig != null) {
            aig.loadConfigured(c.aig);
        }

        // linkedAAs
        LinkedAAs linked = new LinkedAAs();
        if ("api".equals(c.linkedAAs.source) && cache != null) {
            cache.load("linkedAAs/list").ifPresent(snap -> {
                try {
                    linked.set(LinkedAAs.parse(Json.bytes(snap.data())));
                } catch (RuntimeException e) {
                    org.slf4j.LoggerFactory.getLogger(Bootstrap.class).atWarn().log("persisted linkedAAs malformed; ignored");
                }
            });
            linked.onReplace(list -> {
                var o = Json.object();
                o.set("linkedAAs", Json.MAPPER.valueToTree(list));
                cache.save("linkedAAs/list", o);
            });
        }
        if ("api".equals(c.linkedAAs.source)) {
            String url = c.linkedAAs.url != null ? c.linkedAAs.url : c.core.baseUrl + c.core.pathPrefix + "/linkedAAs";
            String token = c.secret("linkedAAs.token");
            Periodic p = new Periodic("linkedAAs", () -> linked.pull(url, token, http, Duration.ofSeconds(c.core.timeoutSeconds)),
                    c.linkedAAs.refreshSeconds, 30);
            p.start();
            closeables.add(p);
        } else if (c.linkedAAs.aas != null) {
            linked.set(c.linkedAAs.aas);
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

        Audit audit = new Audit(c.logging.audit == null || c.logging.audit, c.self.id, c.mode);
        Stats stats = new Stats(c.self.id, c.mode, c.logging.statsIntervalSeconds);
        stats.start();

        Gateway gw = new Gateway(c, signing, decryption, registry, aig, linked, apiKeys, tokens, iopTokens, http, audit, stats);
        // Keys from the core: fetched at start-up and every refreshSeconds; while
        // none is loaded the fetch is retried every 30 s. Never persisted.
        if ("api".equals(c.self.signingKey.source)) {
            gw.coreSigning = coreKeys(c, "signing", signing, c.self.signingKey.refreshSeconds, http, closeables);
        }
        if ("api".equals(c.self.decryptionKeys.source)) {
            gw.coreDecryption = coreKeys(c, "decryption", decryption, c.self.decryptionKeys.refreshSeconds, http, closeables);
        }
        GatewayServer server = new GatewayServer(c, new IopHandler(gw), new GwApiHandler(gw));
        server.start();
        closeables.add(stats);
        return new Running(gw, server, closeables);
    }

    private static CoreKeys coreKeys(Config c, String kind, KeyRing ring, int refresh, Http http, List<AutoCloseable> closeables) {
        CoreKeys k = new CoreKeys(kind, ring, c.keyUrl(kind), c.secret("self." + kind + "Key" + ("signing".equals(kind) ? "" : "s") + ".token"),
                http, Duration.ofSeconds(c.core.timeoutSeconds));
        Periodic p = new Periodic(kind + "Keys", k::pull, refresh, () -> k.retrySeconds(refresh));
        closeables.add(p);
        p.start();
        return k;
    }

    private static Instant date(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return CoreKeys.date(s, "key date");
    }
}
