package org.sahamati.iopgw.gateway;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.crypto.KeyRing;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.model.Roles.Mode;
import org.sahamati.iopgw.obs.Audit;
import org.sahamati.iopgw.obs.Stats;
import org.sahamati.iopgw.sources.Aig;
import org.sahamati.iopgw.sources.ApiKeyVerifier;
import org.sahamati.iopgw.sources.Registry;
import org.sahamati.iopgw.sources.TokenService;
import org.sahamati.iopgw.tenant.Tenant;
import org.sahamati.iopgw.tenant.Tenants;

import java.time.Duration;
import java.util.Optional;

/**
 * Everything a running gateway needs, shared by the /iop and internal API handlers: the shared
 * data (entity registry, AIG, token issuer keys) and the loaded entities.
 */
public final class Gateway {
    public final Config config;
    public final Mode mode;
    public final String jwsAlg;
    public final Registry registry;
    public final Aig aig;
    public final ApiKeyVerifier apiKeys;
    public final Tenants tenants;
    public final Http http;
    public final Audit audit;
    public final Stats stats;

    public Gateway(Config config, Registry registry, Aig aig, ApiKeyVerifier apiKeys, Tenants tenants, Http http,
                   Audit audit, Stats stats) {
        this.config = config;
        this.mode = Mode.valueOf(config.mode);
        this.jwsAlg = config.jws.algorithm;
        this.registry = registry;
        this.aig = aig;
        this.apiKeys = apiKeys;
        this.tenants = tenants;
        this.http = http;
        this.audit = audit;
        this.stats = stats;
    }

    public boolean multiTenant() {
        return tenants.multiTenant();
    }

    /** Single-tenant mode: the one entity. */
    public Tenant single() {
        return tenants.only().orElseThrow();
    }

    /** The entity named in audit and stats records: the call's entity, else {@code -} (multi-tenant) or the one entity. */
    public String recordId(Tenant t) {
        if (t != null) {
            return t.id;
        }
        if (multiTenant()) {
            return Stats.UNKNOWN;
        }
        return tenants.only().map(x -> x.id).orElse(Stats.UNKNOWN);
    }

    public String gwVer() {
        return config.gwApi != null ? config.gwApi.ver : "1.1.0";
    }

    public Duration forwardingTimeout() {
        return Duration.ofSeconds(config.forwarding.timeoutSeconds);
    }

    public long maxUpstream() {
        return config.limits.maxUpstreamBytes;
    }

    /**
     * The role api-key on an {@code /iop} call of entity {@code t} to {@code hop}: the hop's own
     * {@code outboundApiKey}, else the entity's {@code outboundApiKey} (testing), else the IopToken in
     * AA mode or the access token in FIU and FIP mode.
     */
    public Optional<String> outboundKey(Tenant t, Registry.Entity hop) {
        return key(t, hop, mode == Mode.AA ? t.iopTokens : t.tokens);
    }

    /**
     * The api-key on a Direct API call of entity {@code t} to {@code entity}: its own
     * {@code outboundApiKey}, else the entity's {@code outboundApiKey} (testing), else the access token.
     */
    public Optional<String> directKey(Tenant t, Registry.Entity entity) {
        return key(t, entity, t.tokens);
    }

    private static Optional<String> key(Tenant t, Registry.Entity peer, TokenService tokens) {
        if (peer.outboundApiKey() != null) {
            return Optional.of(peer.outboundApiKey());
        }
        String fixed = t.outboundApiKey();
        if (fixed != null) {
            return Optional.of(fixed);
        }
        return tokens == null ? Optional.empty() : tokens.get();
    }

    /** Signs {@code body} with a usable signing key of {@code t} (detached JWS), or fails with a bare 500. */
    public String signDetached(Tenant t, byte[] body) throws GwError {
        KeyRing.PrivKey k = t.signing.pickSigning().orElseThrow(() -> new GwError(500, GwError.INTERNAL, "unable to sign"));
        try {
            return Jose.signDetached(body, k, jwsAlg);
        } catch (Jose.JoseException e) {
            throw new GwError(500, GwError.INTERNAL, "unable to sign");
        }
    }

    public String signCompact(Tenant t, byte[] body) throws GwError {
        KeyRing.PrivKey k = t.signing.pickSigning().orElseThrow(() -> new GwError(500, GwError.INTERNAL, "unable to sign payload"));
        try {
            return Jose.signCompact(body, k, jwsAlg);
        } catch (Jose.JoseException e) {
            throw new GwError(500, GwError.INTERNAL, "unable to sign payload");
        }
    }

    /** Compact JSON {@code {"type","id"}} for party headers. */
    public static String party(String type, String id) {
        ObjectNode o = Json.object();
        o.put("type", type);
        o.put("id", id);
        return o.toString();
    }
}
