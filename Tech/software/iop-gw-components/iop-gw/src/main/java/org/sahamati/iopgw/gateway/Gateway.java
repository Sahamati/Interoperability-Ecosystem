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
import org.sahamati.iopgw.sources.LinkedAAs;
import org.sahamati.iopgw.sources.Registry;
import org.sahamati.iopgw.sources.TokenService;

import java.time.Duration;
import java.util.Optional;

/** Everything a running gateway needs, shared by the /iop and internal API handlers. */
public final class Gateway {
    public final Config config;
    public final Mode mode;
    public final String selfId;
    public final String jwsAlg;
    public final KeyRing signing;
    public final KeyRing decryption;
    public final Registry registry;
    public final Aig aig;
    public final LinkedAAs linkedAAs;
    public final ApiKeyVerifier apiKeys;
    public final TokenService tokenService; // the access token; null without tokenService
    public final TokenService iopTokenService; // the IopToken; null without tokenService
    public final Http http;
    public final Audit audit;
    public final Stats stats;
    /** Keys from the core; null with source file. Set by Bootstrap. */
    public volatile org.sahamati.iopgw.sources.CoreKeys coreSigning;
    public volatile org.sahamati.iopgw.sources.CoreKeys coreDecryption;

    public Gateway(Config config, KeyRing signing, KeyRing decryption, Registry registry, Aig aig, LinkedAAs linkedAAs,
                   ApiKeyVerifier apiKeys, TokenService tokenService, TokenService iopTokenService, Http http, Audit audit, Stats stats) {
        this.config = config;
        this.mode = Mode.valueOf(config.mode);
        this.selfId = config.self.id;
        this.jwsAlg = config.jws.algorithm;
        this.signing = signing;
        this.decryption = decryption;
        this.registry = registry;
        this.aig = aig;
        this.linkedAAs = linkedAAs;
        this.apiKeys = apiKeys;
        this.tokenService = tokenService;
        this.iopTokenService = iopTokenService;
        this.http = http;
        this.audit = audit;
        this.stats = stats;
    }

    public String corePrefix() {
        return config.core.pathPrefix;
    }

    public String gwVer() {
        return config.gwApi != null ? config.gwApi.ver : "2.0.0";
    }

    public Duration forwardingTimeout() {
        return Duration.ofSeconds(config.forwarding.timeoutSeconds);
    }

    public Duration coreTimeout() {
        return Duration.ofSeconds(config.core.timeoutSeconds);
    }

    public long maxUpstream() {
        return config.limits.maxUpstreamBytes;
    }

    /**
     * The role api-key on an {@code /iop} call to {@code hop}: the hop's own
     * {@code outboundApiKey}, else {@code self.outboundApiKey} (testing), else the IopToken.
     */
    public Optional<String> outboundKey(Registry.Entity hop) {
        return key(hop, iopTokenService);
    }

    /**
     * The api-key on a Direct API call to {@code entity}: its own
     * {@code outboundApiKey}, else {@code self.outboundApiKey} (testing), else the access token.
     */
    public Optional<String> directKey(Registry.Entity entity) {
        return key(entity, tokenService);
    }

    private Optional<String> key(Registry.Entity peer, TokenService tokens) {
        if (peer.outboundApiKey() != null) {
            return Optional.of(peer.outboundApiKey());
        }
        String fixed = config.secret("self.outboundApiKey");
        if (fixed != null) {
            return Optional.of(fixed);
        }
        return tokens == null ? Optional.empty() : tokens.get();
    }

    /** Signs {@code body} with a usable signing key (detached JWS), or fails with a bare 500. */
    public String signDetached(byte[] body) throws GwError {
        KeyRing.PrivKey k = signing.pickSigning().orElseThrow(() -> new GwError(500, GwError.INTERNAL, "unable to sign"));
        try {
            return Jose.signDetached(body, k, jwsAlg);
        } catch (Jose.JoseException e) {
            throw new GwError(500, GwError.INTERNAL, "unable to sign");
        }
    }

    public String signCompact(byte[] body) throws GwError {
        KeyRing.PrivKey k = signing.pickSigning().orElseThrow(() -> new GwError(500, GwError.INTERNAL, "unable to sign payload"));
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
