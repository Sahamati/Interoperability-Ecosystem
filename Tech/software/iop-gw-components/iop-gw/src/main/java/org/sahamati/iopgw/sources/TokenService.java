package org.sahamati.iopgw.sources;

import com.fasterxml.jackson.databind.JsonNode;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * One token from the Sahamati token service, generated at {@code tokenService.path}: the
 * <b>access token</b> (every mode; Direct API api-key, CR and AIG bearer, and the role api-key on
 * {@code /iop} calls in FIU and FIP mode) and, in AA mode only, the <b>IopToken</b> (the same call
 * with the form field {@code use=iop}; the role api-key on every {@code /iop} call), refreshed
 * independently. The entity secret is read from the mounted credentials file on every
 * generation; neither the secret nor the token is ever logged.
 */
public final class TokenService {
    private static final Logger LOG = LoggerFactory.getLogger(TokenService.class);

    private record Token(String value, Instant issuedAt, Instant expiresAt) {}

    private final Config.TokenServiceConf conf;
    private final String credentialsFile;
    private final String selfId;
    private final Http http;
    private final String use; // the form field "use"; null for the access token
    private final String name; // "token" (access token) or "iopToken"
    private volatile Token token;
    private volatile Instant lastFailure = Instant.EPOCH;
    private volatile Store store; // null without cache.dir

    /** Key of the persisted token. */
    public String cacheKey() {
        return name + "/" + selfId;
    }

    /**
     * Persists every new token in {@code store} and restores a persisted one now: an
     * expired token is never restored; one within its refresh margin is regenerated at first use.
     */
    public synchronized void persistIn(Store s) {
        this.store = s;
        s.load(cacheKey()).ifPresent(snap -> {
            try {
                JsonNode d = snap.data();
                Token t = new Token(d.get("token").asText(), Instant.parse(d.get("issuedAt").asText()),
                        Instant.parse(d.get("expiresAt").asText()));
                if (Instant.now().isBefore(t.expiresAt)) {
                    token = t;
                    LOG.atInfo().addKeyValue("token", name).log("token restored from the cache");
                }
            } catch (Exception e) {
                LOG.atWarn().addKeyValue("token", name).log("persisted token malformed; ignored");
            }
        });
    }

    private void save(Token t) {
        Store s = store;
        if (s != null) {
            var o = Json.object();
            o.put("token", t.value);
            o.put("issuedAt", t.issuedAt.toString());
            o.put("expiresAt", t.expiresAt.toString());
            s.save(cacheKey(), o);
        }
    }

    /**
     * The access token of entity {@code selfId}: generated at {@code tokenService.path} with the
     * entity's {@code credentialsFile}, persisted as {@code token/<entity id>}.
     */
    public TokenService(Config.TokenServiceConf conf, String credentialsFile, String selfId, Http http) {
        this(conf, credentialsFile, selfId, http, null, "token");
    }

    /** A token generated at {@code tokenService.path} with the form field {@code use} (none when null). */
    private TokenService(Config.TokenServiceConf conf, String credentialsFile, String selfId, Http http, String use, String name) {
        this.conf = conf;
        this.credentialsFile = credentialsFile;
        this.selfId = selfId;
        this.http = http;
        this.use = use;
        this.name = name;
    }

    /** The IopToken (AA mode): {@code tokenService.path} with {@code use=iop}, persisted as {@code iopToken/<entity id>}. */
    public static TokenService iopToken(Config.TokenServiceConf conf, String credentialsFile, String selfId, Http http) {
        return new TokenService(conf, credentialsFile, selfId, http, "iop", "iopToken");
    }

    /** True while a token is held that has not expired (no generation is attempted). */
    public boolean held() {
        Token t = token;
        return t != null && Instant.now().isBefore(t.expiresAt);
    }

    /** The current access token, regenerating it when due. Empty when no usable token exists. */
    public synchronized Optional<String> get() {
        Instant now = Instant.now();
        Token t = token;
        if (t == null || refreshDue(t, now)) {
            if (Duration.between(lastFailure, now).getSeconds() >= 10 || t == null && lastFailure == Instant.EPOCH) {
                Token fresh = generate();
                if (fresh != null) {
                    token = fresh;
                    t = fresh;
                    save(fresh);
                } else {
                    lastFailure = now;
                }
            }
        }
        if (t == null || !now.isBefore(t.expiresAt)) {
            return Optional.empty();
        }
        return Optional.of(t.value);
    }

    private boolean refreshDue(Token t, Instant now) {
        long life = Duration.between(t.issuedAt, t.expiresAt).getSeconds();
        long margin = conf.refreshBeforeSeconds;
        Instant due = life <= margin ? t.issuedAt.plusSeconds(life / 2) : t.expiresAt.minusSeconds(margin);
        return !now.isBefore(due);
    }

    private Token generate() {
        String secret;
        try {
            JsonNode creds = Json.MAPPER.readTree(Files.readAllBytes(Path.of(credentialsFile)));
            String entityId = Json.text(creds, "entityId");
            secret = Json.text(creds, "entitySecret");
            if (!selfId.equals(entityId)) {
                LOG.atError().addKeyValue("entity", selfId).log("credentials file is for another entity; no token generated");
                return null;
            }
            if (secret == null || secret.isBlank()) {
                LOG.atError().addKeyValue("entity", selfId).log("credentials file has no entitySecret; no token generated");
                return null;
            }
        } catch (Exception e) {
            LOG.atError().addKeyValue("entity", selfId).addKeyValue("error", e.getClass().getSimpleName()).log("credentials file unreadable");
            return null;
        }
        String form = "id=" + URLEncoder.encode(selfId, StandardCharsets.UTF_8)
                + "&secret=" + URLEncoder.encode(secret, StandardCharsets.UTF_8)
                + (use == null ? "" : "&use=" + URLEncoder.encode(use, StandardCharsets.UTF_8));
        try {
            Http.Response r = http.send("POST", conf.baseUrl + conf.path,
                    Map.of("Content-Type", "application/x-www-form-urlencoded"),
                    form.getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(conf.timeoutSeconds), 1 << 20);
            JsonNode body = Json.parseObject(r.body());
            if (r.status() != 200 || body == null) {
                LOG.atError().addKeyValue("entity", selfId).addKeyValue("token", name).addKeyValue("status", r.status())
                        .addKeyValue("errorCode", Json.text(body, "errorCode"))
                        .addKeyValue("errorMsg", Json.text(body, "errorMsg"))
                        .log("token service refused");
                return null;
            }
            String access = Json.text(body, "accessToken");
            JsonNode exp = body.get("expiresIn");
            if (access == null || exp == null || !exp.canConvertToLong() || exp.asLong() <= 0) {
                LOG.atError().addKeyValue("status", r.status()).log("token service response without accessToken or expiresIn");
                return null;
            }
            Instant now = Instant.now();
            return new Token(access, now, now.plusSeconds(exp.asLong()));
        } catch (Http.NoResponse e) {
            LOG.atError().addKeyValue("entity", selfId).addKeyValue("token", name).addKeyValue("noResponse", e.kind).log("token service unavailable");
            return null;
        }
    }
}
