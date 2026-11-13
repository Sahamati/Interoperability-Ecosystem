package org.sahamati.iopgw.sources;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.sahamati.iopgw.crypto.Pem;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * The token issuer's public keys: from PEM files, or from the issuer's JWKS URL, fetched at
 * start-up, every {@code issuerKeysRefreshSeconds}, and again when a token names an unknown kid (at
 * most once a minute). Only RSA signing keys of at least 2048 bits with a kid are taken. A failed
 * fetch keeps the current keys; while none are loaded, api-keys are rejected and the fetch is
 * retried every 30 s.
 */
public final class IssuerKeys {
    private static final Logger LOG = LoggerFactory.getLogger(IssuerKeys.class);

    public static final long EMPTY_RETRY_SECONDS = 30;
    public static final long UNKNOWN_KID_INTERVAL_SECONDS = 60;

    private final String url; // null with PEM files
    private final Http http;
    private final Duration timeout;
    private volatile List<PubKey> keys;
    private volatile Instant lastUnknownKidFetch = Instant.EPOCH;
    private volatile Consumer<List<PubKey>> onReplace = k -> {};

    private IssuerKeys(String url, Http http, Duration timeout, List<PubKey> keys) {
        this.url = url;
        this.http = http;
        this.timeout = timeout;
        this.keys = keys;
    }

    public static IssuerKeys fixed(List<PubKey> keys) {
        return new IssuerKeys(null, null, null, List.copyOf(keys));
    }

    public static IssuerKeys fromJwks(String url, Http http, Duration timeout) {
        return new IssuerKeys(url, http, timeout, List.of());
    }

    /** Called with every newly loaded set (for the persistent cache). */
    public void onReplace(Consumer<List<PubKey>> c) {
        this.onReplace = c;
    }

    public List<PubKey> get() {
        return keys;
    }

    public boolean loaded() {
        return !keys.isEmpty();
    }

    /** Restores a persisted set. */
    public void restore(List<PubKey> restored) {
        if (url != null && !restored.isEmpty()) {
            keys = List.copyOf(restored);
        }
    }

    public long retrySeconds(long refreshSeconds) {
        return loaded() ? refreshSeconds : EMPTY_RETRY_SECONDS;
    }

    /** One JWKS fetch; a failure keeps the current keys. */
    public boolean fetch() {
        if (url == null) {
            return true;
        }
        try {
            Http.Response r = http.send("GET", url, Map.of("Accept", "application/json"), null, timeout, 1 << 20);
            if (r.status() != 200) {
                LOG.atWarn().addKeyValue("status", r.status()).log("issuer JWKS fetch failed; current keys kept");
                return false;
            }
            List<PubKey> parsed = parse(r.body());
            if (parsed.isEmpty()) {
                LOG.atWarn().log("issuer JWKS has no usable RSA signing key; current keys kept");
                return false;
            }
            keys = parsed;
            onReplace.accept(parsed);
            LOG.atInfo().addKeyValue("kids", parsed.stream().map(PubKey::kid).toList()).log("issuer keys loaded");
            return true;
        } catch (Http.NoResponse e) {
            LOG.atWarn().addKeyValue("noResponse", e.kind).log("issuer JWKS fetch failed; current keys kept");
            return false;
        }
    }

    /**
     * A token named a kid we do not hold: refetch once, at most once a minute. Returns true
     * when a fetch ran and succeeded.
     */
    public synchronized boolean refetchForUnknownKid() {
        if (url == null) {
            return false;
        }
        Instant now = Instant.now();
        if (Duration.between(lastUnknownKidFetch, now).getSeconds() < UNKNOWN_KID_INTERVAL_SECONDS) {
            return false;
        }
        lastUnknownKidFetch = now;
        return fetch();
    }

    /**
     * RSA signing keys of at least 2048 bits with a kid. Encryption keys, EC keys, entries with an
     * HMAC or other non-RS256/PS256 {@code alg}, and undecodable entries are skipped.
     */
    public static List<PubKey> parse(byte[] body) {
        List<PubKey> out = new ArrayList<>();
        var root = Json.parseObject(body);
        var arr = root == null ? null : root.get("keys");
        if (arr == null || !arr.isArray()) {
            return out;
        }
        for (var item : arr) {
            try {
                JWK jwk = JWK.parse(item.toString());
                if (!(jwk instanceof RSAKey rsa) || jwk.getKeyID() == null || jwk.getKeyID().isEmpty()) {
                    continue;
                }
                if (jwk.getKeyUse() != null && !KeyUse.SIGNATURE.equals(jwk.getKeyUse())) {
                    continue;
                }
                if (jwk.getAlgorithm() != null && !JWSAlgorithm.RS256.equals(jwk.getAlgorithm())
                        && !JWSAlgorithm.PS256.equals(jwk.getAlgorithm())) {
                    continue;
                }
                var pub = rsa.toRSAPublicKey();
                if (pub.getModulus().bitLength() < Pem.MIN_RSA_BITS) {
                    continue;
                }
                out.add(new PubKey(jwk.getKeyID(), pub));
            } catch (Exception e) {
                // undecodable entry (e.g. a bad modulus): skipped
            }
        }
        return List.copyOf(out);
    }
}
