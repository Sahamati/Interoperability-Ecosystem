package org.sahamati.iopgw.sources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.sahamati.iopgw.crypto.KeyRing;
import org.sahamati.iopgw.crypto.Pem;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This participant's private signing or decryption keys from the core: fetched by
 * {@code GET} (https only, bearer token) and replaced by key push. A set is accepted only whole
 *. Key material is never logged or returned, only kids and validity.
 */
public final class CoreKeys {
    private static final Logger LOG = LoggerFactory.getLogger(CoreKeys.class);

    /** Retry interval while no key is loaded. */
    public static final long EMPTY_RETRY_SECONDS = 30;

    private final String name; // "signing" or "decryption"
    private final KeyRing ring;
    private final String url;
    private final String token;
    private final Http http;
    private final Duration timeout;

    public CoreKeys(String name, KeyRing ring, String url, String token, Http http, Duration timeout) {
        this.name = name;
        this.ring = ring;
        this.url = url;
        this.token = token;
        this.http = http;
        this.timeout = timeout;
    }

    /** One GET from the core. A failure keeps the current set. */
    public boolean pull() {
        try {
            Http.Response r = http.send("GET", url, Map.of("Authorization", "Bearer " + token), null, timeout, 1 << 20);
            if (r.status() != 200) {
                LOG.atWarn().addKeyValue("keys", name).addKeyValue("status", r.status()).log("key fetch failed; current set kept");
                return false;
            }
            List<KeyRing.PrivKey> set = parse(r.body());
            ring.replace(set);
            logSet("key set fetched", set);
            return true;
        } catch (Http.NoResponse e) {
            LOG.atWarn().addKeyValue("keys", name).addKeyValue("noResponse", e.kind).log("key fetch failed; current set kept");
            return false;
        } catch (IllegalArgumentException e) {
            LOG.atWarn().addKeyValue("keys", name).addKeyValue("reason", e.getMessage()).log("key set invalid; current set kept");
            return false;
        }
    }

    /** Seconds to the next fetch after a failure: 30 s while no key is loaded, else the refresh interval. */
    public long retrySeconds(long refreshSeconds) {
        return ring.loaded() ? refreshSeconds : EMPTY_RETRY_SECONDS;
    }

    /** Replaces the set from a key push; throws {@link IllegalArgumentException} with a safe reason. */
    public List<KeyRing.PrivKey> push(byte[] body) {
        List<KeyRing.PrivKey> set = parse(body);
        ring.replace(set);
        logSet("key set replaced by push", set);
        return set;
    }

    private void logSet(String msg, List<KeyRing.PrivKey> set) {
        Instant now = Instant.now();
        boolean anyUsable = set.stream().anyMatch(k -> k.usable(now));
        var ev = (anyUsable ? LOG.atInfo() : LOG.atWarn()).addKeyValue("keys", name).addKeyValue("set", Json.MAPPER.convertValue(status(set), Object.class));
        ev.log(anyUsable ? msg : msg + "; no key is usable now");
    }

    // ---------------- parsing and validation ----------------

    /**
     * Parses {@code {"keys": [{"kid","privateKey","active","applied","expiry"}]}}. Every key must be
     * a PEM RSA key of at least 2048 bits with a unique non-empty kid; {@code active} and
     * {@code applied} are required, {@code expiry} may be null or absent and must be after
     * {@code applied}. The reason in the exception never contains key material.
     */
    public static List<KeyRing.PrivKey> parse(byte[] body) {
        JsonNode n = Json.parseObject(body);
        if (n == null) {
            throw new IllegalArgumentException("body must be a JSON object");
        }
        JsonNode keys = n.get("keys");
        if (keys == null || !keys.isArray() || keys.isEmpty()) {
            throw new IllegalArgumentException("keys must be a non-empty list");
        }
        Set<String> kids = new HashSet<>();
        List<KeyRing.PrivKey> out = new ArrayList<>();
        int i = 0;
        for (JsonNode k : keys) {
            String where = "keys[" + i++ + "]";
            if (!k.isObject()) {
                throw new IllegalArgumentException(where + " must be an object");
            }
            JsonNode kidNode = k.get("kid");
            if (kidNode == null || !kidNode.isTextual() || kidNode.asText().isEmpty()) {
                throw new IllegalArgumentException(where + ".kid must be a non-empty string");
            }
            String kid = kidNode.asText();
            if (!kids.add(kid)) {
                throw new IllegalArgumentException("kid " + kid + " is repeated");
            }
            JsonNode pem = k.get("privateKey");
            if (pem == null || !pem.isTextual()) {
                throw new IllegalArgumentException("key " + kid + ": privateKey must be a PEM string");
            }
            java.security.interfaces.RSAPrivateKey key;
            try {
                key = Pem.privateKey(pem.asText());
            } catch (Exception e) {
                throw new IllegalArgumentException("key " + kid + ": privateKey is not an RSA private key of at least 2048 bits");
            }
            JsonNode active = k.get("active");
            if (active == null || !active.isBoolean()) {
                throw new IllegalArgumentException("key " + kid + ": active is required (true or false)");
            }
            JsonNode applied = k.get("applied");
            if (applied == null || !applied.isTextual()) {
                throw new IllegalArgumentException("key " + kid + ": applied is required (a date)");
            }
            Instant from = date(applied.asText(), "key " + kid + ": applied");
            JsonNode expiry = k.get("expiry");
            Instant to = null;
            if (expiry != null && !expiry.isNull()) {
                if (!expiry.isTextual()) {
                    throw new IllegalArgumentException("key " + kid + ": expiry must be a date or null");
                }
                to = date(expiry.asText(), "key " + kid + ": expiry");
                if (!to.isAfter(from)) {
                    throw new IllegalArgumentException("key " + kid + ": expiry must be after applied");
                }
            }
            out.add(new KeyRing.PrivKey(kid, key, active.asBoolean(), from, to));
        }
        return List.copyOf(out);
    }

    /** RFC 3339 or {@code YYYY-MM-DD} (00:00 UTC). */
    public static Instant date(String s, String what) {
        try {
            if (s.length() == 10) {
                return LocalDate.parse(s).atStartOfDay(ZoneOffset.UTC).toInstant();
            }
            return OffsetDateTime.parse(s).toInstant();
        } catch (Exception e) {
            throw new IllegalArgumentException(what + " is not an RFC 3339 or YYYY-MM-DD date");
        }
    }

    /** Each key's kid, active, applied, expiry and whether it is usable now; never key material. */
    public static ArrayNode status(List<KeyRing.PrivKey> set) {
        Instant now = Instant.now();
        ArrayNode arr = Json.MAPPER.createArrayNode();
        for (KeyRing.PrivKey k : set) {
            ObjectNode o = arr.addObject();
            o.put("kid", k.kid());
            o.put("active", k.active());
            if (k.applied() == null) {
                o.putNull("applied");
            } else {
                o.put("applied", k.applied().toString());
            }
            if (k.expiry() == null) {
                o.putNull("expiry");
            } else {
                o.put("expiry", k.expiry().toString());
            }
            o.put("usable", k.usable(now));
        }
        return arr;
    }
}
