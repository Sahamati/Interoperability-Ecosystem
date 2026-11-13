package org.sahamati.iopgw.sources;

import com.fasterxml.jackson.databind.JsonNode;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/** The AAs this participant is linked to: the only AAs used as hops. */
public final class LinkedAAs {
    private static final Logger LOG = LoggerFactory.getLogger(LinkedAAs.class);

    private volatile List<String> aas;
    private volatile java.util.function.Consumer<List<String>> onReplace = x -> {};

    /** Called with every new list from the core, pulled or pushed (for the persistent cache). */
    public void onReplace(java.util.function.Consumer<List<String>> c) {
        this.onReplace = c;
    }

    /** Replaces the list from the core (pull or push) and persists it. */
    public void replace(List<String> next) {
        set(next);
        onReplace.accept(get());
    }

    public boolean loaded() {
        return aas != null;
    }

    public List<String> get() {
        List<String> l = aas;
        return l == null ? List.of() : l;
    }

    public void set(List<String> next) {
        this.aas = List.copyOf(next);
    }

    /**
     * Parses {@code {"linkedAAs": [...]}}: non-empty, unique, non-empty string ids. Returns the list,
     * or throws {@link IllegalArgumentException} with a reason safe to return to the core.
     */
    public static List<String> parse(byte[] body) {
        JsonNode n = Json.parseObject(body);
        if (n == null) {
            throw new IllegalArgumentException("body must be a JSON object");
        }
        JsonNode arr = n.get("linkedAAs");
        if (arr == null || !arr.isArray() || arr.isEmpty()) {
            throw new IllegalArgumentException("linkedAAs must be a non-empty list");
        }
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (JsonNode v : arr) {
            if (!v.isTextual() || v.asText().isEmpty()) {
                throw new IllegalArgumentException("linkedAAs entries must be non-empty strings");
            }
            if (!seen.add(v.asText())) {
                throw new IllegalArgumentException("linkedAAs has a repeated id");
            }
        }
        return new ArrayList<>(seen);
    }

    /** One pull from the core. */
    public boolean pull(String url, String token, Http http, Duration timeout) {
        try {
            Http.Response r = http.send("GET", url, Map.of("Authorization", "Bearer " + token), null, timeout, 1 << 20);
            if (r.status() != 200) {
                LOG.atWarn().addKeyValue("status", r.status()).log("linkedAAs pull failed; current list kept");
                return false;
            }
            replace(parse(r.body()));
            LOG.atInfo().addKeyValue("count", get().size()).log("linkedAAs loaded");
            return true;
        } catch (Http.NoResponse e) {
            LOG.atWarn().addKeyValue("noResponse", e.kind).log("linkedAAs pull failed; current list kept");
            return false;
        } catch (IllegalArgumentException e) {
            LOG.atWarn().addKeyValue("reason", e.getMessage()).log("linkedAAs pull invalid; current list kept");
            return false;
        }
    }
}
