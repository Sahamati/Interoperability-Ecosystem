package org.sahamati.iopgw.sources;

import com.fasterxml.jackson.databind.JsonNode;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.model.Roles.EntityType;
import org.sahamati.iopgw.model.Roles.Mode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The AA Interoperability Graph, held in memory; never called per request.
 * AA mode: per FIU its connected-AAs, per FIP its inter-AAs. FIU and FIP mode: per AA its peer-AAs,
 * where peering counts in both directions. {@code verified} and {@code attr} do not affect routing.
 */
public final class Aig {
    private static final Logger LOG = LoggerFactory.getLogger(Aig.class);

    private record Graph(Map<String, List<String>> fiu, Map<String, List<String>> fip, Map<String, List<String>> aa) {}

    private final Mode mode;
    private volatile Graph graph;
    private volatile java.util.function.Consumer<com.fasterxml.jackson.databind.JsonNode> onReplace = x -> {};

    /** Called with every newly loaded graph (for the persistent cache). */
    public void onReplace(java.util.function.Consumer<com.fasterxml.jackson.databind.JsonNode> c) {
        this.onReplace = c;
    }

    private void set(Graph g) {
        graph = g;
        onReplace.accept(CacheCodec.graph(g.fiu, g.fip, g.aa));
    }

    /** Serves a persisted graph. Throws {@link IllegalArgumentException} on a malformed copy. */
    public void restore(com.fasterxml.jackson.databind.JsonNode n) {
        graph = new Graph(CacheCodec.graphPart(n, "fiu"), CacheCodec.graphPart(n, "fip"), CacheCodec.graphPart(n, "aa"));
        LOG.atInfo().log("AIG restored from the cache");
    }

    public Aig(Mode mode) {
        this.mode = mode;
    }

    public boolean loaded() {
        return graph != null;
    }

    /** The AAs the graph says can reach {@code target}, in graph order. Empty when absent. */
    public List<String> candidates(EntityType targetType, String target) {
        Graph g = graph;
        if (g == null) {
            throw new IllegalStateException("AIG not loaded");
        }
        if (mode == Mode.AA) {
            return switch (targetType) {
                case FIU -> g.fiu.getOrDefault(target, List.of());
                case FIP -> g.fip.getOrDefault(target, List.of());
                case AA -> List.of();
            };
        }
        if (targetType != EntityType.AA) {
            return List.of();
        }
        Set<String> out = new LinkedHashSet<>(g.aa.getOrDefault(target, List.of()));
        g.aa.forEach((aa, peers) -> {
            if (peers.contains(target)) {
                out.add(aa);
            }
        });
        out.remove(target);
        return List.copyOf(out);
    }

    // ---------------- configuration source ----------------

    public void loadConfigured(Config.AigGraph conf) {
        set(new Graph(flatten(conf.fiu), flatten(conf.fip), flatten(conf.aa)));
    }

    private static Map<String, List<String>> flatten(List<Map<String, List<String>>> entries) {
        Map<String, List<String>> m = new LinkedHashMap<>();
        if (entries != null) {
            for (Map<String, List<String>> e : entries) {
                e.forEach((k, v) -> m.put(k, List.copyOf(v)));
            }
        }
        return Map.copyOf(m);
    }

    // ---------------- API source ----------------

    /** One load of every graph the mode needs; the previous graph is kept unless all succeed. */
    public boolean loadFromApi(Config c, Http http, Supplier<Optional<String>> bearer) {
        Optional<String> token = bearer.get();
        if (token.isEmpty()) {
            LOG.atWarn().log("AIG load skipped: no access token");
            return false;
        }
        try {
            if (mode == Mode.AA) {
                Map<String, List<String>> fiu = fetch(c, http, token.get(), c.fiuAigPath, "fiu", "connected-AA");
                Map<String, List<String>> fip = fetch(c, http, token.get(), c.fipAigPath, "fip", "inter-AA");
                if (fiu == null || fip == null) {
                    return false;
                }
                set(new Graph(fiu, fip, Map.of()));
            } else {
                Map<String, List<String>> aa = fetch(c, http, token.get(), c.aaAigPath, "aa", "peer-AA");
                if (aa == null) {
                    return false;
                }
                set(new Graph(Map.of(), Map.of(), aa));
            }
            LOG.atInfo().log("AIG loaded");
            return true;
        } catch (Http.NoResponse e) {
            LOG.atWarn().addKeyValue("noResponse", e.kind).log("AIG load failed; previous graph kept");
            return false;
        }
    }

    private Map<String, List<String>> fetch(Config c, Http http, String token, String path, String listKey, String linkKey)
            throws Http.NoResponse {
        Http.Response r = http.send("GET", c.aigBaseUrl + path, Map.of("Authorization", "Bearer " + token), null,
                Duration.ofSeconds(c.aigTimeoutSeconds), 64L << 20);
        if (r.status() != 200) {
            LOG.atWarn().addKeyValue("path", path).addKeyValue("status", r.status()).log("AIG load failed; previous graph kept");
            return null;
        }
        JsonNode body = Json.parseObject(r.body());
        JsonNode list = body == null ? null : body.get(listKey);
        if (list == null || !list.isArray()) {
            LOG.atWarn().addKeyValue("path", path).log("AIG response without the expected list; previous graph kept");
            return null;
        }
        Map<String, List<String>> m = new LinkedHashMap<>();
        for (JsonNode node : list) {
            String id = Json.text(node, "id");
            JsonNode links = node.get(linkKey);
            if (id == null || links == null || !links.isArray()) {
                LOG.atWarn().addKeyValue("path", path).log("AIG entry malformed; previous graph kept");
                return null;
            }
            List<String> hops = new ArrayList<>();
            for (JsonNode l : links) {
                String hop = Json.text(l, "id");
                if (hop != null) {
                    hops.add(hop);
                }
            }
            m.put(id, List.copyOf(hops));
        }
        return Map.copyOf(m);
    }
}
