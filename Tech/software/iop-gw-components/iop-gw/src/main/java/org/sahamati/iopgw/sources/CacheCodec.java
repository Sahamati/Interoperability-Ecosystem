package org.sahamati.iopgw.sources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.model.Roles.EntityType;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Encodes what the persistent cache holds: public keys only, never private keys or api-keys
 *. Decoding a value of the wrong shape fails with {@link IllegalArgumentException}.
 */
public final class CacheCodec {
    private CacheCodec() {}

    public static ArrayNode pubKeys(List<PubKey> keys) {
        ArrayNode a = Json.MAPPER.createArrayNode();
        for (PubKey k : keys) {
            ObjectNode o = a.addObject();
            if (k.kid() == null) {
                o.putNull("kid");
            } else {
                o.put("kid", k.kid());
            }
            o.put("spki", Base64.getEncoder().encodeToString(k.key().getEncoded()));
            if (k.validFrom() != null) {
                o.put("validFrom", k.validFrom().toString());
            }
            if (k.validTo() != null) {
                o.put("validTo", k.validTo().toString());
            }
        }
        return a;
    }

    public static List<PubKey> pubKeys(JsonNode n) {
        if (n == null || !n.isArray()) {
            throw new IllegalArgumentException("not a key list");
        }
        List<PubKey> out = new ArrayList<>();
        for (JsonNode o : n) {
            try {
                byte[] der = Base64.getDecoder().decode(o.get("spki").asText());
                RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
                JsonNode kid = o.get("kid");
                JsonNode from = o.get("validFrom");
                JsonNode to = o.get("validTo");
                out.add(new PubKey(kid == null || kid.isNull() ? null : kid.asText(), pub,
                        from == null ? null : java.time.Instant.parse(from.asText()),
                        to == null ? null : java.time.Instant.parse(to.asText())));
            } catch (Exception e) {
                throw new IllegalArgumentException("not a key list");
            }
        }
        return List.copyOf(out);
    }

    // ---------------- entities (without local settings) ----------------

    /** Marks entity snapshots that carry key windows; older snapshots are not restored. */
    private static final String FORMAT = "keyWindows";

    public static ObjectNode entities(Iterable<Registry.Entity> entities) {
        ObjectNode root = Json.object();
        root.put("format", FORMAT);
        ArrayNode a = root.putArray("entities");
        for (Registry.Entity e : entities) {
            ObjectNode o = a.addObject();
            o.put("id", e.id());
            o.put("type", e.type().name());
            if (e.baseUrl() == null) {
                o.putNull("baseUrl");
            } else {
                o.put("baseUrl", e.baseUrl());
            }
            o.put("interop", e.interop());
            o.set("signingKeys", pubKeys(e.allSigningKeys()));
            o.set("encryptionKeys", pubKeys(e.allEncryptionKeys()));
            // outboundApiKey is a local secret: never persisted
        }
        return root;
    }

    public static Map<String, Registry.Entity> entities(JsonNode root) {
        if (root == null || !root.isObject() || !FORMAT.equals(Json.text(root, "format"))) {
            throw new IllegalArgumentException("not an entity list with key windows");
        }
        JsonNode n = root.get("entities");
        if (n == null || !n.isArray()) {
            throw new IllegalArgumentException("not an entity list");
        }
        Map<String, Registry.Entity> m = new LinkedHashMap<>();
        for (JsonNode o : n) {
            if (!o.isObject() || Json.text(o, "id") == null) {
                throw new IllegalArgumentException("not an entity list");
            }
            JsonNode base = o.get("baseUrl");
            m.put(o.get("id").asText(), new Registry.Entity(o.get("id").asText(), EntityType.valueOf(o.get("type").asText()),
                    base == null || base.isNull() ? null : base.asText(), o.path("interop").asBoolean(false),
                    pubKeys(o.get("signingKeys")), pubKeys(o.get("encryptionKeys")), null));
        }
        return m;
    }

    // ---------------- AIG graph ----------------

    public static ObjectNode graph(Map<String, List<String>> fiu, Map<String, List<String>> fip, Map<String, List<String>> aa) {
        ObjectNode o = Json.object();
        o.set("fiu", Json.MAPPER.valueToTree(fiu));
        o.set("fip", Json.MAPPER.valueToTree(fip));
        o.set("aa", Json.MAPPER.valueToTree(aa));
        return o;
    }

    public static Map<String, List<String>> graphPart(JsonNode n, String name) {
        JsonNode part = n == null ? null : n.get(name);
        if (part == null || !part.isObject()) {
            throw new IllegalArgumentException("not an AIG graph");
        }
        Map<String, List<String>> m = new LinkedHashMap<>();
        part.fields().forEachRemaining(e -> {
            if (!e.getValue().isArray()) {
                throw new IllegalArgumentException("not an AIG graph");
            }
            List<String> l = new ArrayList<>();
            e.getValue().forEach(v -> l.add(v.asText()));
            m.put(e.getKey(), List.copyOf(l));
        });
        return Map.copyOf(m);
    }
}
