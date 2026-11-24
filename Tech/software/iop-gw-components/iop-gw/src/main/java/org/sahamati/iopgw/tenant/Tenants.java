package org.sahamati.iopgw.tenant;

import org.sahamati.iopgw.crypto.KeyRing;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The entities loaded now. Readers see a consistent snapshot; a reload replaces one entity at a
 * time. In single-tenant mode it holds the one entity for the gateway's life.
 */
public final class Tenants {
    private final boolean multiTenant;
    private volatile Map<String, Tenant> byId = Map.of();

    public Tenants(boolean multiTenant) {
        this.multiTenant = multiTenant;
    }

    public boolean multiTenant() {
        return multiTenant;
    }

    /** The loaded entities, in load order. */
    public List<Tenant> all() {
        return new ArrayList<>(byId.values());
    }

    public List<String> ids() {
        return new ArrayList<>(byId.keySet());
    }

    public int count() {
        return byId.size();
    }

    public Optional<Tenant> get(String id) {
        return id == null ? Optional.empty() : Optional.ofNullable(byId.get(id));
    }

    /** The one entity, when exactly one is loaded. */
    public Optional<Tenant> only() {
        Map<String, Tenant> m = byId;
        return m.size() == 1 ? Optional.of(m.values().iterator().next()) : Optional.empty();
    }

    /** True when {@code id} is one of this gateway's loaded entities. */
    public boolean isOwn(String id) {
        return id != null && byId.containsKey(id);
    }

    /** The loaded entity whose decryption key set holds {@code kid}. */
    public Optional<Tenant> byDecryptionKid(String kid) {
        if (kid == null) {
            return Optional.empty();
        }
        for (Tenant t : byId.values()) {
            for (KeyRing.PrivKey k : t.decryption.all()) {
                if (kid.equals(k.kid())) {
                    return Optional.of(t);
                }
            }
        }
        return Optional.empty();
    }

    /** The id of a loaded entity other than {@code exceptId} whose decryption key set holds {@code kid}, or null. */
    public String kidOwner(String kid, String exceptId) {
        for (Tenant t : byId.values()) {
            if (t.id.equals(exceptId)) {
                continue;
            }
            for (KeyRing.PrivKey k : t.decryption.all()) {
                if (k.kid().equals(kid)) {
                    return t.id;
                }
            }
        }
        return null;
    }

    /** Adds or replaces an entity; returns the version it replaced, or null. */
    public synchronized Tenant put(Tenant t) {
        Map<String, Tenant> next = new LinkedHashMap<>(byId);
        Tenant old = next.put(t.id, t);
        byId = ordered(next);
        return old;
    }

    /** Removes an entity; returns it, or null. */
    public synchronized Tenant remove(String id) {
        Map<String, Tenant> next = new LinkedHashMap<>(byId);
        Tenant old = next.remove(id);
        byId = ordered(next);
        return old;
    }

    private static Map<String, Tenant> ordered(Map<String, Tenant> m) {
        return java.util.Collections.unmodifiableMap(new LinkedHashMap<>(m));
    }
}
