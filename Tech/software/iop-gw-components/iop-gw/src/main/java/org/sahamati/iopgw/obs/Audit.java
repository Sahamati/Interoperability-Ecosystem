package org.sahamati.iopgw.obs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LoggingEventBuilder;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Audit records: one JSON record per request and response on every leg, tagged
 * {@code IOPGW_AUDIT}. Bodies are never logged; secret headers and signatures appear as
 * {@code <present>}; other unknown headers as {@code <not logged>}.
 */
public final class Audit {
    private static final Logger LOG = LoggerFactory.getLogger(Logs.AUDIT_LOGGER);

    private static final Set<String> SHOWN = Set.of("target-entity", "correlation-id", "forwarding-hop", "preferred-hop",
            "http-retries", "route-retries", "initiator-entity", "iop-gw-error", "content-type", "content-length",
            "accept", "allow");
    /** Never logged by value: the tokens, the signature, and every role api-key header (from Roles, so they stay in step). */
    private static final Set<String> SECRET;

    static {
        java.util.Set<String> s = new java.util.HashSet<>(Set.of("authorization", "x-jws-signature"));
        for (String k : org.sahamati.iopgw.model.Roles.ALL_KEYS) {
            s.add(k.toLowerCase(Locale.ROOT));
        }
        SECRET = Set.copyOf(s);
    }

    private final boolean enabled;
    private final String self;
    private final String mode;

    public Audit(boolean enabled, String self, String mode) {
        this.enabled = enabled;
        this.self = self;
        this.mode = mode;
    }

    /** Header map for a record: values only for the known IOP set. */
    public static Map<String, String> headers(Map<String, String> in) {
        Map<String, String> out = new LinkedHashMap<>();
        in.forEach((k, v) -> {
            String lk = k.toLowerCase(Locale.ROOT);
            if (SECRET.contains(lk)) {
                out.put(k, "<present>");
            } else if (SHOWN.contains(lk)) {
                out.put(k, v);
            } else {
                out.put(k, "<not logged>");
            }
        });
        return out;
    }

    /** Writes one record. {@code fields} holds the audit record fields that are known; nulls are dropped. */
    public void record(String event, String leg, String role, Map<String, Object> fields) {
        if (!enabled) {
            return;
        }
        LoggingEventBuilder b = LOG.atInfo()
                .addKeyValue("tag", "IOPGW_AUDIT")
                .addKeyValue("event", event)
                .addKeyValue("leg", leg)
                .addKeyValue("role", role)
                .addKeyValue("self", self)
                .addKeyValue("mode", mode);
        fields.forEach((k, v) -> {
            if (v != null) {
                b.addKeyValue(k, v);
            }
        });
        b.log("audit");
    }
}
