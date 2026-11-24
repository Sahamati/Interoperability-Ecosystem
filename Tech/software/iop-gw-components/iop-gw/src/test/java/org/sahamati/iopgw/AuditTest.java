package org.sahamati.iopgw;

import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.obs.Audit;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Audit record headers: which values are logged. */
class AuditTest {

    @Test
    void knownIopHeadersAreLoggedSecretsMaskedOthersNamedOnly() {
        List<String> shown = List.of("Core-Entity-Id", "Target-Id", "Target-Entity", "Correlation-Id", "Forwarding-Hop",
                "Preferred-Hop", "Http-Retries", "Route-Retries", "Initiator-Entity", "IOP-Gw-Error", "Content-Type",
                "Content-Length", "Accept", "Allow");
        List<String> secret = List.of("Authorization", "x-jws-signature", "client_api_key", "x-conn_aa_api_key",
                "x-cust_aa_api_key", "x-orig_aa_api_key", "fip_api_key", "x-inter_aa_api_key");
        Map<String, String> in = new LinkedHashMap<>();
        shown.forEach(h -> in.put(h, "value-of-" + h));
        secret.forEach(h -> in.put(h, "secret-of-" + h));
        in.put("X-Something-Else", "other");

        Map<String, String> out = Audit.headers(in);
        shown.forEach(h -> assertEquals("value-of-" + h, out.get(h), h));
        secret.forEach(h -> assertEquals("<present>", out.get(h), h));
        assertEquals("<not logged>", out.get("X-Something-Else"));
    }
}
