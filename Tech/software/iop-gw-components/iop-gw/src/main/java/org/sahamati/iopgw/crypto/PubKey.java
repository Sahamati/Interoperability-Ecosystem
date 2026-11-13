package org.sahamati.iopgw.crypto;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

/**
 * A participant's public key. Keys from the Central Registry may carry a validity window:
 * {@code validFrom} and {@code validTo}, both optional (null = no limit), both inclusive,
 * checked at every use. Configured keys and issuer keys have no window.
 */
public record PubKey(String kid, RSAPublicKey key, Instant validFrom, Instant validTo) {

    public PubKey(String kid, RSAPublicKey key) {
        this(kid, key, null, null);
    }

    /** True while {@code now} is inside the window (both ends included). */
    public boolean usable(Instant now) {
        return (validFrom == null || !now.isBefore(validFrom)) && (validTo == null || !now.isAfter(validTo));
    }

    /** The keys of {@code keys} usable now. */
    public static List<PubKey> usableNow(List<PubKey> keys) {
        Instant now = Instant.now();
        return keys.stream().filter(k -> k.usable(now)).toList();
    }
}
