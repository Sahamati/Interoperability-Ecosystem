package org.sahamati.iopgw.crypto;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * This participant's private keys (signing or decryption) with validity: a key is usable
 * while active, from {@code applied} (inclusive) until {@code expiry} (exclusive), checked at use.
 */
public final class KeyRing {

    public record PrivKey(String kid, RSAPrivateKey key, boolean active, Instant applied, Instant expiry) {
        public boolean usable(Instant now) {
            return active && (applied == null || !now.isBefore(applied)) && (expiry == null || now.isBefore(expiry));
        }

        public PubKey publicKey() {
            if (key instanceof RSAPrivateCrtKey crt) {
                try {
                    RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
                            .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
                    return new PubKey(kid, pub);
                } catch (Exception e) {
                    return null;
                }
            }
            return null;
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private volatile List<PrivKey> keys;

    public KeyRing(List<PrivKey> keys) {
        this.keys = List.copyOf(keys);
    }

    public List<PrivKey> all() {
        return keys;
    }

    public boolean loaded() {
        return !keys.isEmpty();
    }

    public void replace(List<PrivKey> next) {
        this.keys = List.copyOf(next);
    }

    /** A usable key chosen at random, or empty when none is usable now. */
    public Optional<PrivKey> pickSigning() {
        Instant now = Instant.now();
        List<PrivKey> usable = keys.stream().filter(k -> k.usable(now)).toList();
        if (usable.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(usable.get(RANDOM.nextInt(usable.size())));
    }

    public List<PrivKey> usable() {
        Instant now = Instant.now();
        return keys.stream().filter(k -> k.usable(now)).toList();
    }

    public List<PubKey> publicKeys() {
        return keys.stream().map(PrivKey::publicKey).filter(java.util.Objects::nonNull).toList();
    }
}
