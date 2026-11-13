package org.sahamati.iopgw.sources;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.crypto.PubKey;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Reads the sender-id from a role api-key. In {@code jwt} mode the token's RS256/PS256
 * signature, {@code exp}/{@code nbf} (with clock skew) and optional {@code iss}/{@code aud} are
 * checked, and the sender-id is the configured claim ({@code azp} by default). {@code static} mode
 * (development and tests only) maps fixed key values to entity ids.
 */
public final class ApiKeyVerifier {

    private final Config.ApiKey conf;
    private final IssuerKeys issuerKeys;
    private final Map<String, String> staticKeys; // key value -> entity id

    public ApiKeyVerifier(Config.ApiKey conf, List<PubKey> issuerKeys, Map<String, String> staticKeys) {
        this(conf, IssuerKeys.fixed(issuerKeys), staticKeys);
    }

    public ApiKeyVerifier(Config.ApiKey conf, IssuerKeys issuerKeys, Map<String, String> staticKeys) {
        this.conf = conf;
        this.issuerKeys = issuerKeys;
        this.staticKeys = Map.copyOf(staticKeys);
    }

    /** Verifies with the held keys; a kid no held key has triggers one rate-limited JWKS refetch. */
    private boolean verified(SignedJWT jwt) throws com.nimbusds.jose.JOSEException {
        String kid = jwt.getHeader().getKeyID();
        List<PubKey> keys = issuerKeys.get();
        boolean known = kid == null || keys.stream().anyMatch(k -> k.kid() == null || kid.equals(k.kid()));
        if (!known && issuerKeys.refetchForUnknownKid()) {
            keys = issuerKeys.get();
        }
        for (PubKey k : keys) {
            if (kid != null && k.kid() != null && !kid.equals(k.kid())) {
                continue;
            }
            if (jwt.verify(new RSASSAVerifier(k.key()))) {
                return true;
            }
        }
        return false;
    }

    public Optional<String> senderId(String apiKey) {
        if (apiKey == null || apiKey.isEmpty()) {
            return Optional.empty();
        }
        if ("static".equals(conf.mode)) {
            byte[] given = apiKey.getBytes(StandardCharsets.UTF_8);
            for (Map.Entry<String, String> e : staticKeys.entrySet()) {
                if (MessageDigest.isEqual(given, e.getKey().getBytes(StandardCharsets.UTF_8))) {
                    return Optional.of(e.getValue());
                }
            }
            return Optional.empty();
        }
        try {
            SignedJWT jwt = SignedJWT.parse(apiKey);
            JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
            if (!JWSAlgorithm.RS256.equals(alg) && !JWSAlgorithm.PS256.equals(alg)) {
                return Optional.empty();
            }
            if (!verified(jwt)) {
                return Optional.empty();
            }
            JWTClaimsSet c = jwt.getJWTClaimsSet();
            Instant now = Instant.now();
            long skew = conf.clockSkewSeconds;
            Date exp = c.getExpirationTime();
            if (exp == null || now.minusSeconds(skew).isAfter(exp.toInstant())) {
                return Optional.empty();
            }
            Date nbf = c.getNotBeforeTime();
            if (nbf != null && now.plusSeconds(skew).isBefore(nbf.toInstant())) {
                return Optional.empty();
            }
            if (conf.issuer != null && !conf.issuer.equals(c.getIssuer())) {
                return Optional.empty();
            }
            if (conf.audience != null && (c.getAudience() == null || !c.getAudience().contains(conf.audience))) {
                return Optional.empty();
            }
            Object sender = c.getClaim(conf.senderIdClaim);
            return sender instanceof String s && !s.isEmpty() ? Optional.of(s) : Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
