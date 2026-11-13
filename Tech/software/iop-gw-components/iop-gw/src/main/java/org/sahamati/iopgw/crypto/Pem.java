package org.sahamati.iopgw.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reads RSA keys from PEM files: PKCS#8 / PKCS#1 private keys, SPKI public keys and X.509 certificates. */
public final class Pem {
    private Pem() {}

    private static final Pattern BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z ]+)-----([A-Za-z0-9+/=\\s]+)-----END \\1-----");

    public static final int MIN_RSA_BITS = 2048;

    public static RSAPrivateKey privateKey(Path file) throws IOException, GeneralSecurityException {
        return privateKey(Files.readString(file, StandardCharsets.US_ASCII));
    }

    public static RSAPrivateKey privateKey(String pem) throws GeneralSecurityException {
        Matcher m = BLOCK.matcher(pem);
        while (m.find()) {
            byte[] der = Base64.getMimeDecoder().decode(m.group(2));
            String type = m.group(1);
            byte[] pkcs8;
            if ("PRIVATE KEY".equals(type)) {
                pkcs8 = der;
            } else if ("RSA PRIVATE KEY".equals(type)) {
                pkcs8 = wrapPkcs1(der);
            } else {
                continue;
            }
            RSAPrivateKey key = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            checkSize(key.getModulus().bitLength());
            return key;
        }
        throw new GeneralSecurityException("no RSA private key in PEM");
    }

    public static RSAPublicKey publicKey(Path file) throws IOException, GeneralSecurityException {
        String pem = Files.readString(file, StandardCharsets.US_ASCII);
        Matcher m = BLOCK.matcher(pem);
        while (m.find()) {
            byte[] der = Base64.getMimeDecoder().decode(m.group(2));
            RSAPublicKey key;
            switch (m.group(1)) {
                case "PUBLIC KEY" -> key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
                case "CERTIFICATE" -> {
                    X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                            .generateCertificate(new ByteArrayInputStream(der));
                    if (!(cert.getPublicKey() instanceof RSAPublicKey rsa)) {
                        throw new GeneralSecurityException("certificate key is not RSA");
                    }
                    key = rsa;
                }
                default -> {
                    continue;
                }
            }
            checkSize(key.getModulus().bitLength());
            return key;
        }
        throw new GeneralSecurityException("no RSA public key or certificate in PEM");
    }

    private static void checkSize(int bits) throws GeneralSecurityException {
        if (bits < MIN_RSA_BITS) {
            throw new GeneralSecurityException("RSA key smaller than " + MIN_RSA_BITS + " bits");
        }
    }

    /** Wraps a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo. */
    private static byte[] wrapPkcs1(byte[] pkcs1) {
        byte[] algId = {0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
        byte[] version = {0x02, 0x01, 0x00};
        byte[] octet = concat(new byte[]{0x04}, derLength(pkcs1.length), pkcs1);
        byte[] body = concat(version, algId, octet);
        return concat(new byte[]{0x30}, derLength(body.length), body);
    }

    private static byte[] derLength(int len) {
        if (len < 0x80) {
            return new byte[]{(byte) len};
        }
        if (len <= 0xff) {
            return new byte[]{(byte) 0x81, (byte) len};
        }
        if (len <= 0xffff) {
            return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len};
        }
        return new byte[]{(byte) 0x83, (byte) (len >> 16), (byte) (len >> 8), (byte) len};
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
