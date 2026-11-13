package org.sahamati.iopgw.mocks;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * The mock's keys and TLS certificate: generated at start-up (never stored in the repository), or
 * read from files the configuration names.
 */
final class Pki {
    private Pki() {}

    static final char[] TRUSTSTORE_PASSWORD = "changeit".toCharArray();

    static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    /** A self-signed certificate for localhost and 127.0.0.1, valid for 7 days. */
    static X509Certificate selfSigned(KeyPair kp) throws Exception {
        return selfSigned(kp, java.util.List.of("localhost", "127.0.0.1"));
    }

    /** A self-signed certificate valid for {@code hosts}: DNS names, or IP addresses. */
    static X509Certificate selfSigned(KeyPair kp, java.util.List<String> hosts) throws Exception {
        X500Name name = new X500Name("CN=iop-gw-mocks (testing only)");
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + 7L * 86_400_000L),
                name, kp.getPublic());
        GeneralName[] sans = hosts.stream()
                .map(h -> h.matches("[0-9.]+|[0-9a-fA-F:]*:[0-9a-fA-F:]*")
                        ? new GeneralName(GeneralName.iPAddress, h) : new GeneralName(GeneralName.dNSName, h))
                .toArray(GeneralName[]::new);
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    static SSLContext serverContext(KeyPair kp, X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("mock", kp.getPrivate(), TRUSTSTORE_PASSWORD, new Certificate[]{cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, TRUSTSTORE_PASSWORD);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    /** A PKCS#12 truststore holding the mock's certificate, for the gateway's JVM. */
    static void writeTruststore(X509Certificate cert, Path file) throws Exception {
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("iop-gw-mocks", cert);
        try (OutputStream out = Files.newOutputStream(file)) {
            ts.store(out, TRUSTSTORE_PASSWORD);
        }
    }

    /** The first certificate in a PEM file. */
    static X509Certificate readCertificate(Path file) throws Exception {
        try (java.io.InputStream in = Files.newInputStream(file)) {
            return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    /** An RSA key pair from a PEM private key (PKCS#8, "PRIVATE KEY"); the public key is derived from it. */
    static KeyPair readRsaKey(Path file) throws Exception {
        String pem = Files.readString(file);
        int a = pem.indexOf("-----BEGIN PRIVATE KEY-----");
        int b = pem.indexOf("-----END PRIVATE KEY-----");
        if (a < 0 || b < a) {
            throw new java.io.IOException("not a PKCS#8 PEM private key (\"BEGIN PRIVATE KEY\"): " + file);
        }
        byte[] der = Base64.getMimeDecoder().decode(pem.substring(a + 27, b));
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
        java.security.interfaces.RSAPrivateCrtKey priv =
                (java.security.interfaces.RSAPrivateCrtKey) kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
        java.security.PublicKey pub = kf.generatePublic(new java.security.spec.RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
        return new KeyPair(pub, priv);
    }

    static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }
}
