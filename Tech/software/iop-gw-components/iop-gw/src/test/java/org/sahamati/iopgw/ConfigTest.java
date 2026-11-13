package org.sahamati.iopgw;

import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.config.ConfigLoader;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Configuration validation. */
class ConfigTest {

    private static String errors(TestNet net, TestNet.Party p, String extra) {
        ConfigLoader.ConfigException e = assertThrows(ConfigLoader.ConfigException.class,
                () -> new ConfigLoader(net.env()).parse(yamlOf(net, p) + extra));
        return String.join("\n", e.errors);
    }

    private static String yamlOf(TestNet net, TestNet.Party p) throws Exception {
        java.lang.reflect.Method m = TestNet.Party.class.getDeclaredMethod("yaml", List.class);
        m.setAccessible(true);
        return (String) m.invoke(p, List.of(net.get("fiu-test-201"), net.get("aa-test-202")));
    }

    @Test
    void generatedTestConfigurationParses() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-201", "FIU", "FIU");
            net.add("aa-test-202", "AA", "AA");
            fiu.linked = List.of("aa-test-202");
            Config c = net.config(fiu);
            assertEquals("FIU", c.mode);
            assertEquals("/fiu-core", c.core.pathPrefix);
            assertEquals(TestNet.GW_TOKEN, c.secret("gwApi.token"));
        }
    }

    @Test
    void strictYaml() {
        ConfigLoader l = new ConfigLoader(Map.of());
        assertTrue(assertThrows(ConfigLoader.ConfigException.class, () -> l.parse("")).errors.get(0).contains("empty"));
        assertTrue(assertThrows(ConfigLoader.ConfigException.class, () -> l.parse("mode: AA\n---\nmode: FIU\n"))
                .errors.get(0).contains("single YAML document"));
        assertTrue(assertThrows(ConfigLoader.ConfigException.class, () -> l.parse("mode: AA\nnoSuchKey: 1\n"))
                .errors.get(0).contains("unknown configuration key 'noSuchKey'"));
        assertTrue(assertThrows(ConfigLoader.ConfigException.class, () -> l.parse("mode: AA\ngwApi: {listenAddr: \"x:1\", noSuchKey: 2}\n"))
                .errors.get(0).contains("gwApi"));
    }

    @Test
    void secretsMustBeEnvReferencesAndAllErrorsAreReportedTogether() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-201", "FIU", "FIU");
            net.add("aa-test-202", "AA", "AA");
            fiu.linked = List.of("aa-test-202");
            String yaml = yamlOf(net, fiu).replace("token: \"${GW_TOKEN}\"", "token: literal-secret")
                    .replace("hopPreference", "x");
            ConfigLoader.ConfigException e = assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(yaml + "hopPreference: {interAAs: [aa-test-202]}\n"));
            String all = String.join("\n", e.errors);
            assertTrue(all.contains("gwApi.token must be an ${ENV_VAR} reference"), all);
            assertTrue(all.contains("hopPreference.interAAs is not allowed in FIU mode"), all);
        }
    }

    @Test
    void connectorModeRefusesAaOnlySettings() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-201", "FIU", "FIU");
            net.add("aa-test-202", "AA", "AA");
            fiu.linked = List.of("aa-test-202");
            String yaml = yamlOf(net, fiu).replace("forwarding: {timeoutSeconds: 3}",
                    "forwarding: {timeoutSeconds: 3, httpRetries: 1, preserveUnknownEnvelopeFields: true}");
            ConfigLoader.ConfigException e = assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(yaml));
            String all = String.join("\n", e.errors);
            assertTrue(all.contains("forwarding.httpRetries is only allowed in AA mode"), all);
            assertTrue(all.contains("forwarding.preserveUnknownEnvelopeFields is only allowed in AA mode"), all);
        }
    }

    @Test
    void onlyRs256AndNoTerminatingSection() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-201", "FIU", "FIU");
            net.add("aa-test-202", "AA", "AA");
            fiu.linked = List.of("aa-test-202");
            String yaml = yamlOf(net, fiu);
            ConfigLoader.ConfigException ps = assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(yaml.replace("jws: {algorithm: RS256}", "jws: {algorithm: PS256}")));
            assertTrue(String.join("\n", ps.errors).contains("jws.algorithm must be RS256"), String.join("\n", ps.errors));
            ConfigLoader.ConfigException term = assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(yaml + "terminating: {plaintextPaths: []}\n"));
            assertTrue(term.errors.get(0).contains("unknown configuration key 'terminating'"), term.errors.get(0));
        }
    }

    @Test
    void unsetEnvironmentVariableIsRefused() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-201", "FIU", "FIU");
            net.add("aa-test-202", "AA", "AA");
            fiu.linked = List.of("aa-test-202");
            net.env().remove("GW_TOKEN");
            String all = errors(net, fiu, "");
            assertTrue(all.contains("environment variable GW_TOKEN is not set or empty"), all);
        }
    }

    @Test
    void keysFromTheCoreMustBeHttpsWithAToken() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-201", "FIU", "FIU");
            net.add("aa-test-202", "AA", "AA");
            fiu.linked = List.of("aa-test-202");
            // core.baseUrl is http in the test net: the default key URL is refused
            String yaml = yamlOf(net, fiu).replaceFirst("signingKey: \\{source: file, kid: [^}]*}", "signingKey: {source: api}");
            String all = String.join("\n", assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(yaml)).errors);
            assertTrue(all.contains("self.signingKey: the key URL (core.baseUrl, the default) must be https"), all);
            assertTrue(all.contains("self.signingKey.token is required with source api"), all);

            // an http core.keysBaseUrl is refused; an https one is the default for both key types
            String http = yamlOf(net, fiu).replace("core: {baseUrl:", "core: {keysBaseUrl: \"http://127.0.0.1:1\", baseUrl:");
            assertTrue(String.join("\n", assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(http)).errors).contains("core.keysBaseUrl must be an absolute https URL"));
            net.env().put("KEYS_TOKEN", "synthetic-keys-token");
            String ok = yamlOf(net, fiu).replace("core: {baseUrl:", "core: {keysBaseUrl: \"https://127.0.0.1:9\", baseUrl:")
                    .replaceFirst("signingKey: \\{source: file, kid: [^}]*}", "signingKey: {source: api, token: \"\\${KEYS_TOKEN}\"}")
                    .replaceFirst("decryptionKeys: \\{source: file, keys: \\[[^]]*]}", "decryptionKeys: {source: api, token: \"\\${KEYS_TOKEN}\"}");
            Config c = new ConfigLoader(net.env()).parse(ok);
            assertEquals("https://127.0.0.1:9/fiu-core/keys/signing", c.keyUrl("signing"));
            assertEquals("https://127.0.0.1:9/fiu-core/keys/decryption", c.keyUrl("decryption"));
            assertEquals(3600, c.self.signingKey.refreshSeconds);
            // mixing file fields with source api is refused
            String mixed = ok.replace("signingKey: {source: api,", "signingKey: {source: api, kid: k1,");
            assertTrue(String.join("\n", assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(mixed)).errors).contains("belong to source file"));
        }
    }

    @Test
    void fileKeyDatesAreChecked() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-201", "FIU", "FIU");
            net.add("aa-test-202", "AA", "AA");
            fiu.linked = List.of("aa-test-202");
            String yaml = yamlOf(net, fiu).replaceFirst("signingKey: \\{source: file, kid:",
                    "signingKey: {source: file, applied: \"2026-11-09\", expiry: \"2026-11-01\", kid:");
            assertTrue(String.join("\n", assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(yaml)).errors).contains("self.signingKey.expiry must be after applied"));
            String bad = yamlOf(net, fiu).replaceFirst("signingKey: \\{source: file, kid:", "signingKey: {source: file, applied: \"09/11/2026\", kid:");
            assertTrue(String.join("\n", assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(bad)).errors).contains("is not an RFC 3339 or YYYY-MM-DD date"));
        }
    }

    @Test
    void issuerJwksRules() throws Exception {
        try (TestNet net = new TestNet()) {
            TestNet.Party fiu = net.add("fiu-test-201", "FIU", "FIU");
            net.add("aa-test-202", "AA", "AA");
            fiu.linked = List.of("aa-test-202");
            String base = yamlOf(net, fiu);
            String jwt = base.substring(0, base.indexOf("apiKey:")) + "apiKey:\n  mode: jwt\n  issuerKeysUrl: \"%s\"\n%s"
                    + base.substring(base.indexOf("jws:"));
            String http = String.format(jwt, "http://127.0.0.1:1/jwks", "");
            assertTrue(String.join("\n", assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(http)).errors).contains("apiKey.issuerKeysUrl must be an absolute https URL"));
            String both = String.format(jwt, "https://127.0.0.1:1/jwks", "  issuerPublicKeys: [\"" + net.dir.resolve("aa-test-202-sig.pub.pem") + "\"]\n");
            assertTrue(String.join("\n", assertThrows(ConfigLoader.ConfigException.class,
                    () -> new ConfigLoader(net.env()).parse(both)).errors).contains("exclusive"));
            Config c = new ConfigLoader(net.env()).parse(String.format(jwt, "https://127.0.0.1:1/jwks", ""));
            assertEquals(3600, c.apiKey.issuerKeysRefreshSeconds);
            String refreshWithoutUrl = base.replace("  mode: static\n", "  mode: static\n  issuerKeysRefreshSeconds: 10\n");
            assertThrows(ConfigLoader.ConfigException.class, () -> new ConfigLoader(net.env()).parse(refreshWithoutUrl));
        }
    }
}
