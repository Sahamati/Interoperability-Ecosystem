package org.sahamati.iopgw;

import org.junit.jupiter.api.Test;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.config.ConfigLoader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The {@code multiTenant} setting and entity file validation. */
class MultiTenantConfigTest {

    private static String errors(TestNet net, String yaml) {
        return String.join("\n", assertThrows(ConfigLoader.ConfigException.class, () -> new ConfigLoader(net.env()).parse(yaml)).errors);
    }

    /** A single-tenant FIU main file, and a multi-tenant FIU main file with one entity, in one test net. */
    private record Files2(TestNet net, String single, String multi, TestNet.Host host) {}

    private static Files2 files() throws Exception {
        TestNet net = new TestNet();
        TestNet.Party fiu = net.add("fiu-test-f01", "FIU", "FIU");
        TestNet.Host host = net.addHost("cfg", "FIU", "fiu-test-f02");
        TestNet.Party aa = net.add("aa-test-f11", "AA", "AA");
        fiu.linked = List.of(aa.id);
        List<TestNet.Party> all = new ArrayList<>(List.of(fiu, host.entity("fiu-test-f02"), aa));
        return new Files2(net, fiu.yaml(all), host.mainYaml(all), host);
    }

    /** On, off, true and false are accepted; absent means off; any other value stops start-up. */
    @Test
    void multiTenantValues() throws Exception {
        Files2 f = files();
        try (TestNet net = f.net()) {
            ConfigLoader l = new ConfigLoader(net.env());
            assertFalse(l.parse(f.single()).isMultiTenant(), "absent: off");
            assertFalse(new ConfigLoader(net.env()).parse("multiTenant: off\n" + f.single()).isMultiTenant());
            assertFalse(new ConfigLoader(net.env()).parse("multiTenant: false\n" + f.single()).isMultiTenant());
            String multiBody = f.multi().replace("multiTenant: on\n", "");
            assertTrue(new ConfigLoader(net.env()).parse("multiTenant: on\n" + multiBody).isMultiTenant());
            assertTrue(new ConfigLoader(net.env()).parse("multiTenant: true\n" + multiBody).isMultiTenant());
            for (String bad : List.of("maybe", "yes", "On", "1")) {
                assertTrue(errors(net, "multiTenant: " + bad + "\n" + f.single()).contains("multiTenant must be on or off"), bad);
            }
        }
    }

    /** Single-tenant with entityConfigPath set: ignored with a warning, the main file's entity is used. */
    @Test
    void singleTenantIgnoresTheEntityFolder() throws Exception {
        Files2 f = files();
        try (TestNet net = f.net()) {
            ConfigLoader l = new ConfigLoader(net.env());
            Config c = l.parse(f.single() + "entityConfigPath: \"" + f.host().entityDir + "\"\nentityRescanSeconds: 30\n");
            assertFalse(c.isMultiTenant());
            assertEquals("fiu-test-f01", c.single.id);
            assertTrue(l.warnings().stream().anyMatch(w -> w.startsWith("entityConfigPath is ignored with multiTenant: off")), l.warnings().toString());
            assertTrue(l.warnings().stream().anyMatch(w -> w.startsWith("entityRescanSeconds is ignored")), l.warnings().toString());
        }
    }

    /** The self section and entity-file settings in a multi-tenant main file, and AA mode with on, stop start-up. */
    @Test
    void multiTenantRefusals() throws Exception {
        Files2 f = files();
        try (TestNet net = f.net()) {
            Config ok = new ConfigLoader(net.env()).parse(f.multi());
            assertTrue(ok.isMultiTenant());
            assertNull(ok.single);
            assertEquals(1, ok.entityRescanSeconds);

            assertTrue(errors(net, f.multi() + "self:\n  id: fiu-test-f02\n").contains("self is not allowed in the main file with multiTenant: on"));
            assertTrue(errors(net, f.multi() + "core: {baseUrl: \"http://127.0.0.1:1\"}\n").contains("core is not allowed in the main file"));
            assertTrue(errors(net, f.multi() + "linkedAAs: {source: config, aas: [aa-test-f11]}\n").contains("linkedAAs is not allowed in the main file"));
            assertTrue(errors(net, f.multi() + "hopPreference: {connectedAAs: [aa-test-f11]}\n").contains("hopPreference is not allowed"));
            assertTrue(errors(net, f.multi().replace("  httpListenAddr:", "  token: \"${GW_TOKEN}\"\n  httpListenAddr:"))
                    .contains("gwApi.token is not allowed in the main file"));
            assertTrue(errors(net, f.multi().replace("mode: FIU", "mode: AA").replace("aig:\n  aa:\n    - aa-unused: [aa-unused-2]\n",
                    "aig:\n  fiu:\n    - fiu-x: [aa-test-f11]\n  fip:\n    - fip-x: [aa-test-f11]\n"))
                    .contains("multiTenant: on is not allowed in AA mode"));

            assertTrue(errors(net, f.multi().replace("entityRescanSeconds: 1", "entityRescanSeconds: 0")).contains("entityRescanSeconds must be positive"));
            assertTrue(errors(net, f.multi().replace("entityRescanSeconds: 1", "entityRescanSeconds: -5")).contains("entityRescanSeconds must be positive"));
            assertEquals(60, new ConfigLoader(net.env()).parse(f.multi().replace("entityRescanSeconds: 1\n", "")).entityRescanSeconds, "default 60");
            assertTrue(errors(net, f.multi().replace("entityConfigPath: \"" + f.host().entityDir, "entityConfigPath: \"" + f.host().entityDir + "-missing"))
                    .contains("entityConfigPath: folder not found"));
            assertTrue(errors(net, f.multi().replaceFirst("entityConfigPath: [^\\n]*\\n", "")).contains("entityConfigPath is required with multiTenant: on"));
        }
    }

    /** An entity file is validated like the single-tenant settings; problems make it invalid. */
    @Test
    void entityFileValidation() throws Exception {
        Files2 f = files();
        try (TestNet net = f.net()) {
            Config main = new ConfigLoader(net.env()).parse(f.multi());
            TestNet.Party e = f.host().entity("fiu-test-f02");
            String good = f.host().entityYaml(e);

            ConfigLoader.EntityLoad ok = new ConfigLoader(net.env()).entity(main, "f02.yaml", good);
            assertTrue(ok.valid(), ok.errors().toString());
            assertTrue(ok.enabled());
            assertEquals("fiu-test-f02", ok.settings().id);
            assertEquals("/fiu-core", ok.settings().core.pathPrefix);

            ConfigLoader.EntityLoad disabled = new ConfigLoader(net.env()).entity(main, "f02.yaml", good.replace("enable: true", "enable: false"));
            assertTrue(disabled.valid() && !disabled.enabled());

            // an http key URL makes the file invalid
            net.env().put("KEYS_TOKEN", "synthetic-keys-token");
            String httpKeys = good.replaceFirst("signingKey: \\{[^\\n]*\\n", "signingKey: {source: api, token: \"\\${KEYS_TOKEN}\"}\n");
            ConfigLoader.EntityLoad bad = new ConfigLoader(net.env()).entity(main, "f02.yaml", httpKeys);
            assertFalse(bad.valid());
            assertTrue(String.join("\n", bad.errors()).contains("entity file f02.yaml: signingKey: the key URL (core.baseUrl, the default) must be https"),
                    bad.errors().toString());

            // an empty environment variable makes the file invalid
            net.env().remove(e.gwTokenEnv());
            ConfigLoader.EntityLoad unset = new ConfigLoader(net.env()).entity(main, "f02.yaml", good);
            assertTrue(String.join("\n", unset.errors()).contains("entity file f02.yaml: gwApi.token: environment variable " + e.gwTokenEnv()), unset.errors().toString());
            net.env().put(e.gwTokenEnv(), e.gwToken());

            // strict YAML: an unknown key; the entityId is still read, so a loaded entity keeps its settings
            ConfigLoader.EntityLoad unknown = new ConfigLoader(net.env()).entity(main, "f02.yaml", good + "noSuchKey: 1\n");
            assertTrue(String.join("\n", unknown.errors()).contains("unknown entity file key 'noSuchKey'"), unknown.errors().toString());
            assertEquals("fiu-test-f02", unknown.entityId());

            // with tokenService in the main file: the credentials file must be the entity's
            Path creds = net.dir.resolve("creds-other.json");
            Files.writeString(creds, "{\"entityId\":\"fiu-test-other\",\"entitySecret\":\"synthetic\"}");
            Config withTs = new ConfigLoader(net.env()).parse(f.multi() + "tokenService: {baseUrl: \"http://127.0.0.1:1\"}\n");
            String tsEntity = good.replaceFirst("outboundApiKey: [^\\n]*\\n", "") + "tokenService: {credentialsFile: \"" + creds + "\"}\n";
            ConfigLoader.EntityLoad other = new ConfigLoader(net.env()).entity(withTs, "f02.yaml", tsEntity);
            assertTrue(String.join("\n", other.errors()).contains("tokenService.credentialsFile is for another entity, not fiu-test-f02"), other.errors().toString());
        }
    }
}
