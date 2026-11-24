package org.sahamati.iopgw.tenant;

import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.config.ConfigLoader;
import org.sahamati.iopgw.config.EntitySettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Multi-tenant mode: reads the entity folder at start-up and every {@code entityRescanSeconds}.
 * A new enabled file loads its entity at once; a deleted or disabled file
 * unloads it; an invalid file is skipped with an error, and an entity already loaded keeps its
 * previous settings. A changed file loads the new settings next to the old ones: the old version
 * keeps serving until the new one has its signing and decryption keys, a {@code linkedAAs} list and
 * its access token, then takes over.
 */
public final class TenantManager implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(TenantManager.class);
    /** How often a changed entity's new settings are checked for readiness. */
    private static final long PENDING_CHECK_SECONDS = 1;

    private final Config main;
    private final Map<String, String> env;
    private final Tenants tenants;
    private final Tenant.Context ctx;
    private final Path dir;
    /** New settings of changed entities, waiting to take over: entity id -> new version. */
    private final Map<String, Tenant> pending = new HashMap<>();
    /** The problem last logged per entity file, so that a rescan does not repeat it. */
    private final Map<String, String> reported = new HashMap<>();
    private final ScheduledExecutorService exec;

    public TenantManager(Config main, Map<String, String> env, Tenants tenants, Tenant.Context ctx) {
        this.main = main;
        this.env = env;
        this.tenants = tenants;
        this.ctx = ctx;
        this.dir = Path.of(main.entityConfigPath);
        this.exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "iopgw-entities");
            t.setDaemon(true);
            return t;
        });
    }

    /** Reads the folder now, then schedules the rescans. */
    public void start() {
        scan();
        if (tenants.count() == 0) {
            LOG.atWarn().addKeyValue("entityConfigPath", main.entityConfigPath)
                    .log("no entity loaded: /iop calls get 503 and internal API calls 400 until an entity file loads");
        }
        long every = main.entityRescanSeconds;
        exec.scheduleWithFixedDelay(this::scanQuietly, every, every, TimeUnit.SECONDS);
        exec.scheduleWithFixedDelay(this::checkPendingQuietly, PENDING_CHECK_SECONDS, PENDING_CHECK_SECONDS, TimeUnit.SECONDS);
    }

    private void scanQuietly() {
        try {
            scan();
        } catch (RuntimeException e) {
            LOG.atError().addKeyValue("error", e.getClass().getSimpleName()).log("entity rescan failed; entities unchanged");
        }
    }

    private void checkPendingQuietly() {
        try {
            checkPending();
        } catch (RuntimeException e) {
            LOG.atError().addKeyValue("error", e.getClass().getSimpleName()).log("entity reload check failed");
        }
    }

    /** One read of the entity folder. */
    public synchronized void scan() {
        List<Path> files;
        try (Stream<Path> s = Files.list(dir)) {
            files = s.filter(Files::isRegularFile)
                    .filter(p -> {
                        String n = p.getFileName().toString();
                        return n.endsWith(".yaml") || n.endsWith(".yml");
                    })
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .toList();
        } catch (IOException e) {
            LOG.atError().addKeyValue("entityConfigPath", main.entityConfigPath).log("entity folder unreadable; entities unchanged");
            return;
        }

        ConfigLoader loader = new ConfigLoader(env);
        Map<String, ConfigLoader.EntityLoad> wanted = new LinkedHashMap<>();
        Set<String> claimed = new HashSet<>(); // ids named by an enabled file that sorts earlier
        Set<String> keep = new HashSet<>();    // ids whose file is invalid now: the loaded version stays
        Set<String> seenFiles = new HashSet<>();
        for (Path f : files) {
            String name = f.getFileName().toString();
            seenFiles.add(name);
            String text;
            try {
                text = Files.readString(f, StandardCharsets.UTF_8);
            } catch (IOException e) {
                report(name, "unreadable", List.of("entity file " + name + " cannot be read; skipped"));
                continue;
            }
            ConfigLoader.EntityLoad l = loader.entity(main, name, text);
            List<String> warnings = new ArrayList<>(loader.warnings());
            loader.warnings().clear();
            if (!l.valid()) {
                report(name, text + l.errors(), l.errors());
                // an entity already loaded from this file (or named in it) keeps its previous settings
                String id = l.entityId() != null ? l.entityId() : loadedFrom(name);
                if (id != null && claimed.add(id)) {
                    keep.add(id);
                }
                continue;
            }
            if (!l.enabled()) {
                report(name, null, List.of());
                continue;
            }
            if (!claimed.add(l.entityId())) {
                report(name, "duplicate:" + text, List.of("entity file " + name + ": entityId " + l.entityId()
                        + " is already used by an entity file whose name sorts first; skipped"));
                continue;
            }
            reportedWarnings(name, text, warnings);
            wanted.put(l.entityId(), l);
        }
        reported.keySet().removeIf(f -> !seenFiles.contains(f) && !f.startsWith("warn:"));
        reported.keySet().removeIf(f -> f.startsWith("warn:") && !seenFiles.contains(f.substring(5)));

        // deleted, disabled, or no longer the file that names the entity: unload
        for (String id : tenants.ids()) {
            if (!wanted.containsKey(id) && !keep.contains(id)) {
                dropPending(id);
                Tenant old = tenants.remove(id);
                if (old != null) {
                    old.close();
                    LOG.atInfo().addKeyValue("entity", id).log("entity unloaded (entity file deleted or not enabled)");
                }
            }
        }
        for (String id : new ArrayList<>(pending.keySet())) {
            if (!wanted.containsKey(id)) {
                dropPending(id); // the change became invalid or was removed: the loaded version stays
            }
        }

        for (Map.Entry<String, ConfigLoader.EntityLoad> e : wanted.entrySet()) {
            String id = e.getKey();
            EntitySettings s = e.getValue().settings();
            Tenant current = tenants.get(id).orElse(null);
            if (current != null && same(current.settings, s)) {
                dropPending(id);
                reported.remove(s.file);
                continue;
            }
            Tenant waiting = pending.get(id);
            if (waiting != null && same(waiting.settings, s)) {
                continue;
            }
            dropPending(id);
            String conflict = fileKidConflict(s, id);
            if (conflict != null) {
                report(s.file, "kid:" + s.contentHash, List.of("entity file " + s.file + ": " + conflict
                        + (current == null ? "; entity not loaded" : "; the previous settings stay in use")));
                continue;
            }
            Tenant t;
            try {
                t = Tenant.load(ctx, s, kid -> tenants.kidOwner(kid, id));
            } catch (Exception ex) {
                report(s.file, "load:" + s.contentHash, List.of("entity file " + s.file + ": cannot load the entity ("
                        + ex.getClass().getSimpleName() + ")" + (current == null ? "" : "; the previous settings stay in use")));
                continue;
            }
            if (t.kidConflict() != null) {
                t.close();
                report(s.file, "kid:" + s.contentHash, List.of("entity file " + s.file + ": " + t.kidConflict()
                        + (current == null ? "; entity not loaded" : "; the previous settings stay in use")));
                continue;
            }
            reported.remove(s.file);
            if (current == null) {
                tenants.put(t);
                LOG.atInfo().addKeyValue("entity", id).addKeyValue("file", s.file).log("entity loaded");
            } else {
                pending.put(id, t);
                LOG.atInfo().addKeyValue("entity", id).addKeyValue("file", s.file)
                        .log("entity file changed: the new settings are loading; the previous settings serve until they are ready");
            }
        }
        checkPending();
    }

    /** Swaps in every changed entity whose new settings are ready. */
    public synchronized void checkPending() {
        for (String id : new ArrayList<>(pending.keySet())) {
            Tenant next = pending.get(id);
            if (next.ready()) {
                pending.remove(id);
                Tenant old = tenants.put(next);
                if (old != null) {
                    old.close();
                }
                LOG.atInfo().addKeyValue("entity", id).addKeyValue("file", next.settings.file).log("entity reloaded with the new settings");
            }
        }
    }

    /** The id of the entity loaded (or loading) from entity file {@code file}, or null. */
    private String loadedFrom(String file) {
        for (Tenant t : tenants.all()) {
            if (file.equals(t.settings.file)) {
                return t.id;
            }
        }
        for (Tenant t : pending.values()) {
            if (file.equals(t.settings.file)) {
                return t.id;
            }
        }
        return null;
    }

    private void dropPending(String id) {
        Tenant t = pending.remove(id);
        if (t != null) {
            t.close();
        }
    }

    private static boolean same(EntitySettings a, EntitySettings b) {
        return Objects.equals(a.contentHash, b.contentHash) && Objects.equals(a.file, b.file);
    }

    /** For key files: a decryption {@code kid} already used by another loaded entity. */
    private String fileKidConflict(EntitySettings s, String id) {
        if (!"file".equals(s.decryptionKeys.source)) {
            return null;
        }
        for (var k : s.decryptionKeys.keys) {
            String owner = tenants.kidOwner(k.kid, id);
            if (owner != null) {
                return "decryption key kid " + k.kid + " is already used by entity " + owner;
            }
        }
        return null;
    }

    /** Logs a file's problem once (until the file or the problem changes). */
    private void report(String file, String signature, List<String> errors) {
        if (signature == null) {
            reported.remove(file);
            return;
        }
        if (signature.equals(reported.put(file, signature))) {
            return;
        }
        for (String err : errors) {
            LOG.atError().addKeyValue("file", file).addKeyValue("error", err).log("entity file not used");
        }
    }

    private void reportedWarnings(String file, String text, List<String> warnings) {
        if (warnings.isEmpty() || text.equals(reported.put("warn:" + file, text))) {
            return;
        }
        for (String w : warnings) {
            LOG.atWarn().addKeyValue("file", file).log(w);
        }
    }

    /** Unloads every entity (shutdown). */
    @Override
    public synchronized void close() {
        exec.shutdownNow();
        for (String id : new ArrayList<>(pending.keySet())) {
            dropPending(id);
        }
        for (String id : tenants.ids()) {
            Tenant t = tenants.remove(id);
            if (t != null) {
                t.close();
            }
        }
    }
}
