package org.sahamati.iopgw.sources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.rocksdb.CompactRangeOptions;
import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.WriteOptions;
import org.sahamati.iopgw.http.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The persistent cache: an embedded key-value store on local disk under
 * {@code cache.dir}, created {@code 0700}, one gateway process per directory.
 *
 * <ul>
 *   <li>{@code rocksdb} (default): RocksDB, synchronous writes, compacted every 10 minutes so that
 *       repeated rewrites do not grow the store. RocksDB's own LOCK file enforces one process.</li>
 *   <li>{@code file}: one JSON file per key, written to a temporary file and atomically renamed
 *       (no growth, so no compaction); a {@code .lock} file enforces one process. For hosts where
 *       the RocksDB native library cannot load.</li>
 * </ul>
 *
 * Not encrypted at rest, so nothing secret is ever saved: no private keys and no configured
 * api-keys. Every value is a snapshot {@code {key, savedAt, data}}.
 */
public final class Store implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(Store.class);

    public static final long COMPACT_EVERY_SECONDS = 600;

    /** A saved value and when it was saved. */
    public record Snapshot(Instant savedAt, JsonNode data) {}

    private interface Engine extends AutoCloseable {
        void put(String key, byte[] value) throws IOException;

        byte[] get(String key) throws IOException;

        void compact();

        @Override
        void close();
    }

    private final Path dir;
    private final Engine engine;
    private final ScheduledExecutorService compactor;

    private Store(Path dir, Engine engine) {
        this.dir = dir;
        this.engine = engine;
        this.compactor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "iopgw-cache-compact");
            t.setDaemon(true);
            return t;
        });
        compactor.scheduleAtFixedRate(engine::compact, COMPACT_EVERY_SECONDS, COMPACT_EVERY_SECONDS, TimeUnit.SECONDS);
    }

    public static Store open(Path dir) throws IOException {
        return open(dir, "rocksdb");
    }

    /** Opens (creating {@code 0700}) the store; failure stops start-up. */
    public static Store open(Path dir, String engine) throws IOException {
        boolean posix = dir.getFileSystem().supportedFileAttributeViews().contains("posix");
        Set<PosixFilePermission> rwx = PosixFilePermissions.fromString("rwx------");
        if (!Files.exists(dir)) {
            if (posix) {
                Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(rwx));
            } else {
                Files.createDirectories(dir);
            }
        } else if (!Files.isDirectory(dir)) {
            throw new IOException("cache.dir is not a directory");
        }
        if (posix) {
            Files.setPosixFilePermissions(dir, rwx); // whatever the umask or a previous owner left
        }
        Engine e = switch (engine) {
            case "rocksdb" -> Rocks.open(dir);
            case "file" -> FileEngine.open(dir);
            default -> throw new IOException("cache.engine must be rocksdb or file");
        };
        LOG.atInfo().addKeyValue("engine", engine).log("persistent cache opened");
        return new Store(dir, e);
    }

    public Path dir() {
        return dir;
    }

    /** Replaces the snapshot under {@code key}. A failure is logged; the in-memory copy still serves. */
    public void save(String key, JsonNode data) {
        ObjectNode o = Json.object();
        o.put("key", key);
        o.put("savedAt", Instant.now().toString());
        o.set("data", data);
        try {
            engine.put(key, Json.bytes(o));
        } catch (IOException e) {
            LOG.atWarn().addKeyValue("key", key).addKeyValue("error", e.getClass().getSimpleName()).log("cache save failed");
        }
    }

    /** The snapshot under {@code key}, or empty when absent or unreadable. */
    public Optional<Snapshot> load(String key) {
        try {
            byte[] v = engine.get(key);
            if (v == null) {
                return Optional.empty();
            }
            JsonNode o = Json.MAPPER.readTree(new String(v, StandardCharsets.UTF_8));
            if (o == null || !key.equals(Json.text(o, "key")) || o.get("data") == null) {
                LOG.atWarn().addKeyValue("key", key).log("cache entry malformed; ignored");
                return Optional.empty();
            }
            return Optional.of(new Snapshot(Instant.parse(o.get("savedAt").asText()), o.get("data")));
        } catch (Exception e) {
            LOG.atWarn().addKeyValue("key", key).addKeyValue("error", e.getClass().getSimpleName()).log("cache entry unreadable; ignored");
            return Optional.empty();
        }
    }

    /** Compacts now (also done every 10 minutes). */
    public void compact() {
        engine.compact();
    }

    @Override
    public void close() {
        compactor.shutdownNow();
        engine.close();
    }

    // ---------------- RocksDB ----------------

    private static final class Rocks implements Engine {
        static {
            RocksDB.loadLibrary();
        }

        private final Options options;
        private final WriteOptions write;
        private final RocksDB db;

        private Rocks(Options options, WriteOptions write, RocksDB db) {
            this.options = options;
            this.write = write;
            this.db = db;
        }

        static Rocks open(Path dir) throws IOException {
            Options o = new Options().setCreateIfMissing(true).setKeepLogFileNum(2).setMaxManifestFileSize(4L << 20);
            WriteOptions w = new WriteOptions().setSync(true);
            try {
                return new Rocks(o, w, RocksDB.open(o, dir.toString()));
            } catch (RocksDBException e) {
                w.close();
                o.close();
                String msg = String.valueOf(e.getMessage());
                throw new IOException(msg.contains("lock") ? "cache.dir is in use by another gateway process"
                        : "cache store cannot be opened: " + msg.lines().findFirst().orElse(""));
            }
        }

        @Override
        public void put(String key, byte[] value) throws IOException {
            try {
                db.put(write, key.getBytes(StandardCharsets.UTF_8), value);
            } catch (RocksDBException e) {
                throw new IOException("rocksdb put failed");
            }
        }

        @Override
        public byte[] get(String key) throws IOException {
            try {
                return db.get(key.getBytes(StandardCharsets.UTF_8));
            } catch (RocksDBException e) {
                throw new IOException("rocksdb get failed");
            }
        }

        @Override
        public void compact() {
            try (CompactRangeOptions c = new CompactRangeOptions()) {
                db.compactRange(null, null, null, c);
            } catch (RocksDBException e) {
                LOG.atWarn().log("cache compaction failed");
            }
        }

        @Override
        public void close() {
            db.close();
            write.close();
            options.close();
        }
    }

    // ---------------- one file per key ----------------

    private static final class FileEngine implements Engine {
        private final Path dir;
        private final FileChannel lockChannel;
        private final FileLock lock;

        private FileEngine(Path dir, FileChannel lockChannel, FileLock lock) {
            this.dir = dir;
            this.lockChannel = lockChannel;
            this.lock = lock;
        }

        static FileEngine open(Path dir) throws IOException {
            FileChannel ch = FileChannel.open(dir.resolve(".lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            FileLock l;
            try {
                l = ch.tryLock();
            } catch (IOException | RuntimeException e) {
                ch.close();
                throw new IOException("cache.dir is in use by another gateway process");
            }
            if (l == null) {
                ch.close();
                throw new IOException("cache.dir is in use by another gateway process");
            }
            return new FileEngine(dir, ch, l);
        }

        private Path file(String key) {
            return dir.resolve(key.replaceAll("[^A-Za-z0-9._-]", "_") + ".json");
        }

        @Override
        public void put(String key, byte[] value) throws IOException {
            Path target = file(key);
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ch.write(ByteBuffer.wrap(value));
                ch.force(true);
            }
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }

        @Override
        public byte[] get(String key) throws IOException {
            Path f = file(key);
            return Files.isRegularFile(f) ? Files.readAllBytes(f) : null;
        }

        @Override
        public void compact() {
            // each write replaces its file: nothing grows
        }

        @Override
        public void close() {
            try {
                lock.release();
                lockChannel.close();
            } catch (IOException ignored) {
                // shutting down
            }
        }
    }
}
