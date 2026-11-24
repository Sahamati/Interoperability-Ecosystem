package org.sahamati.iopgw.obs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Supplier;

/**
 * Interval counters written as {@code IOPGW_STATS} records per interval and at shutdown:
 * one record per loaded entity, plus one for entity {@code -} (calls refused before their entity
 * was known) in multi-tenant mode; in single-tenant mode, one record for the one entity.
 */
public final class Stats implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(Logs.AUDIT_LOGGER);
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .withZone(ZoneOffset.UTC);

    /** The entity of calls refused before their entity was known (multi-tenant mode). */
    public static final String UNKNOWN = "-";

    /** The counters, in record order. */
    public enum C {
        coreReq, coreResp, coreRespOk, coreRespErr,
        coreNotif, coreNotifResp, coreNotifOk, coreNotifErr, coreNotifNoResp,
        iopReq, iopResp, iopRespOk, iopRespErr,
        hopReq, hopResp, hopOk, hopErr, hopNoResp,
        targetReq, targetResp, targetOk, targetErr, targetNoResp, targetRetries,
        retries, nextRoute, allRoutesUnavailable,
        success, failure
    }

    /** The counts of one call, added to its entity's record once the entity is known (or at the end). */
    public static final class Counts {
        private final int[] n = new int[C.values().length];

        public void inc(C c) {
            n[c.ordinal()]++;
        }

        public void addAll(Counts other) {
            for (int i = 0; i < n.length; i++) {
                n[i] += other.n[i];
            }
        }
    }

    private final Map<String, LongAdder[]> counts = new ConcurrentHashMap<>();
    private final String mode;
    private final int intervalSeconds;
    /** The entities that get a record every interval: the loaded entities, plus {@code -} in multi-tenant mode. */
    private final Supplier<List<String>> recorded;
    private ScheduledExecutorService exec;
    private volatile Instant start = Instant.now();

    public Stats(String mode, int intervalSeconds, Supplier<List<String>> recorded) {
        this.mode = mode;
        this.intervalSeconds = intervalSeconds;
        this.recorded = recorded;
    }

    private LongAdder[] of(String entity) {
        return counts.computeIfAbsent(entity, e -> {
            LongAdder[] a = new LongAdder[C.values().length];
            for (int i = 0; i < a.length; i++) {
                a[i] = new LongAdder();
            }
            return a;
        });
    }

    public void add(String entity, Counts c) {
        LongAdder[] a = of(entity);
        for (int i = 0; i < c.n.length; i++) {
            if (c.n[i] != 0) {
                a[i].add(c.n[i]);
            }
        }
    }

    /** The count so far in this interval, over every entity. */
    public long get(C c) {
        long sum = 0;
        for (LongAdder[] a : counts.values()) {
            sum += a[c.ordinal()].sum();
        }
        return sum;
    }

    /** The count so far in this interval for one entity. */
    public long get(String entity, C c) {
        LongAdder[] a = counts.get(entity);
        return a == null ? 0 : a[c.ordinal()].sum();
    }

    public void start() {
        if (intervalSeconds <= 0) {
            return;
        }
        exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "iopgw-stats");
            t.setDaemon(true);
            return t;
        });
        exec.scheduleAtFixedRate(this::flush, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
    }

    /**
     * Writes the records for the interval so far and restarts the counts from 0: one per entity that
     * gets a record, and one for any other entity that counted calls in the interval (for example an
     * entity unloaded since).
     */
    public synchronized List<String> flush() {
        Instant end = Instant.now();
        List<String> wanted = recorded.get();
        Set<String> ids = new LinkedHashSet<>(wanted);
        ids.addAll(counts.keySet());
        List<String> lines = new ArrayList<>();
        for (String id : ids) {
            LongAdder[] a = of(id);
            StringBuilder sb = new StringBuilder("IOPGW_STATS|")
                    .append(TS.format(start.truncatedTo(ChronoUnit.MILLIS))).append('|')
                    .append(TS.format(end.truncatedTo(ChronoUnit.MILLIS))).append('|')
                    .append(id).append('|').append(mode).append('|')
                    .append(Math.max(0, end.getEpochSecond() - start.getEpochSecond()));
            for (C c : C.values()) {
                sb.append('|').append(c.name()).append('=').append(a[c.ordinal()].sumThenReset());
            }
            String line = sb.toString();
            LOG.atInfo().addKeyValue("tag", "IOPGW_STATS").addKeyValue("stats", line).log("stats");
            lines.add(line);
            if (!wanted.contains(id)) {
                counts.remove(id);
            }
        }
        start = end;
        return lines;
    }

    @Override
    public void close() {
        if (exec != null) {
            exec.shutdownNow();
        }
        if (intervalSeconds > 0) {
            flush();
        }
    }
}
