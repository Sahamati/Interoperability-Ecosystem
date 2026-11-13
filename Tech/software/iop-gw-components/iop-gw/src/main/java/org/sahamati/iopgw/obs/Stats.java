package org.sahamati.iopgw.obs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

/** Interval counters written as one {@code IOPGW_STATS} record per interval and at shutdown. */
public final class Stats implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(Logs.AUDIT_LOGGER);
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .withZone(ZoneOffset.UTC);

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

    private final Map<C, LongAdder> counts = new EnumMap<>(C.class);
    private final String self;
    private final String mode;
    private final int intervalSeconds;
    private ScheduledExecutorService exec;
    private volatile Instant start = Instant.now();

    public Stats(String self, String mode, int intervalSeconds) {
        this.self = self;
        this.mode = mode;
        this.intervalSeconds = intervalSeconds;
        for (C c : C.values()) {
            counts.put(c, new LongAdder());
        }
    }

    public void inc(C c) {
        counts.get(c).increment();
    }

    public long get(C c) {
        return counts.get(c).sum();
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

    /** Writes the record for the interval so far and restarts the counts from 0. */
    public synchronized String flush() {
        Instant end = Instant.now();
        StringBuilder sb = new StringBuilder("IOPGW_STATS|")
                .append(TS.format(start.truncatedTo(ChronoUnit.MILLIS))).append('|')
                .append(TS.format(end.truncatedTo(ChronoUnit.MILLIS))).append('|')
                .append(self).append('|').append(mode).append('|')
                .append(Math.max(0, end.getEpochSecond() - start.getEpochSecond()));
        for (C c : C.values()) {
            sb.append('|').append(c.name()).append('=').append(counts.get(c).sumThenReset());
        }
        start = end;
        String line = sb.toString();
        LOG.atInfo().addKeyValue("tag", "IOPGW_STATS").addKeyValue("stats", line).log("stats");
        return line;
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
