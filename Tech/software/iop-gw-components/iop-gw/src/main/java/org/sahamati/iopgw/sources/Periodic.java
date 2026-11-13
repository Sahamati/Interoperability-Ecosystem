package org.sahamati.iopgw.sources;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/**
 * Runs a load at start-up, then again after {@code refreshSeconds} when it succeeds or after
 * {@code retrySeconds} when it fails.
 */
public final class Periodic implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(Periodic.class);

    private final ScheduledExecutorService exec;
    private final String name;
    private final BooleanSupplier load;
    private final long refreshSeconds;
    private final LongSupplier retrySeconds;

    public Periodic(String name, BooleanSupplier load, long refreshSeconds, long retrySeconds) {
        this(name, load, refreshSeconds, () -> retrySeconds);
    }

    /** {@code retrySeconds} is asked after each failure (e.g. 30 s while nothing is loaded). */
    public Periodic(String name, BooleanSupplier load, long refreshSeconds, LongSupplier retrySeconds) {
        this.name = name;
        this.load = load;
        this.refreshSeconds = refreshSeconds;
        this.retrySeconds = retrySeconds;
        this.exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "iopgw-" + name);
            t.setDaemon(true);
            return t;
        });
    }

    /** Runs the first load synchronously, then schedules the next one. */
    public void start() {
        schedule(runOnce());
    }

    /** Schedules the first load after {@code delaySeconds} (used when a fresh copy is already held). */
    public void startAfter(long delaySeconds) {
        exec.schedule(() -> schedule(runOnce()), Math.max(0, delaySeconds), TimeUnit.SECONDS);
    }

    /**
     * Starts with a restored copy in mind: when one saved at {@code savedAt} is younger
     * than the refresh interval, the first load waits until it reaches that age; otherwise (none,
     * or stale) the load runs at once, and the restored copy keeps serving if it fails.
     */
    public void startRestored(java.time.Instant savedAt) {
        if (savedAt == null) {
            start();
            return;
        }
        long age = java.time.Duration.between(savedAt, java.time.Instant.now()).getSeconds();
        if (age >= 0 && age < refreshSeconds) {
            startAfter(refreshSeconds - age);
        } else {
            start();
        }
    }

    private boolean runOnce() {
        try {
            return load.getAsBoolean();
        } catch (RuntimeException e) {
            LOG.atWarn().addKeyValue("source", name).addKeyValue("error", e.getClass().getSimpleName()).log("load failed");
            return false;
        }
    }

    private void schedule(boolean ok) {
        long delay = ok ? refreshSeconds : retrySeconds.getAsLong();
        exec.schedule(() -> schedule(runOnce()), delay, TimeUnit.SECONDS);
    }

    @Override
    public void close() {
        exec.shutdownNow();
    }
}
