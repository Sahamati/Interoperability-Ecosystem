package org.sahamati.iopgw.obs;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.LayoutBase;
import ch.qos.logback.core.encoder.LayoutWrappingEncoder;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.spi.FilterReply;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.sahamati.iopgw.http.Json;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.slf4j.event.KeyValuePair;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * JSON-lines logging on stdout: {@code time} (UTC, RFC 3339, ms), {@code level}, {@code msg}
 * plus attributes. Levels TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL; CRITICAL is ERROR with the
 * {@link #CRITICAL} marker. Audit and stats records (logger {@code iopgw.audit}) are always written.
 */
public final class Logs {
    private Logs() {}

    public static final Marker CRITICAL = MarkerFactory.getMarker("CRITICAL");
    public static final String AUDIT_LOGGER = "iopgw.audit";

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .withZone(ZoneOffset.UTC);

    /** Parses a level name case-insensitively (WARNING and FATAL are aliases), or returns null. */
    public static String normalise(String level) {
        if (level == null) {
            return null;
        }
        String l = level.trim().toUpperCase(Locale.ROOT);
        return switch (l) {
            case "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL" -> l;
            case "WARNING" -> "WARN";
            case "FATAL" -> "CRITICAL";
            default -> null;
        };
    }

    private static volatile boolean criticalOnly;

    /** Configures logging. {@code level} must be a normalised level name. */
    public static void configure(String level) {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        ctx.reset();
        criticalOnly = "CRITICAL".equals(level);

        LayoutBase<ILoggingEvent> layout = new LayoutBase<>() {
            @Override
            public String doLayout(ILoggingEvent e) {
                ObjectNode o = Json.object();
                o.put("time", TIME.format(Instant.ofEpochMilli(e.getTimeStamp())));
                o.put("level", levelName(e));
                o.put("msg", e.getFormattedMessage());
                if (e.getKeyValuePairs() != null) {
                    for (KeyValuePair kv : e.getKeyValuePairs()) {
                        o.set(kv.key, Json.MAPPER.valueToTree(kv.value));
                    }
                }
                return o.toString() + "\n";
            }
        };
        layout.setContext(ctx);
        layout.start();
        LayoutWrappingEncoder<ILoggingEvent> enc = new LayoutWrappingEncoder<>();
        enc.setContext(ctx);
        enc.setLayout(layout);
        enc.start();

        ConsoleAppender<ILoggingEvent> app = new ConsoleAppender<>();
        app.setContext(ctx);
        app.setName("stdout");
        app.setEncoder(enc);
        app.addFilter(new Filter<>() {
            @Override
            public FilterReply decide(ILoggingEvent e) {
                if (!criticalOnly || AUDIT_LOGGER.equals(e.getLoggerName())) {
                    return FilterReply.NEUTRAL;
                }
                return isCritical(e) ? FilterReply.NEUTRAL : FilterReply.DENY;
            }
        });
        app.start();

        ch.qos.logback.classic.Logger root = ctx.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        root.addAppender(app);
        root.setLevel(switch (level) {
            case "TRACE" -> Level.TRACE;
            case "DEBUG" -> Level.DEBUG;
            case "WARN" -> Level.WARN;
            case "ERROR", "CRITICAL" -> Level.ERROR;
            default -> Level.INFO;
        });
        ctx.getLogger(AUDIT_LOGGER).setLevel(Level.INFO);
        ctx.getLogger("org.apache").setLevel(Level.WARN);
        // Tomcat logs through java.util.logging: keep only its severe messages off stdout's JSON stream.
        TOMCAT_JUL.setLevel(java.util.logging.Level.SEVERE);
    }

    private static final java.util.logging.Logger TOMCAT_JUL = java.util.logging.Logger.getLogger("org.apache");

    private static boolean isCritical(ILoggingEvent e) {
        return e.getMarkerList() != null && e.getMarkerList().contains(CRITICAL);
    }

    private static String levelName(ILoggingEvent e) {
        if (isCritical(e)) {
            return "CRITICAL";
        }
        return e.getLevel().toString();
    }
}
