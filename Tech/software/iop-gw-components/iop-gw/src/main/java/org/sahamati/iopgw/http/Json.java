package org.sahamati.iopgw.http;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.regex.Pattern;

/** JSON helpers and identifier formats. */
public final class Json {
    private Json() {}

    public static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Pattern UUID_RE =
            Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .withZone(ZoneOffset.UTC);

    public static ObjectNode object() {
        return MAPPER.createObjectNode();
    }

    /** Parses bytes as a JSON object, or returns null. */
    public static ObjectNode parseObject(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode n = MAPPER.readTree(body);
            return n instanceof ObjectNode o ? o : null;
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] bytes(JsonNode n) {
        try {
            return MAPPER.writeValueAsBytes(n);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String text(JsonNode n, String field) {
        if (n == null) {
            return null;
        }
        JsonNode v = n.get(field);
        return v != null && v.isTextual() ? v.asText() : null;
    }

    public static boolean isUuid(String s) {
        return s != null && UUID_RE.matcher(s).matches();
    }

    public static String newTxnId() {
        return UUID.randomUUID().toString();
    }

    public static String now() {
        return TS.format(Instant.now().truncatedTo(ChronoUnit.MILLIS));
    }
}
