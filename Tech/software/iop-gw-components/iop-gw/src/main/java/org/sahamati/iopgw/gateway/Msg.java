package org.sahamati.iopgw.gateway;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/** Server-independent request and response types used by the handlers. */
public final class Msg {
    private Msg() {}

    /** Which listener a request arrived on. */
    public enum Listener { PUBLIC, GW_HTTPS, GW_HTTP }

    public static final class Req {
        public final String method;
        public final String path;
        /** Request headers, case-insensitive names, first value only. */
        public final Map<String, String> headers;
        public final byte[] body;
        /** True when the body exceeded the configured limit (body is then truncated). */
        public final boolean tooLarge;
        public final Listener listener;

        public Req(String method, String path, Map<String, String> headers, byte[] body, boolean tooLarge, Listener listener) {
            this.method = method;
            this.path = path;
            TreeMap<String, String> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            h.putAll(headers);
            this.headers = Collections.unmodifiableMap(h);
            this.body = body == null ? new byte[0] : body;
            this.tooLarge = tooLarge;
            this.listener = listener;
        }

        public String header(String name) {
            return headers.get(name);
        }
    }

    public static final class Resp {
        public final int status;
        /** Response headers in the exact spelling sent on the wire. */
        public final Map<String, String> headers = new LinkedHashMap<>();
        public final byte[] body;

        public Resp(int status, byte[] body) {
            this.status = status;
            this.body = body == null ? new byte[0] : body;
        }

        public Resp header(String name, String value) {
            if (value != null) {
                headers.put(name, value);
            }
            return this;
        }
    }
}
