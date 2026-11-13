package org.sahamati.iopgw.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;

/** Outbound HTTP: HTTP/1.1, redirects never followed, response bodies size-limited. */
public final class Http {

    public record Response(int status, Map<String, List<String>> headers, byte[] body) {
        public Optional<String> header(String name) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() != null && e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
                    return Optional.of(e.getValue().get(0));
                }
            }
            return Optional.empty();
        }
    }

    /** No usable answer. {@code kind} is one of timeout, unreachable, cancelled, unreadable. */
    public static final class NoResponse extends Exception {
        public final String kind;

        public NoResponse(String kind) {
            super(kind);
            this.kind = kind;
        }

        public boolean timeout() {
            return "timeout".equals(kind);
        }
    }

    private final HttpClient client;

    public Http() {
        this.client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .executor(Executors.newVirtualThreadPerTaskExecutor())
                .build();
    }

    public Http(HttpClient client) {
        this.client = client;
    }

    public Response send(String method, String url, Map<String, String> headers, byte[] body,
                         Duration timeout, long maxBytes) throws NoResponse {
        HttpRequest.Builder b;
        try {
            b = HttpRequest.newBuilder(URI.create(url)).timeout(timeout);
        } catch (IllegalArgumentException e) {
            throw new NoResponse("unreachable");
        }
        headers.forEach((k, v) -> {
            if (v != null) {
                b.header(k, v);
            }
        });
        if (body == null) {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            b.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
        }
        try {
            HttpResponse<InputStream> r = client.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
            byte[] data;
            try (InputStream in = r.body()) {
                data = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, maxBytes + 1));
            }
            if (data.length > maxBytes) {
                throw new NoResponse("response unreadable or too large");
            }
            return new Response(r.statusCode(), r.headers().map(), data);
        } catch (HttpConnectTimeoutException e) {
            throw new NoResponse("unreachable");
        } catch (HttpTimeoutException e) {
            throw new NoResponse("timeout");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NoResponse("cancelled");
        } catch (IOException e) {
            throw new NoResponse("unreachable");
        }
    }
}
