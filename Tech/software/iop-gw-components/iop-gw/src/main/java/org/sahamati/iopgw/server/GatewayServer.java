package org.sahamati.iopgw.server;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.gateway.GwApiHandler;
import org.sahamati.iopgw.gateway.IopHandler;
import org.sahamati.iopgw.gateway.Msg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Embedded Tomcat with up to three listeners: the public /iop listener, the internal HTTPS listener
 * and the optional internal plain-HTTP listener. Requests are dispatched by the listener they
 * arrived on, so the internal APIs are never served on the public listener.
 */
public final class GatewayServer implements AutoCloseable {

    private final Tomcat tomcat = new Tomcat();
    private final Map<Integer, Msg.Listener> byPort = new ConcurrentHashMap<>();
    private final Map<Msg.Listener, Connector> connectors = new LinkedHashMap<>();
    private final IopHandler iop;
    private final GwApiHandler gwApi;
    private final long maxBody;
    private final Path baseDir;

    public GatewayServer(Config c, IopHandler iop, GwApiHandler gwApi) throws IOException {
        this.iop = iop;
        this.gwApi = gwApi;
        this.maxBody = c.limits.maxBodyBytes;
        this.baseDir = Files.createTempDirectory("iopgw-tomcat");
        tomcat.setBaseDir(baseDir.toString());
        tomcat.getHost().setAutoDeploy(false);

        connectors.put(Msg.Listener.PUBLIC, connector(c.listenAddr, c.tls));
        if (c.gwApi != null) {
            connectors.put(Msg.Listener.GW_HTTPS, connector(c.gwApi.listenAddr, c.gwApi.tls));
            if (c.gwApi.httpListenAddr != null) {
                connectors.put(Msg.Listener.GW_HTTP, connector(c.gwApi.httpListenAddr, null));
            }
        }
        boolean first = true;
        for (Connector conn : connectors.values()) {
            if (first) {
                tomcat.setConnector(conn);
                first = false;
            } else {
                tomcat.getService().addConnector(conn);
            }
        }

        Context ctx = tomcat.addContext("", baseDir.toString());
        if (ctx instanceof org.apache.catalina.core.StandardContext sc) {
            sc.setClearReferencesRmiTargets(false);
            sc.setClearReferencesThreadLocals(false);
        }
        Tomcat.addServlet(ctx, "gateway", new Dispatch());
        ctx.addServletMappingDecoded("/*", "gateway");
    }

    private static Connector connector(String addr, Config.Tls tls) {
        Connector conn = new Connector(Http11NioProtocol.class.getName());
        HostPort hp = HostPort.parse(addr);
        conn.setPort(hp.port());
        if (hp.host() != null) {
            conn.setProperty("address", hp.host());
        }
        conn.setXpoweredBy(false);
        conn.setProperty("server", "");
        conn.setAllowTrace(false);
        conn.setProperty("relaxedQueryChars", "");
        if (tls != null) {
            conn.setSecure(true);
            conn.setScheme("https");
            conn.setProperty("SSLEnabled", "true");
            SSLHostConfig ssl = new SSLHostConfig();
            ssl.setProtocols("TLSv1.2+TLSv1.3");
            SSLHostConfigCertificate cert = new SSLHostConfigCertificate(ssl, SSLHostConfigCertificate.Type.RSA);
            cert.setCertificateFile(tls.certFile);
            cert.setCertificateKeyFile(tls.keyFile);
            ssl.addCertificate(cert);
            conn.addSslHostConfig(ssl);
        }
        return conn;
    }

    /** Starts every listener; fails (and stops) if any listener could not be bound (fail closed, G4). */
    public void start() throws LifecycleException {
        tomcat.start();
        for (Map.Entry<Msg.Listener, Connector> e : connectors.entrySet()) {
            Connector conn = e.getValue();
            if (conn.getState() != org.apache.catalina.LifecycleState.STARTED || conn.getLocalPort() <= 0) {
                close();
                throw new LifecycleException("listener " + e.getKey() + " could not be started on port " + conn.getPort());
            }
            byPort.put(conn.getLocalPort(), e.getKey());
        }
    }

    /** The bound port of a listener (useful when configured with port 0). */
    public int port(Msg.Listener l) {
        Connector c = connectors.get(l);
        return c == null ? -1 : c.getLocalPort();
    }

    @Override
    public void close() {
        try {
            tomcat.stop();
            tomcat.destroy();
        } catch (LifecycleException ignored) {
            // shutting down
        }
    }

    private final class Dispatch extends HttpServlet {
        @Override
        protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            Msg.Listener listener = byPort.getOrDefault(req.getLocalPort(), Msg.Listener.PUBLIC);
            byte[] body;
            boolean tooLarge;
            try (InputStream in = req.getInputStream()) {
                body = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, maxBody + 1));
                tooLarge = body.length > maxBody;
            }
            Map<String, String> headers = new LinkedHashMap<>();
            Enumeration<String> names = req.getHeaderNames();
            while (names.hasMoreElements()) {
                String n = names.nextElement();
                headers.put(n, req.getHeader(n));
            }
            String path = req.getRequestURI();
            Msg.Req r = new Msg.Req(req.getMethod(), path, headers, body, tooLarge, listener);
            Msg.Resp out = listener == Msg.Listener.PUBLIC ? publicListener(r) : gwApi.handle(r);
            resp.setStatus(out.status);
            out.headers.forEach(resp::setHeader);
            resp.setContentLength(out.body.length);
            if (out.body.length > 0) {
                try (OutputStream os = resp.getOutputStream()) {
                    os.write(out.body);
                }
            }
        }

        private Msg.Resp publicListener(Msg.Req r) {
            if ("/healthz".equals(r.path) && "GET".equals(r.method)) {
                return new Msg.Resp(200, "ok".getBytes());
            }
            return iop.handle(r);
        }
    }

    /** host:port, where host may be empty (all interfaces). */
    public record HostPort(String host, int port) {
        public static HostPort parse(String addr) {
            int i = addr.lastIndexOf(':');
            if (i < 0) {
                throw new IllegalArgumentException("address must be host:port");
            }
            String host = addr.substring(0, i);
            int port = Integer.parseInt(addr.substring(i + 1));
            return new HostPort(host.isEmpty() ? null : host, port);
        }
    }
}
