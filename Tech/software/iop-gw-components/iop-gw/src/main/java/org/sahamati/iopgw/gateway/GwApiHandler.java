package org.sahamati.iopgw.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.model.Roles;
import org.sahamati.iopgw.model.Roles.EntityType;
import org.sahamati.iopgw.model.Roles.Family;
import org.sahamati.iopgw.obs.Audit;
import org.sahamati.iopgw.obs.Stats.C;
import org.sahamati.iopgw.sources.LinkedAAs;
import org.sahamati.iopgw.sources.Registry.Entity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The internal APIs the core calls. Every error this class generates is in the
 * complete list of "Errors returned to the core", checked in that order.
 */
public final class GwApiHandler {
    private static final Logger LOG = LoggerFactory.getLogger(GwApiHandler.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Gateway gw;
    private final List<Family> families;

    public GwApiHandler(Gateway gw) {
        this.gw = gw;
        this.families = Roles.families(gw.mode);
    }

    private enum Kind { MESSAGE, HEARTBEAT, BROADCAST, LINKED_AAS, KEYS_SIGNING, KEYS_DECRYPTION }

    private record Route(Family family, String api, Kind kind) {}

    /** Per-request context for error bodies and audit records. */
    private static final class Ctx {
        String ver;
        String txnid;
        String correlationId;
        String target;
        long started = System.nanoTime();
    }

    public Msg.Resp handle(Msg.Req req) {
        Ctx ctx = new Ctx();
        Route route = resolve(req.path);
        if (route != null && route.kind == Kind.LINKED_AAS) {
            return linkedAAsPush(req);
        }
        if (route != null && (route.kind == Kind.KEYS_SIGNING || route.kind == Kind.KEYS_DECRYPTION)) {
            return keyPush(req, route.kind == Kind.KEYS_SIGNING ? gw.coreSigning : gw.coreDecryption);
        }
        gw.stats.inc(C.coreReq);
        Map<String, Object> rf = new LinkedHashMap<>();
        rf.put("method", req.method);
        rf.put("path", req.path);
        rf.put("peer", "core");
        ObjectNode early = Json.parseObject(req.body);
        rf.put("ver", Json.text(early, "ver"));
        rf.put("txnid", Json.text(early, "txnid"));
        rf.put("correlationId", req.header("Correlation-Id"));
        rf.put("target", targetOf(req.header("Target-Entity")));
        rf.put("bodyBytes", req.body.length);
        rf.put("headers", Audit.headers(req.headers));
        gw.audit.record("request", "core-in", "initiator", rf);
        Msg.Resp resp;
        boolean own = false;
        String ownMsg = null;
        try {
            resp = process(req, route, ctx);
        } catch (GwError e) {
            resp = error(e, ctx, req);
            own = true;
            ownMsg = e.getMessage();
        }
        if (req.header("Correlation-Id") != null) {
            resp.header("Correlation-Id", req.header("Correlation-Id"));
        }
        gw.stats.inc(C.coreResp);
        gw.stats.inc(resp.status < 400 ? C.coreRespOk : C.coreRespErr);
        gw.stats.inc(resp.status < 400 ? C.success : C.failure);
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("method", req.method);
        f.put("path", req.path);
        f.put("peer", "core");
        f.put("ver", ctx.ver);
        f.put("txnid", ctx.txnid);
        f.put("correlationId", ctx.correlationId);
        f.put("initiator", gw.mode.name() + "/" + gw.selfId);
        f.put("target", ctx.target);
        f.put("status", resp.status);
        f.put("bodyBytes", resp.body.length);
        if (own) {
            f.put("errorCode", Json.text(Json.parseObject(resp.body), "errorCode"));
            f.put("errorMsg", ownMsg);
        }
        f.put("ms", (System.nanoTime() - ctx.started) / 1_000_000);
        f.put("headers", Audit.headers(resp.headers));
        gw.audit.record("response", "core-in", "initiator", f);
        return resp;
    }

    private Route resolve(String path) {
        for (Family fam : families) {
            String p = fam.prefix() + "/";
            if (!path.startsWith(p)) {
                continue;
            }
            String api = path.substring(p.length());
            if (fam.postApis().contains(api)) {
                return new Route(fam, api, Kind.MESSAGE);
            }
            if (fam.heartbeat() && "Heartbeat".equals(api)) {
                return new Route(fam, api, Kind.HEARTBEAT);
            }
            // the user discovery broadcast, FIU mode only (other modes: 404).
            if ("broadcast/User/discover".equals(api) && gw.mode == Roles.Mode.FIU) {
                return new Route(fam, api, Kind.BROADCAST);
            }
            if ("linkedAAs".equals(api) && "api".equals(gw.config.linkedAAs.source)) {
                return new Route(fam, api, Kind.LINKED_AAS);
            }
            // Key push; a key type not taken from the core gets a header-less 404 InvalidURI.
            if ("keys/signing".equals(api)) {
                return new Route(fam, api, Kind.KEYS_SIGNING);
            }
            if ("keys/decryption".equals(api)) {
                return new Route(fam, api, Kind.KEYS_DECRYPTION);
            }
        }
        return null;
    }

    private Msg.Resp process(Msg.Req req, Route route, Ctx ctx) throws GwError {
        // Lenient early parse, so that error bodies carry the payload's ver and txnid.
        ObjectNode payload = Json.parseObject(req.body);
        ctx.ver = payload != null && Json.text(payload, "ver") != null ? Json.text(payload, "ver") : gw.gwVer();
        ctx.txnid = Json.text(payload, "txnid");

        // ---- 1. The core's request ----
        if (route == null) {
            throw new GwError(404, GwError.INVALID_URI, "unknown internal API path in " + gw.mode + " mode");
        }
        boolean heartbeat = route.kind == Kind.HEARTBEAT;
        if (heartbeat) {
            ctx.txnid = Json.newTxnId();
            ctx.ver = gw.gwVer();
        }
        String expectMethod = heartbeat ? "GET" : "POST";
        if (!expectMethod.equals(req.method)) {
            throw new GwError(405, GwError.INVALID_REQUEST, "method not allowed");
        }
        if (req.tooLarge) {
            throw new GwError(413, GwError.INVALID_REQUEST, "body too large or unreadable");
        }
        checkToken(req);
        if (route.kind == Kind.BROADCAST) {
            return broadcast(req, route, ctx, payload);
        }
        String corr = req.header("Correlation-Id");
        if (corr == null || !Json.isUuid(corr)) {
            throw new GwError(400, GwError.INVALID_REQUEST, "Correlation-Id header is required, in standard UUID format");
        }
        ctx.correlationId = corr;
        ObjectNode te = Json.parseObject(req.header("Target-Entity") == null ? null
                : req.header("Target-Entity").getBytes(StandardCharsets.UTF_8));
        String tType = Json.text(te, "type");
        String tId = Json.text(te, "id");
        if (tType == null || tId == null || tType.isEmpty() || tId.isEmpty()) {
            throw new GwError(400, GwError.INVALID_REQUEST, "Target-Entity header must be {\"type\":...,\"id\":...}");
        }
        ctx.target = tType + "/" + tId;
        EntityType want = route.family.targetType();
        if (!want.name().equals(tType)) {
            throw new GwError(400, GwError.INVALID_REQUEST, "Target.type must be " + want + " on " + req.path);
        }
        if (!gw.registry.loaded()) {
            throw new GwError(503, GwError.INTERNAL, "entity registry not loaded");
        }
        Entity target = gw.registry.get(tId).filter(e -> e.type() == want && !e.id().equals(gw.selfId))
                .orElseThrow(() -> new GwError(400, GwError.INVALID_REQUEST, "Target is not registered"));
        if (!target.interop()) {
            throw new GwError(400, GwError.INVALID_REQUEST, "Target is not interop ready");
        }
        int maxRetries = gw.config.gwApi.maxRetries;
        int maxRouteRetries = gw.config.gwApi.maxRouteRetries;
        int httpRetries = retriesHeader(req.header("Http-Retries"), "Http-Retries", Math.min(2, maxRetries), maxRetries);
        int routeRetries = retriesHeader(req.header("Route-Retries"), "Route-Retries", Math.min(2, maxRouteRetries), maxRouteRetries);

        // ---- 2. Route selection ----
        List<Entity> routes = selectRoutes(route.family, target, req.header("Preferred-Hop"));

        // ---- 3. Building the IOP request ----
        PubKey encKey = target.encryptionKey()
                .orElseThrow(() -> new GwError(500, GwError.INTERNAL, "no encryption key configured for Target"));
        String encryptedPayload = null;
        String envVer = gw.gwVer();
        if (!heartbeat) {
            if (payload == null || Json.text(payload, "txnid") == null) {
                throw new GwError(400, GwError.INVALID_REQUEST, "body must be a JSON object with txnid");
            }
            if (Json.text(payload, "ver") != null) {
                envVer = Json.text(payload, "ver");
            }
            String inner = innerJws(req);
            try {
                encryptedPayload = Jose.encrypt(inner, encKey);
            } catch (Jose.JoseException e) {
                throw new GwError(500, GwError.INTERNAL, "unable to encrypt for Target");
            }
        }

        // ---- 4. Sending to the routes ----
        return send(req, route, ctx, target, routes, encryptedPayload, envVer, httpRetries, routeRetries);
    }

    // =====================================================================================
    // User discovery broadcast
    // =====================================================================================

    /**
     * Asks every AA in the entity registry, in parallel, whether it knows the customer: a linked AA
     * on the Direct API {@code POST <baseUrl>/User/discover}; an AA that is not linked but interop
     * ready through {@code /iop/User/discover} via a linked AA; any other AA not at all. Answers
     * arriving after {@code gwApi.broadcastTimeoutSeconds} are ignored. The reply merges the
     * {@code User Found} entries and carries no {@code x-jws-signature} (several AAs answered).
     */
    private Msg.Resp broadcast(Msg.Req req, Route route, Ctx ctx, ObjectNode payload) throws GwError {
        String corr = req.header("Correlation-Id");
        if (corr == null || !Json.isUuid(corr)) {
            throw new GwError(400, GwError.INVALID_REQUEST, "Correlation-Id header is required, in standard UUID format");
        }
        ctx.correlationId = corr;
        ctx.target = "broadcast";
        if (payload == null || Json.text(payload, "txnid") == null) {
            throw new GwError(400, GwError.INVALID_REQUEST, "body must be a JSON object with txnid");
        }
        int maxRetries = gw.config.gwApi.maxRetries;
        int maxRouteRetries = gw.config.gwApi.maxRouteRetries;
        int httpRetries = retriesHeader(req.header("Http-Retries"), "Http-Retries", Math.min(2, maxRetries), maxRetries);
        int routeRetries = retriesHeader(req.header("Route-Retries"), "Route-Retries", Math.min(2, maxRouteRetries), maxRouteRetries);
        if (!gw.registry.loaded()) {
            throw new GwError(503, GwError.INTERNAL, "entity registry not loaded");
        }
        if (!gw.linkedAAs.loaded()) {
            throw new GwError(503, GwError.INTERNAL, "linkedAAs not loaded");
        }
        Set<String> linked = new LinkedHashSet<>(gw.linkedAAs.get());

        List<java.util.concurrent.Callable<JsonNode>> asks = new ArrayList<>();
        for (Entity aa : gw.registry.all()) {
            if (aa.type() != EntityType.AA || aa.id().equals(gw.selfId)) {
                continue;
            }
            if (linked.contains(aa.id())) {
                asks.add(() -> askDirect(aa, payload, corr));
            } else if (aa.interop()) {
                asks.add(() -> askViaIop(aa, route, payload, corr, httpRetries, routeRetries));
            }
            // neither linked nor interop ready: not asked
        }

        long timeoutMs = 1000L * gw.config.gwApi.broadcastTimeoutSeconds;
        long deadline = System.nanoTime() + timeoutMs * 1_000_000;
        List<JsonNode> answers = new ArrayList<>();
        try (var exec = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            List<java.util.concurrent.Future<JsonNode>> futures = new ArrayList<>();
            for (var a : asks) {
                futures.add(exec.submit(a));
            }
            for (var f : futures) {
                long left = Math.max(0, deadline - System.nanoTime());
                try {
                    JsonNode n = f.get(left, java.util.concurrent.TimeUnit.NANOSECONDS);
                    if (n != null) {
                        answers.add(n);
                    }
                } catch (java.util.concurrent.TimeoutException e) {
                    f.cancel(true); // later answers are ignored
                } catch (java.util.concurrent.ExecutionException e) {
                    LOG.atDebug().addKeyValue("error", String.valueOf(e.getCause())).log("broadcast: an AA did not answer successfully");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            exec.shutdownNow(); // do not wait for the slow ones
        }
        if (answers.isEmpty()) {
            gw.stats.inc(C.allRoutesUnavailable);
            throw new GwError(503, GwError.ALL_ROUTES, "no AA answered the user discovery (" + asks.size() + " asked)");
        }
        com.fasterxml.jackson.databind.node.ArrayNode found = Json.MAPPER.createArrayNode();
        for (JsonNode a : answers) {
            JsonNode entries = a.get("customerDiscoveryResponse");
            if ("User Found".equals(Json.text(a, "status")) && entries != null && entries.isArray()) {
                entries.forEach(found::add);
            }
        }
        ObjectNode out = Json.object();
        out.put("ver", ctx.ver);
        out.put("timestamp", Json.now());
        out.put("txnid", Json.text(payload, "txnid"));
        out.put("correlationId", corr);
        out.put("status", found.isEmpty() ? "User Not Found" : "User Found");
        out.set("customerDiscoveryResponse", found);
        return new Msg.Resp(200, Json.bytes(out));
    }

    /** The core's request for one AA: its own new txnid, the Correlation-Id as correlationId. */
    private static byte[] discoveryBody(ObjectNode payload, String corr) {
        ObjectNode b = payload.deepCopy();
        b.put("txnid", Json.newTxnId());
        b.put("correlationId", corr);
        return Json.bytes(b);
    }

    /** A linked AA: the Direct API, plaintext, signed by this gateway, answered 200 with a valid signature. */
    private JsonNode askDirect(Entity aa, ObjectNode payload, String corr) throws Exception {
        if (aa.baseUrl() == null) {
            throw new IllegalStateException("no baseUrl");
        }
        byte[] body = discoveryBody(payload, corr);
        String key = gw.directKey(aa).orElseThrow(() -> new IllegalStateException("no access token")); // the Direct API takes the access token, not the IopToken
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", "application/json");
        h.put(Roles.CLIENT, key);
        h.put("x-jws-signature", gw.signDetached(body));
        Http.Response r = gw.http.send("POST", aa.baseUrl() + "/User/discover", h, body, gw.forwardingTimeout(), gw.maxUpstream());
        if (r.status() != 200) {
            throw new IllegalStateException("HTTP " + r.status());
        }
        if (!Boolean.TRUE.equals(gw.config.forwarding.skipUpstreamResponseSignature)
                && !Jose.verifyDetached(r.header("x-jws-signature").orElse(null), r.body(), aa.signingKeys())) {
            throw new IllegalStateException("signature invalid");
        }
        ObjectNode n = Json.parseObject(r.body());
        if (n == null) {
            throw new IllegalStateException("not JSON");
        }
        return n;
    }

    /** An AA that is not linked but interop ready: /iop/User/discover via a linked AA, as for /fiu-dgw/User/discover. */
    private JsonNode askViaIop(Entity aa, Route route, ObjectNode payload, String corr, int httpRetries, int routeRetries)
            throws Exception {
        byte[] body = discoveryBody(payload, corr);
        Route r = new Route(route.family, "User/discover", Kind.MESSAGE);
        Ctx c = new Ctx();
        c.correlationId = corr;
        c.target = "AA/" + aa.id();
        List<Entity> routes = selectRoutes(route.family, aa, null);
        PubKey encKey = aa.encryptionKey().orElseThrow(() -> new IllegalStateException("no encryption key"));
        String enc = Jose.encrypt(gw.signCompact(body), encKey);
        String ver = Json.text(payload, "ver") != null ? Json.text(payload, "ver") : gw.gwVer();
        Msg.Resp resp = send(null, r, c, aa, routes, enc, ver, httpRetries, routeRetries);
        if (resp.status != 200) {
            throw new IllegalStateException("HTTP " + resp.status);
        }
        ObjectNode n = Json.parseObject(resp.body);
        if (n == null) {
            throw new IllegalStateException("not JSON");
        }
        return n;
    }

    private void checkToken(Msg.Req req) throws GwError {
        String token = gw.config.secret("gwApi.token");
        if (token == null) {
            return;
        }
        String auth = req.header("Authorization");
        String given = auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : "";
        if (!MessageDigest.isEqual(given.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8))) {
            throw new GwError(401, GwError.INVALID_SECURITY, "invalid or missing internal API token");
        }
    }

    private static int retriesHeader(String value, String name, int dflt, int cap) throws GwError {
        if (value == null) {
            return dflt;
        }
        int n;
        try {
            n = Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new GwError(400, GwError.INVALID_REQUEST, name + ": not a non-negative integer");
        }
        if (n < 0) {
            throw new GwError(400, GwError.INVALID_REQUEST, name + ": not a non-negative integer");
        }
        return Math.min(n, cap);
    }

    /** Eligible hops in order. */
    private List<Entity> selectRoutes(Family family, Entity target, String preferred) throws GwError {
        if (!gw.linkedAAs.loaded()) {
            throw new GwError(503, GwError.INTERNAL, "linkedAAs not loaded");
        }
        if (!gw.aig.loaded()) {
            throw new GwError(502, GwError.BAD_GATEWAY, "hop directory unavailable");
        }
        Set<String> linked = new LinkedHashSet<>(gw.linkedAAs.get());
        Map<String, Entity> eligible = new LinkedHashMap<>();
        for (String id : gw.aig.candidates(target.type(), target.id())) {
            if (!linked.contains(id) || id.equals(target.id()) || id.equals(gw.selfId)) {
                continue;
            }
            Entity hop = gw.registry.get(id).orElse(null);
            if (hop == null || hop.type() != EntityType.AA || hop.baseUrl() == null) {
                continue;
            }
            if (!hop.interop()) {
                LOG.atDebug().addKeyValue("hop", id).log("hop skipped: not interop ready");
                continue;
            }
            eligible.put(id, hop);
        }
        if (eligible.isEmpty()) {
            throw new GwError(400, GwError.INVALID_REQUEST, "no interop-ready linked AA can reach this Target");
        }
        List<Entity> ordered = new ArrayList<>();
        if (preferred != null) {
            Entity p = eligible.remove(preferred);
            if (p != null) {
                ordered.add(p);
            } else {
                LOG.atInfo().addKeyValue("preferredHop", preferred).log("Preferred-Hop ignored: not an eligible hop");
            }
        }
        List<String> policy = family.viaConnectedAA() ? gw.config.hopPreference.connectedAAs : gw.config.hopPreference.interAAs;
        for (String id : policy) {
            Entity p = eligible.remove(id);
            if (p != null) {
                ordered.add(p);
            }
        }
        List<Entity> rest = new ArrayList<>(eligible.values());
        Collections.shuffle(rest, RANDOM);
        ordered.addAll(rest);
        return ordered;
    }

    /**
     * The inner JWS, always signed here. A signature the core sends of its own is checked against
     * this participant's signing keys (400 when it does not verify), but not carried.
     */
    private String innerJws(Msg.Req req) throws GwError {
        String coreSig = req.header("x-jws-signature");
        if (coreSig != null && !coreSig.isEmpty() && !Jose.verifyDetached(coreSig, req.body, gw.signing.publicKeys())) {
            throw new GwError(400, GwError.INVALID_REQUEST,
                    "core x-jws-signature does not verify with any of this participant's signing keys");
        }
        return gw.signCompact(req.body);
    }

    private Msg.Resp send(Msg.Req req, Route route, Ctx ctx, Entity target, List<Entity> routes, String encryptedPayload,
                          String envVer, int httpRetries, int routeRetries) throws GwError {
        String iopPath = "/iop/" + route.api;
        int allowed = 1 + routeRetries;
        int tried = 0;
        for (Entity hop : routes) {
            if (tried >= allowed) {
                break;
            }
            String key = gw.outboundKey(hop).orElse(null);
            if (key == null) {
                LOG.atWarn().addKeyValue("hop", hop.id()).log("hop skipped: no api-key (IopToken unavailable)");
                continue;
            }
            tried++;
            if (tried > 1) {
                gw.stats.inc(C.nextRoute);
            }
            // One envelope per route: new txnid, the same on retries of that route.
            ObjectNode env = Json.object();
            env.put("ver", envVer);
            env.put("timestamp", Json.now());
            String legTxn = Json.newTxnId();
            env.put("txnid", legTxn);
            env.put("correlationId", ctx.correlationId);
            ObjectNode t = env.putObject("Target");
            t.put("type", target.type().name());
            t.put("id", target.id());
            if (encryptedPayload != null) {
                env.put("encryptedPayload", encryptedPayload);
            }
            byte[] body;
            String sig;
            try {
                body = Json.bytes(env);
            } catch (RuntimeException e) {
                throw new GwError(500, GwError.INTERNAL, "unable to build envelope");
            }
            sig = gw.signDetached(body);
            Map<String, String> h = new LinkedHashMap<>();
            h.put("Content-Type", "application/json");
            h.put(route.family.roleKey(), key);
            h.put("x-jws-signature", sig);

            long backoff = 200;
            Http.Response resp = null;
            for (int attempt = 1; attempt <= 1 + httpRetries; attempt++) {
                if (attempt > 1) {
                    gw.stats.inc(C.retries);
                    sleep(backoff);
                    backoff = Math.min(backoff * 2, 2000);
                }
                Map<String, Object> rf = new LinkedHashMap<>();
                rf.put("method", "POST");
                rf.put("path", iopPath);
                rf.put("peer", hop.id());
                rf.put("route", tried);
                rf.put("attempt", attempt);
                rf.put("ver", envVer);
                rf.put("txnid", legTxn);
                rf.put("correlationId", ctx.correlationId);
                rf.put("target", ctx.target);
                rf.put("bodyBytes", body.length);
                rf.put("encryptedPayloadBytes", encryptedPayload == null ? null : encryptedPayload.length());
                rf.put("headers", Audit.headers(h));
                gw.audit.record("request", "hop-out", "initiator", rf);
                gw.stats.inc(C.hopReq);
                long t0 = System.nanoTime();
                try {
                    resp = gw.http.send("POST", hop.baseUrl() + iopPath, h, body, gw.forwardingTimeout(), gw.maxUpstream());
                } catch (Http.NoResponse e) {
                    gw.stats.inc(C.hopNoResp);
                    Map<String, Object> f = new LinkedHashMap<>(rf);
                    f.remove("headers");
                    f.remove("bodyBytes");
                    f.remove("encryptedPayloadBytes");
                    f.put("noResponse", e.kind);
                    f.put("ms", (System.nanoTime() - t0) / 1_000_000);
                    gw.audit.record("response", "hop-out", "initiator", f);
                    if (Thread.currentThread().isInterrupted()) {
                        throw new GwError(504, GwError.GATEWAY_TIMEOUT, "request cancelled while retrying");
                    }
                    continue;
                }
                gw.stats.inc(C.hopResp);
                gw.stats.inc(resp.status() < 400 ? C.hopOk : C.hopErr);
                ObjectNode rb = Json.parseObject(resp.body());
                Map<String, Object> f = new LinkedHashMap<>(rf);
                f.remove("encryptedPayloadBytes");
                f.put("status", resp.status());
                f.put("bodyBytes", resp.body().length);
                f.put("errorCode", Json.text(rb, "errorCode"));
                f.put("encryptedPayloadBytes", rb != null && rb.hasNonNull("encryptedPayload") ? rb.get("encryptedPayload").asText().length() : null);
                f.put("ms", (System.nanoTime() - t0) / 1_000_000);
                f.put("headers", Audit.headers(IopHandler.flatten(resp.headers())));
                gw.audit.record("response", "hop-out", "initiator", f);
                break; // a hop answer is never retried on the same route
            }
            if (resp == null) {
                continue; // no answer after the retries: next route
            }
            ObjectNode rb = Json.parseObject(resp.body());
            boolean hasCipher = rb != null && rb.hasNonNull("encryptedPayload");
            if (resp.status() < 400 || hasCipher) {
                return openReply(resp, rb, hop, target);
            }
            if (rb != null && GwError.DOWNSTREAM.equals(Json.text(rb, "errorCode"))) {
                // The Target answered without a payload: its status, empty body; no retry, no other route.
                verifyHop(resp, hop, false);
                return new Msg.Resp(resp.status(), null).header("Forwarding-Hop", hop.id());
            }
            // Any other hop error: the route failed; try the next one at once.
        }
        if (tried == 0) {
            throw new GwError(503, GwError.INTERNAL, "IopToken unavailable");
        }
        gw.stats.inc(C.allRoutesUnavailable);
        throw new GwError(503, GwError.ALL_ROUTES, "no route could deliver the call (" + tried + " tried)");
    }

    private void verifyHop(Http.Response resp, Entity hop, boolean withHopHeader) throws GwError {
        if (Boolean.TRUE.equals(gw.config.forwarding.skipUpstreamResponseSignature)) {
            return;
        }
        String sig = resp.header("x-jws-signature").orElse(null);
        if (!Jose.verifyDetached(sig, resp.body(), hop.signingKeys())) {
            throw new GwError(502, GwError.BAD_GATEWAY, "hop response signature invalid", withHopHeader ? hop.id() : null);
        }
    }

    /** ---- 5. Checking the hop's final answer ---- */
    private Msg.Resp openReply(Http.Response resp, ObjectNode rb, Entity hop, Entity target) throws GwError {
        verifyHop(resp, hop, true);
        if (!gw.decryption.loaded()) {
            throw new GwError(503, GwError.INTERNAL, "decryption keys not loaded", hop.id());
        }
        JsonNode c = rb == null ? null : rb.get("encryptedPayload");
        String jws;
        try {
            if (c == null || !c.isTextual()) {
                throw new Jose.JoseException("no ciphertext");
            }
            jws = Jose.decrypt(c.asText(), gw.decryption);
        } catch (Jose.JoseException e) {
            throw new GwError(502, GwError.BAD_GATEWAY, "unable to decrypt reply", hop.id());
        }
        if (!Jose.isCompactJws(jws)) {
            throw new GwError(502, GwError.BAD_GATEWAY, "reply does not contain a compact JWS", hop.id());
        }
        byte[] payload = Jose.verifyCompact(jws, target.signingKeys());
        if (payload == null) {
            throw new GwError(502, GwError.SIG_MISMATCH, "Target signature on reply invalid", hop.id());
        }
        return new Msg.Resp(resp.status(), payload)
                .header("x-jws-signature", Jose.detach(jws))
                .header("Forwarding-Hop", hop.id());
    }

    /** Error to the core: unsigned body, IOP-Gw-Error, no Content-Type. */
    private Msg.Resp error(GwError e, Ctx ctx, Msg.Req req) {
        ObjectNode err = Json.object();
        err.put("ver", ctx.ver != null ? ctx.ver : gw.gwVer());
        if (ctx.txnid != null) {
            err.put("txnid", ctx.txnid);
        } else {
            err.putNull("txnid");
        }
        err.put("timestamp", Json.now());
        err.put("errorCode", e.code);
        err.put("errorMsg", e.getMessage());
        Msg.Resp r = new Msg.Resp(e.status, Json.bytes(err)).header("IOP-Gw-Error", "true");
        if (e.forwardingHop != null) {
            r.header("Forwarding-Hop", e.forwardingHop);
        }
        if (e.status == 405) {
            r.header("Allow", "Heartbeat".equals(lastSegment(req.path)) ? "GET" : "POST");
        }
        return r;
    }

    // ---------------- linkedAAs push: replies carry no headers ----------------

    private Msg.Resp linkedAAsPush(Msg.Req req) {
        try {
            if (!"POST".equals(req.method)) {
                throw new GwError(405, GwError.INVALID_REQUEST, "method not allowed");
            }
            if (req.tooLarge) {
                throw new GwError(413, GwError.INVALID_REQUEST, "body too large or unreadable");
            }
            checkToken(req);
            List<String> list;
            try {
                list = LinkedAAs.parse(req.body);
            } catch (IllegalArgumentException e) {
                throw new GwError(400, GwError.INVALID_REQUEST, e.getMessage());
            }
            gw.linkedAAs.replace(list);
            LOG.atInfo().addKeyValue("count", list.size()).log("linkedAAs replaced by push");
            ObjectNode ok = Json.object();
            ok.set("linkedAAs", Json.MAPPER.valueToTree(list));
            return new Msg.Resp(200, Json.bytes(ok));
        } catch (GwError e) {
            return headerless(e, Json.newTxnId());
        }
    }

    /** Error body for key and linkedAAs push: the usual body, no headers. */
    private Msg.Resp headerless(GwError e, String txnid) {
        ObjectNode err = Json.object();
        err.put("ver", gw.gwVer());
        err.put("txnid", txnid);
        err.put("timestamp", Json.now());
        err.put("errorCode", e.code);
        err.put("errorMsg", e.getMessage());
        return new Msg.Resp(e.status, Json.bytes(err));
    }

    // ---------------- key push: HTTPS listener only, replies carry no headers ----------------

    private Msg.Resp keyPush(Msg.Req req, org.sahamati.iopgw.sources.CoreKeys keys) {
        try {
            if (keys == null) {
                throw new GwError(404, GwError.INVALID_URI, "this key type is not taken from the core");
            }
            if (req.listener != Msg.Listener.GW_HTTPS) {
                throw new GwError(403, GwError.INVALID_SECURITY, "key push is accepted only over HTTPS");
            }
            if (!"POST".equals(req.method)) {
                throw new GwError(405, GwError.INVALID_REQUEST, "method not allowed");
            }
            checkToken(req);
            if (req.tooLarge) {
                throw new GwError(413, GwError.INVALID_REQUEST, "body too large or unreadable");
            }
            java.util.List<org.sahamati.iopgw.crypto.KeyRing.PrivKey> set;
            try {
                set = keys.push(req.body);
            } catch (IllegalArgumentException e) {
                throw new GwError(400, GwError.INVALID_REQUEST, e.getMessage());
            }
            ObjectNode ok = Json.object();
            ok.set("keys", org.sahamati.iopgw.sources.CoreKeys.status(set));
            return new Msg.Resp(200, Json.bytes(ok));
        } catch (GwError e) {
            return headerless(e, ""); // a key set has no txnid
        }
    }

    private static String targetOf(String header) {
        ObjectNode te = header == null ? null : Json.parseObject(header.getBytes(StandardCharsets.UTF_8));
        String t = Json.text(te, "type");
        String i = Json.text(te, "id");
        return t != null && i != null ? t + "/" + i : null;
    }

    private static String lastSegment(String path) {
        int i = path.lastIndexOf('/');
        return i < 0 ? path : path.substring(i + 1);
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
