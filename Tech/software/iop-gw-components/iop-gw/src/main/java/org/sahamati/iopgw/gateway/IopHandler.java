package org.sahamati.iopgw.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.sahamati.iopgw.config.Config;
import org.sahamati.iopgw.crypto.Jose;
import org.sahamati.iopgw.crypto.PubKey;
import org.sahamati.iopgw.http.Http;
import org.sahamati.iopgw.http.Json;
import org.sahamati.iopgw.model.Roles;
import org.sahamati.iopgw.model.Roles.EntityType;
import org.sahamati.iopgw.obs.Audit;
import org.sahamati.iopgw.obs.Stats;
import org.sahamati.iopgw.obs.Stats.C;
import org.sahamati.iopgw.sources.ApiKeyVerifier;
import org.sahamati.iopgw.sources.Registry.Entity;
import org.sahamati.iopgw.tenant.Tenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** The public {@code /iop/*} surface: common pipeline, terminate and forward. */
public final class IopHandler {
    private static final Logger LOG = LoggerFactory.getLogger(IopHandler.class);
    private static final String HEARTBEAT = "/iop/Heartbeat";
    private static final Set<String> ENVELOPE_FIELDS =
            Set.of("ver", "timestamp", "txnid", "correlationId", "Target", "Initiator", "encryptedPayload");

    private final Gateway gw;

    public IopHandler(Gateway gw) {
        this.gw = gw;
    }

    /** Per-request context gathered as the pipeline runs (for errors and audit records). */
    private static final class Ctx {
        String ver;
        String txnid;
        String correlationId;
        String peer;
        String role = "target";
        boolean terminating; // set once this gateway acts as the Target: its error replies then carry errorSource
        String initiator;
        String target;
        /** The entity the call is for: known from the start in single-tenant mode, from the kid or Target-Id otherwise. */
        Tenant tenant;
        final Stats.Counts counts = new Stats.Counts();
        long started = System.nanoTime();
    }

    public Msg.Resp handle(Msg.Req req) {
        Ctx ctx = new Ctx();
        if (!gw.multiTenant()) {
            ctx.tenant = gw.single(); // single-tenant: every call is for the one entity
        }
        ctx.counts.inc(C.iopReq);
        Map<String, Object> reqFields = new LinkedHashMap<>();
        reqFields.put("method", req.method);
        reqFields.put("path", req.path);
        ObjectNode early = Json.parseObject(req.body);
        reqFields.put("ver", Json.text(early, "ver"));
        reqFields.put("txnid", Json.text(early, "txnid"));
        reqFields.put("envTimestamp", Json.text(early, "timestamp"));
        reqFields.put("correlationId", Json.text(early, "correlationId"));
        reqFields.put("initiator", party(early, "Initiator"));
        reqFields.put("target", party(early, "Target"));
        reqFields.put("encryptedPayloadBytes", early != null && early.hasNonNull("encryptedPayload") ? early.get("encryptedPayload").asText().length() : null);
        reqFields.put("bodyBytes", req.body.length);
        reqFields.put("headers", Audit.headers(req.headers));
        gw.audit.record("request", "iop-in", null, gw.recordId(ctx.tenant), reqFields);
        Msg.Resp resp;
        try {
            resp = pipeline(req, ctx);
        } catch (GwError e) {
            resp = errorResponse(e, ctx);
        }
        ctx.counts.inc(C.iopResp);
        ctx.counts.inc(resp.status < 400 ? C.iopRespOk : C.iopRespErr);
        ctx.counts.inc(resp.status < 400 ? C.success : C.failure);
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("method", req.method);
        f.put("path", req.path);
        f.put("peer", ctx.peer);
        f.put("ver", ctx.ver);
        f.put("txnid", ctx.txnid);
        f.put("correlationId", ctx.correlationId);
        f.put("initiator", ctx.initiator);
        f.put("target", ctx.target);
        f.put("status", resp.status);
        f.put("bodyBytes", resp.body.length);
        ObjectNode rb = Json.parseObject(resp.body);
        f.put("errorCode", Json.text(rb, "errorCode"));
        if (resp.headers.containsKey("X-Iopgw-Own-Error")) {
            f.put("errorMsg", Json.text(rb, "errorMsg"));
            resp.headers.remove("X-Iopgw-Own-Error");
        }
        f.put("ms", (System.nanoTime() - ctx.started) / 1_000_000);
        f.put("headers", Audit.headers(resp.headers));
        gw.audit.record("response", "iop-in", ctx.role, gw.recordId(ctx.tenant), f);
        gw.stats.add(gw.recordId(ctx.tenant), ctx.counts);
        return resp;
    }

    private Msg.Resp pipeline(Msg.Req req, Ctx ctx) throws GwError {
        Map<String, Set<String>> routes = Roles.iopRoutes(gw.mode);
        Set<String> accepted = routes.get(req.path);
        if (accepted == null) {
            throw new GwError(404, GwError.INVALID_URI, "unknown /iop path for this mode");
        }
        if (!"POST".equals(req.method)) {
            throw new GwError(405, GwError.INVALID_REQUEST, "method not allowed");
        }
        if (req.tooLarge) {
            throw new GwError(413, GwError.INVALID_REQUEST, "body too large");
        }
        if (gw.multiTenant() && gw.tenants.count() == 0) {
            throw new GwError(503, GwError.SERVICE_UNAVAILABLE, "no entity loaded");
        }
        List<String> present = new ArrayList<>();
        for (String k : Roles.ALL_KEYS) {
            if (req.header(k) != null) {
                present.add(k);
            }
        }
        if (present.size() != 1) {
            throw new GwError(400, GwError.INVALID_SECURITY, present.isEmpty() ? "role api-key header missing" : "more than one role api-key header");
        }
        String key = present.get(0);
        if (!accepted.contains(key)) {
            throw new GwError(403, GwError.INVALID_SECURITY, "api-key header not accepted on this path");
        }
        Roles.Leg leg = Roles.leg(gw.mode, key);
        if (!gw.registry.loaded()) {
            throw new GwError(503, GwError.SERVICE_UNAVAILABLE, "entity registry not loaded");
        }
        ApiKeyVerifier.Caller caller = gw.apiKeys.verify(req.header(key))
                .orElseThrow(() -> new GwError(400, GwError.INVALID_SECURITY, "invalid api-key"));
        String senderId = caller.senderId();
        Entity sender = gw.registry.get(senderId)
                .orElseThrow(() -> new GwError(400, GwError.INVALID_SECURITY, "sender not registered"));
        ctx.peer = senderId;
        if (sender.type() != Roles.KEY_OWNER.get(key)) {
            throw new GwError(403, GwError.INVALID_SECURITY, "sender type does not own this api-key header");
        }
        String sig = req.header("x-jws-signature");
        if (sig == null || sig.isEmpty()) {
            throw new GwError(400, GwError.INVALID_SECURITY, "x-jws-signature missing");
        }
        if (!Jose.verifyDetached(sig, req.body, sender.signingKeys())) {
            throw new GwError(400, GwError.SIG_MISMATCH, "x-jws-signature does not verify");
        }
        if (Roles.IOP_TOKEN_KEYS.contains(key) && !caller.iopToken()) {
            // an AA role api-key must be an IopToken; checked after the api-key and signature.
            throw new GwError(400, GwError.INVALID_SECURITY, "api-key is not an IopToken");
        }
        ObjectNode env = Json.parseObject(req.body);
        if (env == null || Json.text(env, "txnid") == null) {
            throw new GwError(400, GwError.INVALID_REQUEST, "body must be a JSON envelope with txnid");
        }
        ctx.ver = Json.text(env, "ver");
        ctx.txnid = Json.text(env, "txnid");
        String corr = Json.text(env, "correlationId");
        if (corr == null || corr.isEmpty()) {
            throw new GwError(400, GwError.INVALID_REQUEST, "correlationId is required");
        }
        ctx.correlationId = corr;
        if (!Json.isUuid(corr)) {
            throw new GwError(400, GwError.INVALID_REQUEST, "correlationId must be in standard UUID format");
        }
        boolean heartbeat = HEARTBEAT.equals(req.path);
        if (leg.forward()) {
            ctx.role = "hop";
            return forward(req, ctx, env, leg, sender, heartbeat);
        }
        return terminate(req, ctx, env, leg, sender, heartbeat);
    }

    // =====================================================================================
    // Terminate
    // =====================================================================================

    private Msg.Resp terminate(Msg.Req req, Ctx ctx, ObjectNode env, Roles.Leg leg, Entity sender, boolean heartbeat)
            throws GwError {
        ctx.terminating = true;
        if (ctx.tenant == null) {
            ctx.tenant = entityOf(req, env, heartbeat);
        }
        Tenant t = ctx.tenant;
        JsonNode init = env.get("Initiator");
        String initType = Json.text(init, "type");
        String initId = Json.text(init, "id");
        if (initType == null || initId == null) {
            throw new GwError(400, GwError.INVALID_REQUEST, "Initiator is required on this leg");
        }
        ctx.initiator = initType + "/" + initId;
        if (!leg.partyType().name().equals(initType)) {
            throw new GwError(400, GwError.INVALID_REQUEST, "wrong Initiator type for this leg");
        }
        Entity initiator = gw.registry.get(initId).filter(e -> e.type() == leg.partyType())
                .orElseThrow(() -> new GwError(400, GwError.INVALID_REQUEST, "Initiator not registered"));
        JsonNode payloadNode = env.get("encryptedPayload");
        if (heartbeat) {
            if (payloadNode != null && !payloadNode.isNull()) {
                throw new GwError(400, GwError.INVALID_REQUEST, "encryptedPayload not allowed on a heartbeat");
            }
        } else if (payloadNode == null || !payloadNode.isTextual() || !Jose.isCompactJwe(payloadNode.asText())) {
            throw new GwError(400, GwError.INVALID_REQUEST, "encryptedPayload must be a compact JWE");
        }
        PubKey encKey = initiator.encryptionKey()
                .orElseThrow(() -> new GwError(500, GwError.INTERNAL, "cannot encrypt response for Initiator")); // no encryption key in its validity window

        byte[] payload = null;
        String innerJws = null;
        if (!heartbeat) {
            if (!t.decryption.loaded()) {
                throw new GwError(503, GwError.SERVICE_UNAVAILABLE, "decryption keys not loaded");
            }
            if (kidOf(payloadNode.asText()) == null) {
                throw new GwError(400, GwError.INVALID_REQUEST, NO_KID); // both modes
            }
            try {
                innerJws = Jose.decrypt(payloadNode.asText(), t.decryption, true);
            } catch (Jose.JoseException e) {
                throw new GwError(400, GwError.INVALID_REQUEST, "encryptedPayload not decryptable");
            }
            if (!Jose.isCompactJws(innerJws)) {
                throw new GwError(400, GwError.INVALID_REQUEST, "encryptedPayload does not contain a compact JWS");
            }
            payload = Jose.verifyCompact(innerJws, initiator.signingKeys());
            if (payload == null) {
                throw new GwError(400, GwError.SIG_MISMATCH, "Initiator signature does not verify");
            }
        }

        // Call the core.
        String api = req.path.substring("/iop".length());
        String url = t.coreBaseUrl() + t.corePrefix() + api;
        Map<String, String> h = new LinkedHashMap<>(t.coreEntityHeader); // Core-Entity-Id, multi-tenant mode only
        h.put("Initiator-Entity", Gateway.party(initType, initId));
        h.put("Forwarding-Hop", sender.id());
        h.put("Correlation-Id", ctx.correlationId);
        String coreToken = t.coreToken();
        if (coreToken != null) {
            h.put("Authorization", "Bearer " + coreToken);
        }
        if (!heartbeat) {
            h.put("x-jws-signature", Jose.detach(innerJws));
        }
        String method = heartbeat ? "GET" : "POST";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("method", method);
        out.put("path", t.corePrefix() + api);
        out.put("peer", "core");
        out.put("txnid", payload == null ? null : Json.text(Json.parseObject(payload), "txnid"));
        out.put("correlationId", ctx.correlationId);
        out.put("initiator", ctx.initiator);
        out.put("bodyBytes", payload == null ? 0 : payload.length);
        out.put("headers", Audit.headers(h));
        gw.audit.record("request", "core-out", "target", t.id, out);
        ctx.counts.inc(C.coreNotif);
        long t0 = System.nanoTime();
        Http.Response core;
        try {
            core = gw.http.send(method, url, h, payload, t.coreTimeout(), gw.maxUpstream());
        } catch (Http.NoResponse e) {
            ctx.counts.inc(C.coreNotifNoResp);
            Map<String, Object> f = new LinkedHashMap<>(out);
            f.remove("headers");
            f.remove("bodyBytes");
            f.put("noResponse", e.kind);
            f.put("ms", (System.nanoTime() - t0) / 1_000_000);
            gw.audit.record("response", "core-out", "target", t.id, f);
            throw new GwError(500, GwError.INTERNAL, "core unavailable");
        }
        ctx.counts.inc(C.coreNotifResp);
        ctx.counts.inc(core.status() < 400 ? C.coreNotifOk : C.coreNotifErr);
        Map<String, Object> f = new LinkedHashMap<>(out);
        f.put("status", core.status());
        f.put("bodyBytes", core.body().length);
        f.put("ms", (System.nanoTime() - t0) / 1_000_000);
        f.put("headers", Audit.headers(flatten(core.headers())));
        gw.audit.record("response", "core-out", "target", t.id, f);
        String echoed = core.header("Correlation-Id").orElse(null);
        if (!ctx.correlationId.equals(echoed)) {
            throw new GwError(500, GwError.INTERNAL, "core Correlation-Id missing or different");
        }

        // Wrap the core's answer for the Initiator. The inner JWS is always signed here; a signature
        // the core sends of its own must verify with this participant's signing keys.
        byte[] body = core.body();
        String coreSig = core.header("x-jws-signature").orElse(null);
        if (coreSig != null && !coreSig.isEmpty() && !Jose.verifyDetached(coreSig, body, t.signing.publicKeys())) {
            LOG.atWarn().addKeyValue("correlationId", ctx.correlationId).log("core response x-jws-signature does not verify");
            throw new GwError(500, GwError.INTERNAL, "core response signature does not verify");
        }
        String inner = gw.signCompact(t, body);
        String jwe;
        try {
            jwe = Jose.encrypt(inner, encKey);
        } catch (Jose.JoseException e) {
            throw new GwError(500, GwError.INTERNAL, "unable to encrypt for the Initiator");
        }
        ObjectNode reply = Json.object();
        reply.put("ver", ctx.ver);
        reply.put("timestamp", Json.now());
        reply.put("txnid", ctx.txnid);
        reply.put("correlationId", ctx.correlationId);
        reply.put("encryptedPayload", jwe); // success and error alike: the status tells them apart
        if (core.status() >= 400) {
            reply.set("errorSource", errorSource(t));
        }
        return signed(t, core.status(), Json.bytes(reply));
    }

    // =====================================================================================
    // Forward
    // =====================================================================================

    private Msg.Resp forward(Msg.Req req, Ctx ctx, ObjectNode env, Roles.Leg leg, Entity sender, boolean heartbeat)
            throws GwError {
        JsonNode tgt = env.get("Target");
        String tType = Json.text(tgt, "type");
        String tId = Json.text(tgt, "id");
        if (tType == null || tId == null) {
            throw new GwError(400, GwError.INVALID_REQUEST, "Target is required on this leg");
        }
        ctx.target = tType + "/" + tId;
        if (!leg.partyType().name().equals(tType)) {
            throw new GwError(400, GwError.INVALID_REQUEST, "wrong Target type for this leg");
        }
        if (heartbeat && EntityType.FIU.name().equals(tType)) {
            throw new GwError(400, GwError.INVALID_REQUEST, "heartbeat to an FIU is not allowed");
        }
        Tenant t = ctx.tenant; // AA mode: always single-tenant
        if (gw.tenants.isOwn(tId)) {
            throw new GwError(400, GwError.INVALID_REQUEST, "Target is this AA");
        }
        Entity target = gw.registry.get(tId).filter(e -> e.type() == leg.partyType() && e.baseUrl() != null)
                .orElseThrow(() -> new GwError(400, GwError.INVALID_ROUTE, "Target is not registered with this AA"));
        checkLinked(t, target);
        JsonNode payloadNode = env.get("encryptedPayload");
        if (heartbeat) {
            if (payloadNode != null && !payloadNode.isNull()) {
                throw new GwError(400, GwError.INVALID_REQUEST, "encryptedPayload not allowed on a heartbeat");
            }
        } else if (payloadNode == null || !payloadNode.isTextual() || !Jose.isCompactJwe(payloadNode.asText())) {
            throw new GwError(400, GwError.INVALID_REQUEST, "encryptedPayload must be a compact JWE");
        }
        ctx.initiator = sender.type().name() + "/" + sender.id();

        // New envelope: new txnid for the hop -> Target leg, the same on every retry.
        ObjectNode out = Json.object();
        if (ctx.ver != null) {
            out.put("ver", ctx.ver);
        }
        out.put("timestamp", Json.now());
        String legTxn = Json.newTxnId();
        out.put("txnid", legTxn);
        out.put("correlationId", ctx.correlationId);
        ObjectNode initiator = out.putObject("Initiator");
        initiator.put("type", sender.type().name());
        initiator.put("id", sender.id());
        if (!heartbeat) {
            out.put("encryptedPayload", payloadNode.asText());
        }
        if (Boolean.TRUE.equals(gw.config.forwarding.preserveUnknownEnvelopeFields)) {
            env.fields().forEachRemaining(e -> {
                if (!ENVELOPE_FIELDS.contains(e.getKey())) {
                    out.set(e.getKey(), e.getValue());
                }
            });
        }
        byte[] outBody = Json.bytes(out);
        String outSig = gw.signDetached(t, outBody);
        String apiKey = gw.outboundKey(t, target)
                .orElseThrow(() -> new GwError(503, GwError.SERVICE_UNAVAILABLE, "role api-key token unavailable"));
        String outPath = rewrite(req.path, target.type());
        String url = target.baseUrl() + outPath;
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", "application/json");
        h.put(leg.outboundKey(), apiKey);
        h.put("x-jws-signature", outSig);

        int retries = gw.config.forwarding.httpRetries == null ? 2 : gw.config.forwarding.httpRetries;
        Http.Response resp = null;
        Http.NoResponse lastNo = null;
        long backoff = 200;
        for (int attempt = 1; attempt <= 1 + retries; attempt++) {
            if (attempt > 1) {
                ctx.counts.inc(C.targetRetries);
                sleep(backoff);
                backoff = Math.min(backoff * 2, 2000);
            }
            Map<String, Object> rf = new LinkedHashMap<>();
            rf.put("method", "POST");
            rf.put("path", outPath);
            rf.put("peer", target.id());
            rf.put("attempt", attempt);
            rf.put("ver", ctx.ver);
            rf.put("txnid", legTxn);
            rf.put("correlationId", ctx.correlationId);
            rf.put("initiator", ctx.initiator);
            rf.put("target", ctx.target);
            rf.put("bodyBytes", outBody.length);
            rf.put("encryptedPayloadBytes", heartbeat ? null : payloadNode.asText().length());
            rf.put("headers", Audit.headers(h));
            gw.audit.record("request", "target-out", "hop", t.id, rf);
            ctx.counts.inc(C.targetReq);
            long t0 = System.nanoTime();
            try {
                resp = gw.http.send("POST", url, h, outBody, gw.forwardingTimeout(), gw.maxUpstream());
                lastNo = null;
            } catch (Http.NoResponse e) {
                lastNo = e;
                resp = null;
                ctx.counts.inc(C.targetNoResp);
                Map<String, Object> f = new LinkedHashMap<>(rf);
                f.remove("headers");
                f.remove("bodyBytes");
                f.remove("encryptedPayloadBytes");
                f.put("noResponse", e.kind);
                f.put("ms", (System.nanoTime() - t0) / 1_000_000);
                gw.audit.record("response", "target-out", "hop", t.id, f);
                continue;
            }
            ctx.counts.inc(C.targetResp);
            ctx.counts.inc(resp.status() < 400 ? C.targetOk : C.targetErr);
            ObjectNode rb = Json.parseObject(resp.body());
            Map<String, Object> f = new LinkedHashMap<>(rf);
            f.put("status", resp.status());
            f.put("bodyBytes", resp.body().length);
            f.put("errorCode", Json.text(rb, "errorCode"));
            f.put("encryptedPayloadBytes", rb != null && rb.hasNonNull("encryptedPayload") ? rb.get("encryptedPayload").asText().length() : null);
            f.remove("encryptedPayloadBytes");
            f.put("ms", (System.nanoTime() - t0) / 1_000_000);
            f.put("headers", Audit.headers(flatten(resp.headers())));
            gw.audit.record("response", "target-out", "hop", t.id, f);
            boolean retriable = (resp.status() == 502 || resp.status() == 503 || resp.status() == 504)
                    && (rb == null || !rb.hasNonNull("encryptedPayload"));
            if (!retriable) {
                break;
            }
        }
        if (resp == null) {
            boolean timeout = lastNo != null && lastNo.timeout();
            throw new GwError(timeout ? 504 : 502, GwError.DOWNSTREAM,
                    timeout ? "Target did not answer in time" : "Target unreachable");
        }
        return relay(resp, ctx, t, target);
    }

    /**
     * Hop route check: the Target must be linked to this AA. An FIU Target lists this
     * AA as a Connected-AA in the AIG; a FIP Target lists it as an Inter-AA; an AA Target is in this
     * AA's linkedAAs. Otherwise 400 InvalidRoute, and the Target is not called. An AIG not loaded
     * gives 503, and so does a linkedAAs list not loaded for an AA Target.
     */
    private void checkLinked(Tenant t, Entity target) throws GwError {
        boolean linked;
        if (target.type() == EntityType.AA) {
            if (!t.linkedAAs.loaded()) {
                throw new GwError(503, GwError.SERVICE_UNAVAILABLE, "linkedAAs not loaded");
            }
            linked = t.linkedAAs.get().contains(target.id());
        } else {
            if (!gw.aig.loaded()) {
                throw new GwError(503, GwError.SERVICE_UNAVAILABLE, "hop directory unavailable");
            }
            linked = gw.aig.candidates(target.type(), target.id()).contains(t.id);
        }
        if (!linked) {
            throw new GwError(400, GwError.INVALID_ROUTE, "Target is not linked to this AA");
        }
    }

    /** Relays the Target's answer to the caller. */
    private Msg.Resp relay(Http.Response resp, Ctx ctx, Tenant t, Entity target) throws GwError {
        byte[] body = resp.body();
        ObjectNode rb = null;
        if (body.length > 0) {
            if (!Boolean.TRUE.equals(gw.config.forwarding.skipUpstreamResponseSignature)) {
                String sig = resp.header("x-jws-signature").orElse(null);
                if (!Jose.verifyDetached(sig, body, target.signingKeys())) {
                    throw new GwError(502, GwError.DOWNSTREAM, "Target response signature invalid");
                }
            }
            rb = Json.parseObject(body);
            if (rb == null) {
                throw new GwError(502, GwError.DOWNSTREAM, "Target response unreadable");
            }
        }
        if (resp.status() < 400) {
            if (rb == null) {
                return signed(t, resp.status(), body);
            }
            rb.put("txnid", ctx.txnid);
            return signed(t, resp.status(), Json.bytes(rb));
        }
        ObjectNode err = Json.object();
        err.put("ver", ctx.ver);
        err.put("txnid", ctx.txnid);
        err.put("timestamp", Json.now());
        err.put("correlationId", ctx.correlationId);
        err.put("errorCode", GwError.DOWNSTREAM);
        JsonNode cipher = rb == null ? null : rb.get("encryptedPayload");
        if (cipher != null && !cipher.isNull()) {
            err.put("errorMsg", "Target responded with HTTP " + resp.status());
            err.set("encryptedPayload", cipher);
        } else {
            err.put("errorMsg", "No error payload received");
        }
        // the Target's errorSource object, copied unchanged when present.
        JsonNode source = rb == null ? null : rb.get("errorSource");
        if (source != null && source.isObject()) {
            err.set("errorSource", source);
        }
        return signed(t, resp.status(), Json.bytes(err));
    }

    private String rewrite(String path, EntityType targetType) {
        List<Config.PathRewrite> rules = gw.config.forwarding.pathRewrite;
        if (rules == null) {
            return path; // no default rewrite
        }
        for (Config.PathRewrite r : rules) {
            if (r.targetType.equals(targetType.name()) && r.from.equals(path)) {
                return r.to;
            }
        }
        return path;
    }

    // =====================================================================================
    // Responses
    // =====================================================================================

    private Msg.Resp signed(Tenant t, int status, byte[] body) throws GwError {
        return new Msg.Resp(status, body).header("x-jws-signature", gw.signDetached(t, body));
    }

    // =====================================================================================
    // Which entity a terminating call is for (multi-tenant mode)
    // =====================================================================================

    private static final String NO_KID = "encryptedPayload has no kid in its JWE header";

    /** The kid of a compact JWE, or null when it has none or its header cannot be read. */
    private static String kidOf(String compact) {
        try {
            return Jose.jweKid(compact);
        } catch (Jose.JoseException e) {
            return null;
        }
    }

    /**
     * A terminating call: the entity owning the JWE kid; a FIP heartbeat: the entity named in
     * {@code Target-Id}, or the one entity loaded when there is no {@code Target-Id}. {@code Target-Id}
     * is used on {@code /iop/Heartbeat} only.
     */
    private Tenant entityOf(Msg.Req req, ObjectNode env, boolean heartbeat) throws GwError {
        if (heartbeat) {
            String targetId = req.header("Target-Id");
            if (targetId == null) {
                if (gw.tenants.count() > 1) {
                    throw new GwError(400, GwError.INVALID_REQUEST, "Target-Id header is required on a heartbeat while more than one entity is loaded");
                }
                return gw.tenants.only().orElseThrow(() -> new GwError(503, GwError.SERVICE_UNAVAILABLE, "no entity loaded"));
            }
            return gw.tenants.get(targetId)
                    .orElseThrow(() -> new GwError(400, GwError.INVALID_REQUEST, "Target-Id is not a loaded entity"));
        }
        JsonNode payloadNode = env.get("encryptedPayload");
        if (payloadNode == null || !payloadNode.isTextual() || !Jose.isCompactJwe(payloadNode.asText())) {
            throw new GwError(400, GwError.INVALID_REQUEST, "encryptedPayload must be a compact JWE");
        }
        String kid = kidOf(payloadNode.asText());
        if (kid == null) {
            throw new GwError(400, GwError.INVALID_REQUEST, NO_KID);
        }
        return gw.tenants.byDecryptionKid(kid)
                .orElseThrow(() -> new GwError(400, GwError.INVALID_REQUEST, "encryptedPayload not decryptable"));
    }

    /**
     * Plaintext ErrorResponse, signed by the entity the call is for. Before that entity is known
     * (multi-tenant mode): signed by the one entity loaded, or, with none or several loaded,
     * unsigned and without errorSource. A bare 500 when it cannot sign.
     */
    private Msg.Resp errorResponse(GwError e, Ctx ctx) {
        Tenant signer = ctx.tenant != null ? ctx.tenant : gw.tenants.only().orElse(null);
        ObjectNode err = Json.object();
        err.put("ver", ctx.ver != null ? ctx.ver : gw.gwVer());
        err.put("txnid", ctx.txnid != null ? ctx.txnid : Json.newTxnId());
        err.put("timestamp", Json.now());
        if (ctx.correlationId != null && GwError.DOWNSTREAM.equals(e.code)) {
            err.put("correlationId", ctx.correlationId);
        }
        err.put("errorCode", e.code);
        err.put("errorMsg", e.getMessage());
        if (ctx.terminating && signer != null) {
            err.set("errorSource", errorSource(signer));
        }
        byte[] body = Json.bytes(err);
        Msg.Resp r;
        if (signer == null) {
            r = new Msg.Resp(e.status, body); // no entity's signing key can be chosen
        } else {
            try {
                r = signed(signer, e.status, body);
            } catch (GwError signFail) {
                return new Msg.Resp(500, null);
            }
        }
        if (e.status == 405) {
            r.header("Allow", "POST");
        }
        r.header("X-Iopgw-Own-Error", "1"); // internal marker for the audit record; removed before sending
        return r;
    }

    /** This participant as the source of an error it answers as the Target. A hop never adds its own. */
    private ObjectNode errorSource(Tenant t) {
        ObjectNode s = Json.object();
        s.put("type", gw.mode.name());
        s.put("id", t.id);
        return s;
    }

    private static String party(JsonNode env, String field) {
        JsonNode p = env == null ? null : env.get(field);
        String t = Json.text(p, "type");
        String i = Json.text(p, "id");
        return t != null && i != null ? t + "/" + i : null;
    }

    static Map<String, String> flatten(Map<String, List<String>> h) {
        Map<String, String> out = new LinkedHashMap<>();
        h.forEach((k, v) -> {
            if (k != null && !k.startsWith(":") && !v.isEmpty()) {
                out.put(k, v.get(0));
            }
        });
        return out;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
