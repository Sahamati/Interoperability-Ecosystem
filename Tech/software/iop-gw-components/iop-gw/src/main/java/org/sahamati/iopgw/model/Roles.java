package org.sahamati.iopgw.model;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** The IOP role tables: role api-key headers, legs, and the paths each mode serves. */
public final class Roles {
    private Roles() {}

    public enum Mode { AA, FIU, FIP }

    public enum EntityType { AA, FIU, FIP }

    public static final String CLIENT = "client_api_key";
    // the AA role api-key headers keep their "x-" prefix (4.0 had dropped it; reverted).
    public static final String CONN_AA = "x-conn_aa_api_key";
    public static final String CUST_AA = "x-cust_aa_api_key";
    public static final String ORIG_AA = "x-orig_aa_api_key";
    public static final String FIP_KEY = "fip_api_key";
    public static final String INTER_AA = "x-inter_aa_api_key";

    public static final List<String> ALL_KEYS = List.of(CLIENT, CONN_AA, CUST_AA, ORIG_AA, FIP_KEY, INTER_AA);

    /** Type of the sender that owns each key header. */
    public static final Map<String, EntityType> KEY_OWNER = Map.of(
            CLIENT, EntityType.FIU,
            CONN_AA, EntityType.AA,
            CUST_AA, EntityType.AA,
            ORIG_AA, EntityType.AA,
            FIP_KEY, EntityType.FIP,
            INTER_AA, EntityType.AA);

    /** One leg of the role table. */
    public record Leg(String inboundKey, boolean forward, EntityType partyType, String outboundKey) {}

    /** AA-mode role table. partyType: Target type when forwarding, Initiator type when terminating. */
    public static final Map<String, Leg> AA_LEGS = Map.of(
            CLIENT, new Leg(CLIENT, true, EntityType.AA, CONN_AA),
            CUST_AA, new Leg(CUST_AA, true, EntityType.FIU, CONN_AA),
            ORIG_AA, new Leg(ORIG_AA, true, EntityType.FIP, INTER_AA),
            FIP_KEY, new Leg(FIP_KEY, true, EntityType.AA, INTER_AA),
            CONN_AA, new Leg(CONN_AA, false, EntityType.FIU, null),
            INTER_AA, new Leg(INTER_AA, false, EntityType.FIP, null));

    public static Leg leg(Mode mode, String key) {
        return switch (mode) {
            case AA -> AA_LEGS.get(key);
            case FIU -> CONN_AA.equals(key) ? new Leg(CONN_AA, false, EntityType.AA, null) : null;
            case FIP -> INTER_AA.equals(key) ? new Leg(INTER_AA, false, EntityType.AA, null) : null;
        };
    }

    private static final Set<String> ACCOUNT_KEYS = Set.of(ORIG_AA);

    /** AA-mode /iop routes and accepted keys. */
    public static final Map<String, Set<String>> AA_ROUTES = Map.ofEntries(
            Map.entry("/iop/Accounts/discover", ACCOUNT_KEYS),
            Map.entry("/iop/Accounts/link", ACCOUNT_KEYS),
            Map.entry("/iop/Accounts/link/verify", ACCOUNT_KEYS),
            Map.entry("/iop/Accounts/link/reverify", ACCOUNT_KEYS),
            Map.entry("/iop/Accounts/delink", ACCOUNT_KEYS),
            Map.entry("/iop/Account/link/Notification", Set.of(FIP_KEY, INTER_AA)),
            Map.entry("/iop/Consent", Set.of(CLIENT, CONN_AA, ORIG_AA)),
            Map.entry("/iop/FI/request", Set.of(CLIENT, CONN_AA, ORIG_AA)),
            Map.entry("/iop/FI/fetch", Set.of(CLIENT, CONN_AA, ORIG_AA)),
            Map.entry("/iop/Consent/handle", Set.of(CLIENT, CONN_AA)),
            Map.entry("/iop/Consent/fetch", Set.of(CLIENT, CONN_AA)),
            Map.entry("/iop/User/discover", Set.of(CLIENT, CONN_AA)), // FIU → Connected-AA (hop), Connected-AA → Customer-AA
            Map.entry("/iop/Consent/Notification", Set.copyOf(ALL_KEYS)),
            Map.entry("/iop/FI/Notification", Set.of(FIP_KEY, INTER_AA, CUST_AA)),
            Map.entry("/iop/Heartbeat", Set.copyOf(ALL_KEYS)));

    public static final Map<String, Set<String>> FIU_ROUTES = Map.of(
            "/iop/Consent/Notification", Set.of(CONN_AA),
            "/iop/FI/Notification", Set.of(CONN_AA));

    public static final Map<String, Set<String>> FIP_ROUTES = Map.ofEntries(
            Map.entry("/iop/Accounts/discover", Set.of(INTER_AA)),
            Map.entry("/iop/Accounts/link", Set.of(INTER_AA)),
            Map.entry("/iop/Accounts/link/verify", Set.of(INTER_AA)),
            Map.entry("/iop/Accounts/link/reverify", Set.of(INTER_AA)),
            Map.entry("/iop/Accounts/delink", Set.of(INTER_AA)),
            Map.entry("/iop/Consent", Set.of(INTER_AA)),
            Map.entry("/iop/FI/request", Set.of(INTER_AA)),
            Map.entry("/iop/FI/fetch", Set.of(INTER_AA)),
            Map.entry("/iop/Consent/Notification", Set.of(INTER_AA)),
            Map.entry("/iop/Heartbeat", Set.of(INTER_AA)));

    public static Map<String, Set<String>> iopRoutes(Mode mode) {
        return switch (mode) {
            case AA -> AA_ROUTES;
            case FIU -> FIU_ROUTES;
            case FIP -> FIP_ROUTES;
        };
    }

    /** One internal API family: what the core may call and how it maps to /iop. */
    public record Family(String prefix, String roleKey, EntityType targetType, boolean viaConnectedAA,
                         Set<String> postApis, boolean heartbeat) {}

    public static List<Family> families(Mode mode) {
        return switch (mode) {
            case FIU -> List.of(new Family("/fiu-dgw", CLIENT, EntityType.AA, true,
                    Set.of("Consent", "Consent/handle", "Consent/fetch", "FI/request", "FI/fetch", "Consent/Notification",
                            "User/discover"), // routed like the other /fiu-dgw APIs
                    true));
            case AA -> List.of(
                    new Family("/aa-dgw", CUST_AA, EntityType.FIU, true,
                            Set.of("FI/Notification", "Consent/Notification"), false), // an AA never sends user discovery: /aa-dgw/User/discover is 404
                    new Family("/aa-sgw", ORIG_AA, EntityType.FIP, false,
                            Set.of("Accounts/discover", "Accounts/link", "Accounts/delink", "Accounts/link/verify",
                                    "Accounts/link/reverify", "FI/request", "FI/fetch", "Consent/Notification", "Consent"),
                            true));
            case FIP -> List.of(new Family("/fip-sgw", FIP_KEY, EntityType.AA, false,
                    Set.of("Consent/Notification", "FI/Notification", "Account/link/Notification"), true));
        };
    }

    public static String defaultCorePrefix(Mode mode) {
        return switch (mode) {
            case AA -> "/aa-core";
            case FIU -> "/fiu-core";
            case FIP -> "/fip-core";
        };
    }
}
