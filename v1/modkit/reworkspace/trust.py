"""Method-level Android trust-boundary classification for DEX evidence.

The classifier is deliberately architecture-oriented. It identifies concrete
application surfaces (authentication, entitlements, storage, network, etc.)
and describes whether the directly referenced behavior appears local,
platform-backed, server-backed, or still unknown. Presence is never treated as
a vulnerability and static evidence is never promoted to runtime confirmation.
"""
from __future__ import annotations

import re

from .dex import DexFile, DexError, DexDefinedMethod

_FRAMEWORK_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "org.jetbrains.",
    "com.google.", "com.android.", "com.facebook.", "com.appsflyer.", "com.adjust.",
    # Common bundled SDK namespaces. Their presence is valuable trust-boundary
    # evidence, but it must not be counted as application-owned business logic.
    "com.datadog.", "com.revenuecat.", "com.singular.", "com.statsig.",
    "io.sentry.", "com.braze.", "com.intercom.", "com.segment.",
    "com.amplitude.", "com.mixpanel.", "com.onesignal.", "io.branch.",
    "com.stripe.", "com.adyen.", "com.paypal.", "com.squareup.",
    "okhttp3.", "retrofit2.", "com.applovin.", "com.ironsource.", "com.unity3d.ads.",
    "org.spongycastle.", "org.bouncycastle.", "org.chromium.", "com.linecorp.android.security.",
)

# Rules are intentionally conservative and based on class/method names first.
# Strings and invoke targets are used to establish trust-boundary context, not to
# turn an unrelated method into a finding merely because a generic word appears.
_SURFACE_RULES = {
    "defensive": {
        "tokens": {"tamper", "fraud", "integrity", "root", "anticheat", "defensive"},
        "compact": ("anticheat", "cheatdetection", "playintegrity", "safetynet"),
    },
    "monetization": {
        "tokens": {"payment", "purchase", "billing", "iap", "cashier", "receipt"},
        "compact": ("billingclient", "inapppurchase", "purchaseflow", "paymentmanager",
                    "confirmorder", "createorder", "purchaseorder", "paywithcurrency", "paymentrequest"),
    },
    "entitlement": {
        "tokens": {"premium", "subscription", "entitlement", "license", "licensed", "pro", "unlock", "sku"},
        "compact": ("fullversion", "ispremium", "hasentitlement", "subscriptionstate", "licensecheck"),
    },
    "authentication": {
        "tokens": {"auth", "login", "signin", "signon", "token", "session", "oauth", "credential", "password"},
        "compact": ("authentication", "refreshtoken", "accesstoken", "sessionmanager", "accountlogin"),
    },
    "feature_flags": {
        "tokens": {"feature", "flag", "experiment", "variant", "toggle", "rollout"},
        "compact": ("featureflag", "remoteconfig", "abtest", "experimentmanager"),
    },
    "local_storage": {
        "tokens": {"database", "sqlite", "room", "datastore", "preferences", "sharedpreferences", "cache", "storage"},
        "compact": ("sharedpreferences", "sqliteopenhelper", "roomdatabase", "localstore", "diskcache"),
    },
    "network": {
        "tokens": {"network", "request", "response", "http", "https", "api", "endpoint", "websocket", "grpc"},
        "compact": ("okhttp", "retrofit", "urlconnection", "websocket", "grpc", "apiclient"),
    },
    "crypto": {
        "tokens": {"encrypt", "decrypt", "cipher", "keystore", "signature", "digest", "hmac", "aes", "rsa"},
        "compact": ("secretkey", "publickey", "privatekey", "keygenerator", "messagedigest"),
    },
    "webview": {
        "tokens": {"webview", "javascript", "web", "browser"},
        "compact": ("addjavascriptinterface", "evaluatejavascript", "webviewclient", "loadurl"),
    },
    "deep_link": {
        "tokens": {"deeplink", "intent", "uri", "scheme", "applink", "navigation"},
        "compact": ("deeplink", "appscheme", "intentfilter", "navdeeplink"),
    },
    "debug": {
        "tokens": {"debug", "developer", "diagnostic", "console", "staging", "testmode"},
        "compact": ("developermenu", "debugmenu", "devmenu", "diagnosticmenu", "testmode"),
    },
    "serialization": {
        "tokens": {"serialize", "deserialize", "parcel", "json", "protobuf", "gson", "moshi", "jackson"},
        "compact": ("jsonadapter", "typeadapter", "protobuf", "serializer", "deserializer"),
    },
}

_SERVER_WORDS = (
    "https", "http", "request", "response", "retrofit", "okhttp", "urlconnection", "websocket", "grpc",
    "confirmorder", "ordercallback", "refresh_token", "access_token", "bearer", "/api/", "endpoint",
)
_PLATFORM_WORDS = (
    "billingclient", "purchasesupdated", "googleplay", "playintegrity", "safetynet", "accountmanager",
    "android.security.keystore", "biometricprompt", "credentialmanager",
)
_LOCAL_WORDS = (
    "sharedpreferences", "sqlite", "roomdatabase", "datastore", "filesdir", "cachedir", "localstore",
    "getpreferences", "putstring", "putboolean", "database", "diskcache",
)


def evidence_role(cls: str) -> str:
    c = cls.casefold()
    return "framework/third-party" if c.startswith(_FRAMEWORK_PREFIXES) else "application/bundled-sdk"


def ownership_kind(cls: str) -> str:
    """Human-oriented ownership bucket without changing the legacy evidenceRole API."""
    c = cls.casefold()
    if c.startswith(_FRAMEWORK_PREFIXES):
        return "FRAMEWORK"
    if ".sdk." in c or c.startswith((
        "com.facebook.", "com.tiktok.", "com.linecorp.", "com.adjust.", "com.appsflyer.",
        "com.google.android.gms.", "com.google.firebase.", "com.revenuecat.", "com.stripe.",
        "com.paypal.", "com.squareup.", "io.sentry.", "com.braze.", "com.onesignal.",
    )):
        return "BUNDLED_SDK"
    return "APP"


def _terms(m: DexDefinedMethod) -> str:
    return " ".join([m.cls, m.name, *m.strings, *(x.label for x in m.invokes)]).casefold()


def _name_tokens(text: str) -> tuple[set[str], str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    words = re.findall(r"[a-z0-9]+", text.casefold())
    return set(words), "".join(words)


def surfaces_for_method(m: DexDefinedMethod) -> list[str]:
    tokens, compact = _name_tokens(f"{m.cls} {m.name}")
    role = evidence_role(m.cls)
    found: list[str] = []
    for surface, rule in _SURFACE_RULES.items():
        token_hit = bool(tokens & rule["tokens"])
        compact_hit = any(x in compact for x in rule["compact"])
        if token_hit or compact_hit:
            # Framework/support names need a strong compound marker for auth/payment.
            if role != "application/bundled-sdk" and surface in {"monetization", "entitlement", "authentication"} and not compact_hit:
                continue
            if surface in {"defensive", "debug"} and role != "application/bundled-sdk":
                continue
            found.append(surface)
    # Stable priority preserves the historical single-surface API behavior.
    priority = list(_SURFACE_RULES)
    found.sort(key=priority.index)
    return found


def surface_for_method(m: DexDefinedMethod) -> str | None:
    surfaces = surfaces_for_method(m)
    return surfaces[0] if surfaces else None


def _trust(m: DexDefinedMethod) -> str:
    text = _terms(m)
    if any(x in text for x in _SERVER_WORDS):
        return "server-backed"
    if any(x in text for x in _PLATFORM_WORDS):
        return "platform-backed"
    if any(x in text for x in _LOCAL_WORDS):
        return "local"
    return "unknown"


def _local_authority(surface: str, trust: str, m: DexDefinedMethod) -> str:
    text = _terms(m)
    if trust == "server-backed":
        return "not-confirmed"
    if trust == "platform-backed":
        return "not-confirmed"
    if trust == "local":
        return "possible-local"
    if surface in {"local_storage", "feature_flags", "debug"} and any(x in text for x in _LOCAL_WORDS):
        return "possible-local"
    return "unknown"


def method_record(m: DexDefinedMethod, artifact: str, surface: str | None = None) -> dict:
    surface = surface or surface_for_method(m)
    trust = _trust(m)
    role = evidence_role(m.cls)
    direct_calls = [x.label for x in m.invokes[:24]]
    concrete_strings = [x[:240] for x in m.strings[:8]]
    presence = 0.98 if role == "application/bundled-sdk" else 0.88
    behavior = min(0.97, 0.58 + min(len(direct_calls), 8) * 0.035 + min(len(concrete_strings), 6) * 0.025)
    actionability = {
        "server-backed": 0.16,
        "platform-backed": 0.24,
        "local": 0.42,
        "unknown": 0.30,
    }[trust]
    return {
        "artifact": artifact, "surface": surface, "class": m.cls, "method": m.name,
        "label": m.label, "codeOffset": m.code_offset, "evidenceRole": role,
        "ownershipKind": ownership_kind(m.cls),
        "trustBoundary": trust, "localAuthority": _local_authority(str(surface), trust, m),
        "presenceConfidence": round(presence, 2),
        "behaviorConfidence": round(behavior, 2), "actionabilityConfidence": round(actionability, 2),
        "strings": concrete_strings, "directInvokes": direct_calls,
        "rationale": "Direct DEX method/string references describe an application surface and trust boundary; this is static evidence, not a vulnerability or runtime confirmation.",
    }


def _surface_summary(rows: list[dict], surface: str, max_methods: int) -> dict:
    group = [x for x in rows if x.get("surface") == surface]
    group.sort(key=lambda r: (
        r.get("evidenceRole") == "application/bundled-sdk",
        r.get("trustBoundary") == "server-backed",
        float(r.get("behaviorConfidence", 0.0)),
        len(r.get("directInvokes") or []),
    ), reverse=True)
    retained = group[:max_methods]
    app = [x for x in group if x.get("evidenceRole") == "application/bundled-sdk"]
    app_boundaries = [str(x.get("trustBoundary") or "unknown") for x in app]
    if "server-backed" in app_boundaries:
        trust = "server-backed"
    elif "platform-backed" in app_boundaries:
        trust = "platform-backed"
    elif "local" in app_boundaries:
        trust = "local"
    else:
        trust = "unknown"
    local_authority = "possible-local" if any(x.get("localAuthority") == "possible-local" for x in app) else (
        "not-confirmed" if trust in {"server-backed", "platform-backed"} and app else "unknown"
    )
    return {
        "methods": retained,
        "totalMatches": len(group),
        "applicationMatches": len(app),
        "trustBoundaries": sorted({str(x.get("trustBoundary", "unknown")) for x in group}),
        "presenceConfidence": round(max((float(x.get("presenceConfidence", 0.0)) for x in group), default=0.0), 2),
        "behaviorConfidence": round(max((float(x.get("behaviorConfidence", 0.0)) for x in group), default=0.0), 2),
        "trustBoundary": trust,
        "localAuthority": local_authority,
    }


def analyze_dex_trust(artifacts, max_methods_per_surface: int = 120) -> dict:
    items = artifacts.items() if hasattr(artifacts, "items") else artifacts
    rows, errors = [], []
    for name, blob in items:
        if not str(name).lower().endswith(".dex") or not isinstance(blob, (bytes, bytearray)) or not bytes(blob).startswith(b"dex\n"):
            continue
        try:
            dex = DexFile(bytes(blob))
            for m in dex.iter_defined_methods():
                for surface in surfaces_for_method(m):
                    rows.append(method_record(m, str(name), surface))
        except (DexError, ValueError, IndexError) as exc:
            errors.append({"artifact": str(name), "error": str(exc)})

    result = {"schema": "modkit-dex-trust-2", "methodsScanned": len(rows), "errors": errors, "surfaces": {}}
    for surface in _SURFACE_RULES:
        result["surfaces"][surface] = _surface_summary(rows, surface, max_methods_per_surface)
    return result


SURFACE_NAMES = {
    "monetization": "Payments / Purchases",
    "entitlement": "Entitlements / Premium",
    "authentication": "Authentication / Session",
    "feature_flags": "Feature Flags / Experiments",
    "local_storage": "Local Storage / Database",
    "network": "Network / API",
    "crypto": "Crypto / Key Storage",
    "webview": "WebView / JavaScript Bridge",
    "deep_link": "Deep Links / Intents",
    "debug": "Debug / Developer Surfaces",
    "serialization": "Serialization",
    "defensive": "Integrity / Defensive Controls",
}
