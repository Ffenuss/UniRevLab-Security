from modkit.reworkspace.dex import DexDefinedMethod, DexMethodRef
from modkit.reworkspace.trust import surfaces_for_method, method_record
from modkit.mobile.app_discovery import build_application_discovery
from modkit.mobile.target_profile import classify_report, classify_apkset_scan


def _m(cls, name, strings=(), invokes=()):
    return DexDefinedMethod(
        index=1, cls=cls, name=name, return_type="boolean", parameters=[],
        access_flags=1, code_offset=0x100, strings=list(strings), invokes=list(invokes),
    )


def test_trust_classifier_covers_application_surfaces_without_vulnerability_claims():
    auth = _m("com.example.account.SessionManager", "refreshToken", ["https://api.example.test/session"])
    assert "authentication" in surfaces_for_method(auth)
    row = method_record(auth, "classes.dex", "authentication")
    assert row["trustBoundary"] == "server-backed"
    assert row["localAuthority"] == "not-confirmed"
    assert "not a vulnerability" in row["rationale"]

    flags = _m("com.example.flags.FeatureFlagStore", "loadFlags", ["SharedPreferences"])
    assert "feature_flags" in surfaces_for_method(flags)
    f = method_record(flags, "classes2.dex", "feature_flags")
    assert f["trustBoundary"] == "local"
    assert f["localAuthority"] == "possible-local"


def test_application_discovery_separates_confirmed_review_and_not_found_local():
    report = {
        "dexTrust": {
            "schema": "modkit-dex-trust-2",
            "methodsScanned": 2,
            "errors": [],
            "surfaces": {
                "authentication": {
                    "totalMatches": 1, "applicationMatches": 1, "trustBoundary": "server-backed",
                    "localAuthority": "not-confirmed", "presenceConfidence": .98, "behaviorConfidence": .7,
                    "methods": [{"label": "com.example.Auth::login()", "artifact": "classes.dex", "evidenceRole": "application/bundled-sdk", "trustBoundary": "server-backed", "localAuthority": "not-confirmed"}],
                },
                "crypto": {
                    "totalMatches": 1, "applicationMatches": 0, "trustBoundary": "platform-backed",
                    "localAuthority": "unknown", "presenceConfidence": .88, "behaviorConfidence": .6,
                    "methods": [{"label": "android.security.keystore.KeyStore::get()", "artifact": "classes.dex", "evidenceRole": "framework/third-party", "trustBoundary": "platform-backed", "localAuthority": "not-confirmed"}],
                },
            },
        }
    }
    out = build_application_discovery(report)
    cards = {x["domain"]: x for x in out["cards"]}
    assert cards["authentication"]["status"] == "CONFIRMED"
    assert cards["crypto"]["status"] == "REVIEW"
    assert cards["webview"]["status"] == "NOT_FOUND_LOCAL"
    assert "does not prove absence" in out["statusSemantics"]["NOT_FOUND_LOCAL"]


def test_target_profile_distinguishes_app_game_and_hybrid():
    app = classify_report({
        "inventory": {"dex": [{"name": "classes.dex"}], "native": [], "other": []},
        "dexTrust": {"surfaces": {
            "authentication": {"applicationMatches": 2},
            "network": {"applicationMatches": 3},
            "local_storage": {"applicationMatches": 1},
        }},
        "findings": [],
    })
    assert app["profile"] == "APPLICATION"

    game = classify_report({
        "inventory": {"dex": [], "native": [{"name": "libil2cpp.so"}], "other": []},
        "dexTrust": {"surfaces": {}},
        "findings": [{"category": "gameplay_controls"}],
        "unity": {"bundles": [{"apk_entry": "assets/game.bundle"}]},
    })
    assert game["profile"] == "GAME"

    hybrid = classify_report({
        "inventory": {"dex": [{"name": "classes.dex"}], "native": [{"name": "libil2cpp.so"}], "other": []},
        "dexTrust": {"surfaces": {
            "authentication": {"applicationMatches": 1},
            "entitlement": {"applicationMatches": 1},
            "network": {"applicationMatches": 1},
        }},
        "findings": [{"category": "gameplay_controls"}],
        "unity": {"bundles": [{"apk_entry": "assets/game.bundle"}]},
    })
    assert hybrid["profile"] == "HYBRID"


def test_inventory_profile_uses_android_game_category_without_forcing_other_apps_to_game():
    scan = {"summary": {"dexCount": 2, "nativeCount": 1, "unityMarkerCount": 0}}
    assert classify_apkset_scan(scan, False)["profile"] == "APPLICATION"
    assert classify_apkset_scan(scan, True)["profile"] in {"GAME", "HYBRID"}
