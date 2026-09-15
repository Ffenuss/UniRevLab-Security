from pathlib import Path

from modkit.menu.builder import spec_from_analysis
from modkit.mobile.target_profile import classify_apkset_scan
from modkit.reworkspace.trust import evidence_role

ROOT = Path(__file__).resolve().parents[1]


def test_dex_review_string_does_not_become_native_menu_control():
    analysis = {
        "controlCandidates": [{
            "id": "candidate.enabledevelopermode",
            "title": "enableDeveloperModeWhenDebuggable=false",
            "kind": "dex-string",
            "source": "classes.dex",
            "status": "review",
            "suggestedType": "toggle",
            "methodVerification": {"addressConfirmed": False, "runtimeStatus": "not-observed"},
        }],
        "findings": [],
    }
    spec = spec_from_analysis(analysis)
    assert spec.controls == []


def test_dex_candidate_can_only_enter_menu_with_explicit_dex_patch_contract():
    analysis = {
        "controlCandidates": [{
            "id": "candidate.devflag",
            "title": "Developer flag",
            "kind": "dex-method-string-xref",
            "source": "classes.dex",
            "status": "confirmed",
            "suggestedType": "toggle",
            "methodVerification": {"executableDexPatchReady": True},
        }],
        "findings": [],
    }
    spec = spec_from_analysis(analysis)
    assert len(spec.controls) == 1
    assert spec.controls[0].binding is None


def test_inventory_engine_marker_alone_does_not_make_ordinary_app_hybrid():
    scan = {
        "summary": {"dexCount": 5, "nativeCount": 13, "unityMarkerCount": 1},
        "fullIl2cppPair": False,
        "dexTrust": {"surfaces": {
            "authentication": {"applicationMatches": 2},
            "network": {"applicationMatches": 3},
            "entitlement": {"applicationMatches": 1},
        }},
    }
    out = classify_apkset_scan(scan, False)
    assert out["profile"] == "APPLICATION"
    assert out["gameScore"] < 4


def test_discovery_rows_remain_fail_closed_after_legacy_dashboard_removal():
    simple = (ROOT / "modkit/mobile/simple_mode.py").read_text(encoding="utf-8")
    auto = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java").read_text(encoding="utf-8")
    automod = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModActivity.java").read_text(encoding="utf-8")
    assert 'executable = bool(binding) and rva is not None' in simple
    assert '"buildable": executable, "selectable": executable' in simple
    assert '"buildable": False, "selectable": False' in simple
    assert 'safe = [c for c in kept if c.get("binding") and c.get("rva") is not None' in simple
    assert 'ready=cat.optInt("buildable")' in auto
    # AutoMod must be reachable for locator/runtime/review candidates, but the actual signed
    # build remains gated by smart-prepare + preflight inside AutoMod/WorkerService.
    assert 'mod.setEnabled(!app.busy.get()&&(ready>0||actionable>0||important>0))' in auto
    assert 'AutoModActivity.class' in auto
    assert '"menu_smart_prepare"' in automod
    assert '"menu_preflight"' in automod
    assert '"menu_smart_build_apk"' in automod


def test_menu_builder_is_context_aware_and_collapses_advanced_tools():
    menu = (ROOT / "android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java").read_text(encoding="utf-8")
    worker = (ROOT / "android/app/src/main/java/dev/modkit/mobile/WorkerService.java").read_text(encoding="utf-8")
    assert 'hasIl2cppPath()' in menu
    assert 'Расширенные инструменты ▸' in menu
    assert 'menu_smart_prepare' in menu and 'menu_smart_build_apk' in menu
    assert 'menuSmartPrepare' in worker and 'menuSmartBuildApk' in worker
    assert 'DEX developer/debug surface остаётся evidence-only' in worker


def test_dex_scanner_records_method_local_string_context():
    scanner = (ROOT / "modkit/reworkspace/artifact_scan.py").read_text(encoding="utf-8")
    assert 'dex-method-string-xref' in scanner
    assert 'method.label' in scanner
    assert 'method.code_offset' in scanner


def test_common_bundled_sdks_are_not_counted_as_application_owned_logic():
    for cls in (
        "com.datadog.android.core.Configuration",
        "com.revenuecat.purchases.Purchases",
        "com.singular.sdk.internal.ApiStartSession",
        "com.statsig.androidsdk.Store",
    ):
        assert evidence_role(cls) == "framework/third-party"
    assert evidence_role("com.suno.android.account.SessionManager") == "application/bundled-sdk"
