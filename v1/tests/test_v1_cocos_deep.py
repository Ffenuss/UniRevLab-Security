from __future__ import annotations

from modkit.engines import build_default_registry
from modkit.mobile import cocos_deep


def _artifact(function: str = "takeDamage") -> dict:
    return {
        "artifacts": [
            {
                "id": "script:javascript:test",
                "kind": "SCRIPT_SYMBOL",
                "family": "javascript",
                "entry": "assets/src/player.js",
                "function": function,
                "line": 7,
                "charOffset": 90,
            },
            {
                "id": "artifact:cocos:engine",
                "kind": "ARTIFACT_FAMILY",
                "family": "cocos",
                "entry": "lib/arm64-v8a/libcocos2dcpp.so",
            },
        ]
    }


def _native(function: str = "js_Player_takeDamage") -> dict:
    return {
        "libraries": [
            {
                "entry": "lib/arm64-v8a/libcocos2dcpp.so",
                "soname": "libcocos2dcpp.so",
                "needed": ["liblog.so"],
                "functions": [
                    {"name": function, "rva": 0x1200, "size": 64},
                    {"name": "cocos2d::Node::runAction", "rva": 0x2200, "size": 80},
                ],
                "controlFlow": [
                    {
                        "sourceFunction": function,
                        "sourceRva": 0x1200,
                        "targetFunction": "cocos2d::Node::runAction",
                        "targetRva": 0x2200,
                        "kind": "arm64-direct-bl",
                        "targetResolution": "EXACT_STATIC",
                    }
                ],
            }
        ]
    }


def test_cocos_correlates_script_symbol_to_exact_native_bridge_rva():
    out = cocos_deep.correlate(_artifact(), _native())
    assert out["available"] is True
    assert out["detected"] is True
    assert out["detectionConfidence"] == "HIGH"
    assert out["nativeLibraryCount"] == 1
    assert out["scriptArtifactCount"] >= 1
    assert out["correlationCount"] == 1

    row = out["correlations"][0]
    assert row["scriptFunction"] == "takeDamage"
    assert row["scriptLine"] == 7
    assert row["scriptCharOffset"] == 90
    assert row["nativeFunction"] == "js_Player_takeDamage"
    assert row["nativeRva"] == 0x1200
    assert row["match"] == "BRIDGE_NAME_TOKEN"
    assert row["targetResolution"] == "EXACT_NATIVE_SYMBOL_ONLY"
    assert row["runtimeTruth"] == "not-observed-by-static-analysis"
    assert "scriptRva" not in row
    assert row["controlFlowEvidence"][0]["targetRva"] == 0x2200


def test_generic_script_names_are_not_promoted_to_native_matches():
    out = cocos_deep.correlate(_artifact("update"), _native("js_Player_update"))
    assert out["available"] is True
    assert out["correlationCount"] == 0


def test_non_cocos_js_and_native_do_not_create_cocos_runtime():
    artifacts = {"artifacts": [{
        "id": "script:javascript:plain", "kind": "SCRIPT_SYMBOL", "family": "javascript",
        "entry": "assets/web/app.js", "function": "takeDamage", "line": 1, "charOffset": 0,
    }]}
    native = {"libraries": [{
        "entry": "lib/arm64-v8a/libgame.so", "soname": "libgame.so", "needed": [],
        "functions": [{"name": "takeDamage", "rva": 0x1000, "size": 32}], "controlFlow": [],
    }]}
    out = cocos_deep.correlate(artifacts, native)
    assert out["available"] is False
    assert out["nativeLibraryCount"] == 0
    assert out["correlationCount"] == 0


def test_cocos_deep_engine_is_bundled_and_static():
    engine = build_default_registry().get("cocos.deep-embedded")
    assert engine.bundled is True
    assert "script-native-correlation" in engine.capabilities
    assert "exact-native-rva" in engine.capabilities
