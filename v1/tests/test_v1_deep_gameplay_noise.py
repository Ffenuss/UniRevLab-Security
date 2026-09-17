from modkit.mobile.deep_gameplay import analyze


def _titles(rows):
    return {row.get("title") for row in analyze({"artifacts": rows}, {"libraries": []})["findings"]}


def test_upstream_category_does_not_bootstrap_gameplay_evidence():
    titles = _titles([
        {
            "id": "x",
            "title": "__cxa_call_unexpected",
            "category": "Level / XP",
            "kind": "NATIVE_FUNCTION",
            "entry": "lib/arm64-v8a/libc++_shared.so",
        }
    ])
    assert "__cxa_call_unexpected" not in titles


def test_system_and_telemetry_contexts_are_not_gameplay_controls():
    titles = _titles([
        {"id": "goldfish", "title": "Gold", "entry": "/init.goldfish.rc"},
        {"id": "crash", "title": "setLogLevel", "entry": "com/uqm/crashsight/logger"},
        {"id": "net", "title": "setSpeed", "entry": "libalibnetworkdiagnosis.so"},
        {"id": "stack", "title": "Stack", "strings": ["exception stack trace"], "entry": "diagnostics"},
        {"id": "billing", "title": "Balance", "strings": ["purchase billing receipt"], "entry": "billing-sdk"},
    ])
    assert titles == set()


def test_real_gameplay_semantics_survive_noise_filter():
    titles = _titles([
        {"id": "speed", "title": "SetMoveSpeed", "entry": "lib/arm64-v8a/libil2cpp.so", "rva": 0x1234},
        {"id": "coins", "title": "AddCoins", "entry": "Assembly-CSharp.dll", "rva": 0x5678},
        {"id": "hp", "title": "SetMaxHP", "entry": "Assembly-CSharp.dll", "rva": 0x9ABC},
    ])
    assert {"SetMoveSpeed", "AddCoins", "SetMaxHP"}.issubset(titles)
