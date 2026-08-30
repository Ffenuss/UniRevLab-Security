#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
r=json.loads(Path(sys.argv[1]).read_text())
assert r["schemaVersion"] == "1.3"
assert r["architecture"]["pointerSize"] in (4,8)
functions={f["name"]:f for f in r["functions"]}
for name in ("il2cpp_codegen_register","fixture_registration_call","Managed_Method_One","Managed_Method_Two"):
    assert name in functions, (name, functions.keys())
assert any(x["kind"]=="CODE_REGISTRATION" for x in r["il2cppRegistrations"]), r["il2cppRegistrations"]
assert any(x["kind"]=="METADATA_REGISTRATION" for x in r["il2cppRegistrations"]), r["il2cppRegistrations"]
assert r["il2cppCodegenCalls"], r
mods=[m for m in r["il2cppCodegenModules"] if m["moduleName"]=="Assembly-CSharp.dll"]
assert mods, r["il2cppCodegenModules"]
mod=mods[0]
assert mod["methodPointerCount"] == 2, mod
slots={s["slotIndex"]:s["functionRva"] for s in mod["sampledMethodPointers"]}
assert set(slots) >= {0,1}, slots
assert slots[0] == functions["Managed_Method_One"]["rva"], (slots, functions)
assert slots[1] == functions["Managed_Method_Two"]["rva"], (slots, functions)
print("Ghidra multi-ABI IL2CPP fixture: PASS")
