#!/usr/bin/env python3
from __future__ import annotations
import json
import sys
from pathlib import Path

result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert result["schemaVersion"] == "1.3", result["schemaVersion"]
assert result["architecture"]["pointerSize"] in (4, 8)
assert result["architecture"]["endian"] in ("LITTLE", "BIG")
functions = {item["name"]: item for item in result["functions"]}
assert "fixture_branch" in functions, functions.keys()
assert "il2cpp_codegen_register" in functions, functions.keys()
assert any(item["name"].startswith("Java_com_example_NativeBridge_nativeCheck") for item in result["functions"])
assert result["coverage"]["cfgBlocksReported"] >= 2
assert result["coverage"]["xrefsReported"] >= 1
assert any(item["source"] == "STATIC_EXPORT" for item in result["jniRegistrations"])
assert any(item["methodName"] == "nativeAdd" and item["signature"] == "(II)I" for item in result["jniRegistrations"]), result["jniRegistrations"]
assert any(item["kind"] == "CODE_REGISTRATION" for item in result["il2cppRegistrations"])
assert any(item["kind"] == "METADATA_REGISTRATION" for item in result["il2cppRegistrations"])
assert any(item["kind"] == "CODEGEN_REGISTER" for item in result["il2cppRegistrations"])
assert "il2cppCodegenCalls" in result
assert "il2cppPointerTables" in result
assert any(item["decompilerPreview"] for item in result["functions"])
print("Ghidra fixture result: PASS")

assert "il2cppCodegenModules" in result
