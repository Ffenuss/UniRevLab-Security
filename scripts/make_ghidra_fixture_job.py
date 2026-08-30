#!/usr/bin/env python3
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path

artifact = Path(sys.argv[1]).resolve()
receipt = Path(sys.argv[2]).resolve()
out = Path(sys.argv[3]).resolve()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
job = {
    "schemaVersion": "1.1",
    "assessmentId": "m3-ghidra-fixture",
    "artifactSha256": sha(artifact),
    "scopeReceiptSha256": sha(receipt),
    "libraryEntry": "lib/arm64-v8a/libunirevlab_ghidra_fixture.so",
    "inputObjectId": "fixture-object",
    "analysisProfile": "DEEP",
    "analysisModes": [
        "FUNCTION_INDEX", "CFG_INDEX", "XREF_INDEX", "JNI_REGISTRATION_RECOVERY",
        "IL2CPP_REGISTRATION_CORRELATION", "DECOMPILER"
    ],
    "decompilerTargets": [],
    "limits": {
        "wallClockSeconds": 300,
        "memoryMiB": 4096,
        "maxFunctions": 100000,
        "maxCfgBlocks": 500000,
        "maxXrefs": 1000000,
        "maxDecompilerCharsPerFunction": 100000,
        "maxDecompilerTotalChars": 5000000
    }
}
out.write_text(json.dumps(job, sort_keys=True, indent=2) + "\n", encoding="utf-8")
