#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
artifact=Path(sys.argv[1]).resolve(); receipt=Path(sys.argv[2]).resolve(); out=Path(sys.argv[3]).resolve(); abi=sys.argv[4]
sha=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
job={
  "schemaVersion":"1.1","assessmentId":"m3-multiabi-il2cpp-fixture","artifactSha256":sha(artifact),
  "scopeReceiptSha256":sha(receipt),"libraryEntry":f"lib/{abi}/libil2cpp.so","inputObjectId":f"fixture-{abi}",
  "analysisProfile":"DEEP","analysisModes":["FUNCTION_INDEX","CFG_INDEX","XREF_INDEX","IL2CPP_REGISTRATION_CORRELATION","DECOMPILER"],
  "decompilerTargets":[],"limits":{"wallClockSeconds":300,"memoryMiB":4096,"maxFunctions":100000,"maxCfgBlocks":500000,"maxXrefs":1000000,"maxDecompilerCharsPerFunction":100000,"maxDecompilerTotalChars":5000000}
}
out.write_text(json.dumps(job,sort_keys=True,indent=2)+"\n")
