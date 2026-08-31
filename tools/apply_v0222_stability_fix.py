#!/usr/bin/env python3
from pathlib import Path
import runpy

root = Path(__file__).resolve().parent.parent
state = root / "app/src/main/java/org/unirevlab/security/analysis/AnalysisRunState.kt"
text = state.read_text(encoding="utf-8")
old = '''    val startedAtEpochMs: Long,
    val updatedAtEpochMs: Long = System.currentTimeMillis(),
) {
    init {
        require(percent in 0..100) { "percent must be in 0..100" }
    }
}
'''
new = '''    val startedAtEpochMs: Long,
    val updatedAtEpochMs: Long = System.currentTimeMillis(),
    val fractionComplete: Double = percent / 100.0,
    val estimatedFinishAtEpochMs: Long? = null,
) {
    init {
        require(percent in 0..100)
        require(fractionComplete.isFinite() && fractionComplete in 0.0..1.0)
    }
}
'''
if new not in text:
    if old not in text:
        raise SystemExit("AnalysisRunState.kt patch state mismatch")
    state.write_text(text.replace(old, new, 1), encoding="utf-8")
    print("patched: AnalysisRunState.kt")

# Once the verified v0.22.2 analyzer sources have been committed back to the branch, later UI/version
# changes must not be forced to match the historical patch byte-for-byte. Use stable integration
# markers and skip the bootstrap patch in that state.
inspector = root / "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt"
eta = root / "app/src/main/java/org/unirevlab/security/analysis/AnalysisEtaEstimator.kt"
manifest = root / "app/src/main/AndroidManifest.xml"
fully_integrated = (
    inspector.is_file()
    and eta.is_file()
    and 'ENGINE_VERSION = "0.22.2-dev-dex-stability-eta"' in inspector.read_text(encoding="utf-8")
    and 'android:largeHeap="true"' in manifest.read_text(encoding="utf-8")
    and "fractionComplete" in state.read_text(encoding="utf-8")
)

if fully_integrated:
    print("v0.22.2 stability patch already integrated; preserving newer UI/source edits")
else:
    runpy.run_path(str(root / ".ci/apply_v0222_stability_fix.py"), run_name="__main__")
