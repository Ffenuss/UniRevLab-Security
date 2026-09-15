from pathlib import Path


SOURCE = Path("android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java")


def test_embedded_rerun_recursively_clears_hermes_output_tree_before_backend():
    source = SOURCE.read_text(encoding="utf-8")

    helper = source.split("private void deleteRunTree", 1)[1].split("private void invalidateEmbeddedRunOutputs", 1)[0]
    assert "file.isDirectory()" in helper
    assert "for(File child:children)deleteRunTree(child);" in helper
    assert "app.cancelled.get()" in helper
    assert "if(!file.delete()&&file.exists())" in helper

    invalidation = source.split("private void invalidateEmbeddedRunOutputs()", 1)[1].split("/** Chaquopy", 1)[0]
    assert '"hermes-deep"' in invalidation
    assert '"hermes-deep.json"' in invalidation
    assert "deleteRunTree(app.file(name));" in invalidation
    assert '"native-deep-cache"' not in invalidation

    stage = source.index('stage(4,4,"Lua/JS/Hermes deep')
    clear = source.index("invalidateEmbeddedRunOutputs();", stage)
    backend = source.index('getModule("modkit.mobile.embedded_pipeline")', clear)
    assert stage < clear < backend
