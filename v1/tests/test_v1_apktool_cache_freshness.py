from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source() -> str:
    return (ROOT / "android/app/src/main/java/dev/modkit/mobile/ApktoolEngine.java").read_text(encoding="utf-8")


def test_apktool_cache_requires_decoded_workspace_fingerprint():
    text = source()
    for field in ("workspaceSha256", "workspaceFileCount", "workspaceBytes"):
        assert field in text
    assert "workspaceFingerprint(workspace, cancelled)" in text
    assert 'expectedSha.equals(current.optString("sha256"))' in text
    assert 'expectedCount != current.optInt("fileCount", -2)' in text
    assert 'expectedBytes != current.optLong("bytes", -2L)' in text


def test_apktool_cache_miss_clears_stale_workspace_before_decode():
    text = source()
    clear = text.index("if (out.exists()) deleteTree(out, cancelled);")
    decode = text.index("new ApkDecoder(new ExtFile(input), config).decode(out);")
    assert clear < decode
    assert 'throw new IOException("Cannot clear stale Apktool workspace: " + file.getName())' in text


def test_apktool_hash_and_tree_operations_are_cancellable():
    text = source()
    assert "sha256(input, cancelled)" in text
    assert "hashTree(root, root, digest, stats, cancelled)" in text
    assert "check(cancelled);" in text
    assert 'catch (InterruptedIOException cancelledError)' in text
    assert 'row.put("status", "CANCELLED")' in text


def test_apktool_marker_is_written_only_after_workspace_fingerprint():
    text = source()
    fingerprint = text.index("JSONObject fp = workspaceFingerprint(out, cancelled);", text.index("new ApkDecoder"))
    marker_state = text.index('.put("workspaceSha256", fp.getString("sha256"))', fingerprint)
    marker_write = text.index("Files.write(marker.toPath()", marker_state)
    assert fingerprint < marker_state < marker_write
