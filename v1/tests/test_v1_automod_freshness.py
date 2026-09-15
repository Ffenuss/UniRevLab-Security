import os
from pathlib import Path

from modkit.mobile.automod import _fresh


def _touch(path: Path, text: str = "x") -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _set_ns(path: Path, ns: int) -> None:
    os.utime(path, ns=(ns, ns))


def test_fresh_requires_every_output_to_be_at_least_as_new_as_all_inputs(tmp_path: Path):
    metadata = _touch(tmp_path / "metadata.bin")
    library = _touch(tmp_path / "library.so")
    methods = _touch(tmp_path / "analysis.methods.jsonl", "{}\n")
    summary = _touch(tmp_path / "il2cpp-crosscheck.json", "{}")
    rows = _touch(tmp_path / "il2cpp-crosscheck.methods.jsonl", "{}\n")

    _set_ns(metadata, 1_000_000_000)
    _set_ns(library, 1_100_000_000)
    _set_ns(methods, 1_200_000_000)
    _set_ns(summary, 2_000_000_000)
    _set_ns(rows, 2_100_000_000)

    assert _fresh([summary, rows], [metadata, library, methods]) is True


def test_fresh_rejects_stale_companion_rows_even_when_summary_is_new(tmp_path: Path):
    metadata = _touch(tmp_path / "metadata.bin")
    methods = _touch(tmp_path / "analysis.methods.jsonl", "{}\n")
    summary = _touch(tmp_path / "il2cpp-metadata-identity.json", "{}")
    rows = _touch(tmp_path / "il2cpp-metadata-identity.methods.jsonl", "{}\n")

    _set_ns(metadata, 2_000_000_000)
    _set_ns(methods, 2_100_000_000)
    _set_ns(summary, 3_000_000_000)
    _set_ns(rows, 1_000_000_000)

    assert _fresh([summary, rows], [metadata, methods]) is False


def test_fresh_rejects_when_input_is_newer_than_cached_evidence(tmp_path: Path):
    metadata = _touch(tmp_path / "metadata.bin")
    library = _touch(tmp_path / "library.so")
    methods = _touch(tmp_path / "analysis.methods.jsonl", "{}\n")
    summary = _touch(tmp_path / "il2cpp-crosscheck.json", "{}")
    rows = _touch(tmp_path / "il2cpp-crosscheck.methods.jsonl", "{}\n")

    _set_ns(summary, 2_000_000_000)
    _set_ns(rows, 2_000_000_000)
    _set_ns(metadata, 1_000_000_000)
    _set_ns(library, 1_000_000_000)
    _set_ns(methods, 3_000_000_000)

    assert _fresh([summary, rows], [metadata, library, methods]) is False


def test_fresh_rejects_missing_output_or_input(tmp_path: Path):
    source = _touch(tmp_path / "source")
    output = _touch(tmp_path / "output")
    missing = tmp_path / "missing"

    assert _fresh([output, missing], [source]) is False
    assert _fresh([output], [source, missing]) is False
    assert _fresh([], [source]) is False
    assert _fresh([output], []) is False
