from pathlib import Path


def test_menu_payload_uses_safe_needed_chain_and_restores_elf_method(monkeypatch, tmp_path):
    import modkit.menu as menu
    import modkit.elf.reader as reader

    calls = []

    class FakeElf:
        def __init__(self, blob):
            self.blob = bytes(blob)

        def needed(self):
            return ["liblog.so"]

        def add_needed(self, dependency):
            raise ValueError(".dynstr has only 1 trailing zero bytes; 9 required")

        def replace_needed_chain(self, dependency, *, runtime_needed=()):
            calls.append((dependency, tuple(runtime_needed)))
            assert dependency == "libmk.so"
            assert tuple(runtime_needed) == ("liblog.so",)
            return {
                "changed": True,
                "strategy": "needed-chain",
                "dependency": dependency,
                "displacedDependency": "liblog.so",
            }

    original_add_needed = FakeElf.add_needed
    monkeypatch.setattr(reader, "ElfFile", FakeElf)
    monkeypatch.setattr(menu, "verify_preflight_workspace", lambda _source: None)

    def fake_builder(_spec, _source, _runtime, _output, **_kwargs):
        host = reader.ElfFile(b"host")
        return host.add_needed("libmk.so")

    monkeypatch.setattr(menu, "_builder_write_patch_payload", fake_builder)

    runtime = tmp_path / "libmk.so"
    runtime.write_bytes(b"runtime")
    result = menu.write_patch_payload(object(), tmp_path / "base.apk", runtime, tmp_path / "pack.zip")

    assert result["strategy"] == "needed-chain"
    assert "trailing zero bytes" in result["addNeededFailure"]
    assert calls == [("libmk.so", ("liblog.so",))]
    assert FakeElf.add_needed is original_add_needed
