from modkit.reworkspace.native import NativeWorkspace
from modkit.selftest import fixtures


def test_native_workspace_hex_asm_undo(tmp_path):
    so = tmp_path / "libx.so"
    so.write_bytes(fixtures.so_blob())
    ws = NativeWorkspace(so)
    assert ws.summary()["arch"] == "aarch64"
    assert ws.sections()
    rows = ws.hex_page(0x200, 32)
    assert rows and "hex" in rows[0]
    old = ws.elf.read_at_rva(0x1040, 4)
    ch = ws.patch_asm(0x1040, "NOP")
    assert ch["source"] == "asm"
    assert ws.elf.read_at_rva(0x1040, 4) != old
    assert ws.undo() is not None
    assert ws.elf.read_at_rva(0x1040, 4) == old
    ws.patch_hex(0x1040, "1f 20 03 d5", "manual nop")
    out = tmp_path / "patched.so"
    saved = ws.save(out)
    assert out.is_file() and saved["changes"]


def test_native_workspace_symbols_and_disasm(tmp_path):
    so = tmp_path / "libx.so"
    so.write_bytes(fixtures.so_blob())
    ws = NativeWorkspace(so)
    assert any(s["name"] == "il2cpp_domain_get" for s in ws.symbols("domain"))
    assert ws.disassemble(0x1040, 16)
