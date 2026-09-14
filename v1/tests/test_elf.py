"""ELF64 reader against the synthetic .so (readelf-validates it in CI, too)."""

from __future__ import annotations

import pytest

from modkit.elf.reader import ElfFile


@pytest.fixture(scope="module")
def elf(tmp_path_factory):
    from modkit.selftest import fixtures
    path = tmp_path_factory.mktemp("elf") / "libil2cpp.so"
    path.write_bytes(fixtures.so_blob())
    return ElfFile.open(path)


def test_basic_shape(elf):
    info = elf.info()
    assert info["arch"] == "aarch64"
    assert info["pie"] is True
    assert elf.is_arm64() and elf.is_pie          # is_pie is a property
    assert info["text_size"] > 0x1000


def test_needed_libraries(elf):
    assert "liblog.so" in elf.needed()
    assert "libc.so" not in elf.needed()


def test_sections_and_segments(elf):
    text = elf.section(".text")
    assert text.is_exec and text.is_alloc and text.addr == 0x200
    data = elf.section(".data.rel.ro")
    assert not data.is_exec
    assert len(elf.segments) == 2
    assert any(seg.is_exec for seg in elf.segments)


def test_rva_offset_roundtrip(elf):
    for rva in (0x200, 0x1040, 0x41FF):
        off = elf.rva_to_off(rva)
        assert off is not None
        assert elf.off_to_rva(off) == rva
    assert elf.rva_to_off(0xFFFFF00) is None


def test_stubs_exist_at_advertised_rvas(elf):
    (word,) = __import__("struct").unpack("<I", elf.read_at_rva(0x1040, 4))
    assert word == 0xA9BF7BFD          # stp x29, x30, [sp, #-16]!
    with pytest.raises(ValueError):
        elf.read_at_rva(0xFFFFF00, 4)


def test_symbols(elf):
    names = {s.name for s in elf.symbols(functions_only=True)}
    assert {"il2cpp_domain_get", "il2cpp_thread_attach"} <= names
    sym = elf.find_symbol("il2cpp_domain_get")
    assert sym.is_function and sym.is_global
    assert sym.value == 0x208


def test_search_and_missing_metadata_blob(elf):
    assert elf.find_metadata_blob() is None       # our .so keeps metadata external
    hits = elf.search(bytes.fromhex("c003 5fd6".replace(" ", "")))
    assert hits and all(h >= 0x200 for h in hits)  # the `ret` in each stub


def test_write_at_rva_mutates_the_copy(elf):
    before = elf.read_at_rva(0x1040, 4)
    elf.write_at_rva(0x1040, b"\x11\x22\x33\x44")
    assert elf.read_at_rva(0x1040, 4) == b"\x11\x22\x33\x44"
    assert before != elf.read_at_rva(0x1040, 4)


def test_rejects_non_elf64(tmp_path):
    (tmp_path / "notelf.so").write_bytes(b"\x7fELF\x01\x01\x01\x00" + bytes(64))
    with pytest.raises(ValueError, match="ELF64"):
        ElfFile.open(tmp_path / "notelf.so")
    (tmp_path / "garbage").write_bytes(b"random")
    with pytest.raises(ValueError, match="not an ELF"):
        ElfFile.open(tmp_path / "garbage")


def test_add_needed_uses_existing_dynstr_and_dynamic_slack():
    from modkit.selftest import fixtures
    elf = ElfFile(fixtures.so_blob())
    before = elf.needed()
    report = elf.add_needed('libmodkit_runtime.so')
    assert report['changed'] is True
    patched = ElfFile(elf.blob)
    assert patched.needed() == before + ['libmodkit_runtime.so']
    assert patched.soname() == 'libneon.so'


def test_add_needed_is_idempotent():
    from modkit.selftest import fixtures
    elf = ElfFile(fixtures.so_blob())
    elf.add_needed('libmodkit_runtime.so')
    patched = ElfFile(elf.blob)
    report = patched.add_needed('libmodkit_runtime.so')
    assert report['changed'] is False
    assert patched.needed().count('libmodkit_runtime.so') == 1


def test_replace_needed_chain_preserves_original_system_dependency_transitively():
    from modkit.selftest import fixtures
    elf = ElfFile(fixtures.so_blob())
    before = elf.needed()
    report = elf.replace_needed_chain('libmk.so', runtime_needed=tuple(before))
    assert report['strategy'] == 'needed-chain'
    assert report['displacedDependency'] == 'liblog.so'
    needed = ElfFile(elf.blob).needed()
    assert 'libmk.so' in needed and 'liblog.so' not in needed
