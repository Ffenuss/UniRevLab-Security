import struct

from modkit.mobile.il2cpp_no_rva_native import _resolve_modules_expected, _method_pointer


class FakeElf:
    def __init__(self, two_exact=False):
        self.b = bytearray(320)
        name = b"Assembly-CSharp.dll\0"
        self.b[16:16 + len(name)] = name
        self.reloc = {80: 0x1010, 120: 0x1010}
        if two_exact:
            struct.pack_into("<Q", self.b, 88, 2)
        else:
            struct.pack_into("<Q", self.b, 88, 999)
        struct.pack_into("<Q", self.b, 96, 0x2000)
        struct.pack_into("<Q", self.b, 128, 2)
        struct.pack_into("<Q", self.b, 136, 0x3000)
        # Candidate tables.
        struct.pack_into("<QQ", self.b, 176, 0x4100, 0x4110)
        struct.pack_into("<QQ", self.b, 208, 0x4000, 0x4010)

    def virtual(self, off):
        return 0x1000 + int(off)

    def unpack(self, fmt, off):
        return struct.unpack_from(fmt, self.b, off)

    def ptr(self, off):
        return self.unpack("<Q", off)[0]

    def offset(self, va, length=1, executable=False):
        mapping = {0x2000: 176, 0x3000: 208, 0x4000: 240, 0x4010: 244, 0x4100: 248, 0x4110: 252}
        if int(va) not in mapping:
            raise ValueError("not mapped")
        return mapping[int(va)]

    def finds(self, pattern):
        start = 0
        while True:
            pos = bytes(self.b).find(pattern, start)
            if pos < 0:
                return
            yield pos
            start = pos + 1


def test_codegenmodule_expected_method_count_disambiguates_structural_candidates():
    elf = FakeElf(two_exact=False)
    modules, stats = _resolve_modules_expected(elf, {"Assembly-CSharp.dll": 2})
    assert stats["requested"] == 1
    assert stats["resolved"] == 1
    assert stats["ambiguous"] == 0
    assert modules["Assembly-CSharp.dll"] == (2, 208)
    pointer, status = _method_pointer(elf, modules["Assembly-CSharp.dll"], 0x06000001)
    assert status == "EXECUTABLE_METHOD_POINTER"
    assert pointer == 0x4000


def test_codegenmodule_recovery_remains_fail_closed_when_exact_count_is_still_ambiguous():
    elf = FakeElf(two_exact=True)
    modules, stats = _resolve_modules_expected(elf, {"Assembly-CSharp.dll": 2})
    assert modules == {}
    assert stats["resolved"] == 0
    assert stats["ambiguous"] == 1
    assert stats["modules"]["Assembly-CSharp.dll"]["status"] == "AMBIGUOUS_AFTER_EXPECTED_COUNT"


def test_method_pointer_rejects_wrong_token_domain_and_missing_module():
    elf = FakeElf(two_exact=False)
    assert _method_pointer(elf, None, 0x06000001) == (None, "MODULE_UNRESOLVED")
    assert _method_pointer(elf, (2, 208), 0x02000001) == (None, "TOKEN_OUT_OF_MODULE_RANGE")
    assert _method_pointer(elf, (2, 208), 0x06000003) == (None, "TOKEN_OUT_OF_MODULE_RANGE")
