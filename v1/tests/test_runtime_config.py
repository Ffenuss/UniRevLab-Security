import pytest
from modkit.menu import MenuControl, MenuSpec
from modkit.menu.runtime_config import (
    encode_runtime_config, decode_runtime_config, HEADER, ENTRY, MAX_CONTROLS,
    K_ACTION, K_BOOL, K_INT, K_FLOAT, K_PROBE_BOOL, K_PROBE_INT, K_PROBE_FLOAT,
)


def test_runtime_config_roundtrip_and_transliterates_labels():
    spec = MenuSpec("Тестовое меню", controls=[
        MenuControl("god", "Бессмертие", "toggle", rva=0x1234, binding="bool_setter", default=True),
        MenuControl("weather", "Погода", "button", rva=0x2340, binding="action"),
        MenuControl("level", "Уровень", "slider_int", rva=0x3450, binding="number_setter", min_value=1, max_value=50, default=10),
        MenuControl("speed", "Скорость", "slider_float", rva=0x4560, binding="number_setter", min_value=0.5, max_value=3.0, default=1.0),
    ])
    blob = encode_runtime_config(spec)
    decoded = decode_runtime_config(blob)
    assert decoded["targetSo"] == "libil2cpp.so"
    assert decoded["title"] == "Testovoe menyu"
    assert [c["kind"] for c in decoded["controls"]] == [K_BOOL, K_ACTION, K_INT, K_FLOAT]
    assert decoded["controls"][0]["label"] == "Bessmertie"
    assert decoded["controls"][0]["rva"] == 0x1234
    assert decoded["bytesUsed"] == HEADER.size + 4 * ENTRY.size


def test_runtime_config_refuses_instance_binding_without_resolver():
    with pytest.raises(ValueError, match="instance binding requires a confirmed instance resolver RVA"):
        MenuSpec("X", controls=[MenuControl(
            "x", "X", "button", rva=0x1000, binding="action", is_static=False,
            call_abi="il2cpp"
        )]).validate()


def test_runtime_config_roundtrips_il2cpp_instance_resolver():
    spec = MenuSpec("X", controls=[MenuControl(
        "cheat", "Cheat", "toggle", rva=0x2000, binding="bool_setter",
        is_static=False, call_abi="il2cpp", resolver_rva=0x3000,
        resolver_kind="out_ptr_bool", resolver_verified=True
    )])
    decoded = decode_runtime_config(encode_runtime_config(spec))
    row = decoded["controls"][0]
    assert decoded["version"] == 4
    assert row["rva"] == 0x2000
    assert row["resolverRva"] == 0x3000
    assert row["resolverKind"] == "out_ptr_bool"
    assert row["callAbi"] == "il2cpp"
    assert row["isStatic"] is False


def test_runtime_config_roundtrips_return_ptr_instance_resolver():
    spec = MenuSpec("X", controls=[MenuControl(
        "state", "State", "button", rva=0x2200, binding="action",
        is_static=False, call_abi="il2cpp", resolver_rva=0x3300,
        resolver_kind="return_ptr", resolver_verified=True,
    )])
    row = decode_runtime_config(encode_runtime_config(spec))["controls"][0]
    assert row["resolverRva"] == 0x3300
    assert row["resolverKind"] == "return_ptr"
    assert row["isStatic"] is False


def test_runtime_config_roundtrips_static_il2cpp_action():
    spec = MenuSpec("X", controls=[MenuControl(
        "run", "Run", "button", rva=0x4444, binding="action",
        call_abi="il2cpp", is_static=True
    )])
    row = decode_runtime_config(encode_runtime_config(spec))["controls"][0]
    assert row["callAbi"] == "il2cpp"
    assert row["isStatic"] is True
    assert row["resolverRva"] is None


def test_runtime_config_limit():
    controls = [MenuControl(f"x{i}", f"X{i}", "button", rva=0x1000 + i * 4, binding="action")
                for i in range(MAX_CONTROLS + 1)]
    with pytest.raises(ValueError, match="at most"):
        encode_runtime_config(MenuSpec("X", controls=controls))


def test_patch_runtime_blob_writes_mapped_modkitcfg_section():
    from modkit.menu.runtime_config import patch_runtime_blob
    from modkit.selftest import fixtures
    spec = MenuSpec("Меню", controls=[MenuControl(
        "god", "Бессмертие", "toggle", rva=0x1234, binding="bool_setter", default=False
    )])
    config = encode_runtime_config(spec, render_host="libunity.so")
    patched, report = patch_runtime_blob(fixtures.runtime_so_blob(), config)
    assert report["location"] == ".modkitcfg"
    assert report["config"]["controls"][0]["id"] == "god"
    from modkit.elf.reader import ElfFile
    sec = ElfFile(patched).section(".modkitcfg")
    assert sec is not None and sec.size >= 16 * 1024
    decoded = decode_runtime_config(patched[sec.offset: sec.offset + len(config)])
    assert decoded["title"] == "Menyu"


def test_generic_runtime_rejects_numeric_value_abi_mismatch():
    with pytest.raises(ValueError, match='requires System.Int32'):
        encode_runtime_config(MenuSpec('X', controls=[MenuControl(
            'wide', 'Wide', 'slider_int', rva=0x1000, binding='number_setter',
            min_value=0, max_value=10, value_type='System.Int64'
        )]))
    with pytest.raises(ValueError, match='requires System.Single'):
        encode_runtime_config(MenuSpec('X', controls=[MenuControl(
            'double', 'Double', 'slider_float', rva=0x1000, binding='number_setter',
            min_value=0, max_value=10, value_type='System.Double'
        )]))


def test_runtime_config_encodes_generic_ui_tabs():
    spec = MenuSpec("Tabs", controls=[
        MenuControl("damage", "Damage", "toggle", category="Combat", rva=0x1000, binding="bool_setter"),
        MenuControl("speed", "Move Speed", "slider_float", category="Movement", rva=0x2000, binding="number_setter", min_value=0.5, max_value=3.0),
        MenuControl("gold", "Gold", "slider_int", category="Currency", rva=0x3000, binding="number_setter", min_value=0, max_value=100),
        MenuControl("time", "Time Scale", "slider_float", category="World", rva=0x4000, binding="number_setter", min_value=0.5, max_value=2.0),
        MenuControl("dbg", "Debug", "toggle", category="Debug", rva=0x5000, binding="bool_setter"),
    ])
    rows = decode_runtime_config(encode_runtime_config(spec))["controls"]
    assert [r["tab"] for r in rows] == [1, 2, 3, 4, 5]



def test_runtime_config_roundtrips_read_only_probe_fields():
    spec = MenuSpec("Probe", controls=[
        MenuControl("watch_alive", "WATCH alive", "label", category="Health",
                    probe_kind="watch", probe_owner="IGame.RealMapUnit", probe_field="alive",
                    probe_offset=0x19, probe_primitive="bool", probe_status="FIELD OBSERVED"),
        MenuControl("watch_level", "WATCH level", "label", category="Progression",
                    probe_kind="watch", probe_owner="IGame.HeroData", probe_field="level",
                    probe_offset=0x14, probe_primitive="int32", probe_status="FIELD OBSERVED"),
        MenuControl("watch_speed", "WATCH actionSpeed", "label", category="Movement",
                    probe_kind="watch", probe_owner="IGame.AvatarActor", probe_field="actionSpeed",
                    probe_offset=0x8c, probe_primitive="float", probe_status="CONFIRMED"),
    ])
    decoded = decode_runtime_config(encode_runtime_config(spec))
    assert decoded["schema"] == "modkit-runtime-config-4.0"
    assert [x["kind"] for x in decoded["controls"]] == [K_PROBE_BOOL, K_PROBE_INT, K_PROBE_FLOAT]
    assert decoded["controls"][0]["probeReadOnly"] is True
    assert decoded["controls"][0]["probeOwner"] == "IGame.RealMapUnit"
    assert decoded["controls"][0]["probeField"] == "alive"
    assert decoded["controls"][0]["probeOffset"] == 0x19
    assert decoded["controls"][2]["tab"] == 2


def test_probe_control_cannot_be_executable_binding():
    with pytest.raises(ValueError, match="cannot have executable bindings"):
        MenuSpec("X", controls=[MenuControl(
            "bad_probe", "Bad", "toggle", rva=0x1000, binding="bool_setter",
            probe_kind="watch", probe_owner="IGame.X", probe_field="flag",
            probe_offset=0x10, probe_primitive="bool",
        )]).validate()
