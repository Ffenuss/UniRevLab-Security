"""dump.cs parsing: the main input for a menu build."""

from __future__ import annotations

from modkit.dumper.dumpcs import DumpParser, parse_dump_text

SAMPLE = """// Image 0: Assembly-CSharp.dll // 0
// Image 1: UnityEngine.dll // 1

// Image 0: Assembly-CSharp.dll // 0
// Namespace: Game.Save
[Serializable]
public sealed class SaveData : UnityEngine.ScriptableObject // TypeSize: 0x18
{
\t// Fields
\tpublic System.Int32 coins; // 0x10
\tprivate static System.Boolean s_unlocked; // StaticValue: 0x2A4C10, Offset: 0x0

\t// Methods
\tpublic System.Void .ctor() { }
\tpublic System.Int32 get_Coins() { } // RVA: 0x1A2B40 Offset: 0x1A2B40 VA: 0x701A2B40
\tpublic System.Void set_Coins(System.Int32 value) { } // RVA: 0x1A2B50 Offset: 0x1A2B50 VA: 0x701A2B50
\tpublic System.Collections.Generic.Dictionary<System.String, System.Int32> GetStats() { } // RVA: 0x1A2B60 Offset: 0x1A2B60 VA: 0x701A2B60
\tprivate System.Void Recalculate() { } // RVA: 0x0 VA: 0x0
}

// Image 0: Assembly-CSharp.dll // 0
// Namespace: Game.Play
public class Player : MonoBehaviour // TypeSize: 0x20
{
\t// Fields
\tpublic System.Single health; // 0x18
\tpublic System.Single maxHealth; // 0x1C

\t// Methods
\tpublic System.Void Update() { } // RVA: 0x1A3000 Offset: 0x1A3000 VA: 0x701A3000
\tpublic override System.Void TakeDamage(System.Single amount) { } // RVA: 0x1A3010 Offset: 0x1A3010 VA: 0x701A3010
}

// Image 1: UnityEngine.dll // 1
// Namespace: UnityEngine
public class MonoBehaviour : Component // TypeSize: 0x10
{
}
"""


def parse(text: str = SAMPLE):
    return DumpParser().parse(text)


def test_classes_namespaces_and_images():
    prog = parse()
    save = prog.lookup("Game.Save.SaveData")
    player = prog.lookup("Game.Play.Player")
    assert save is not None and player is not None
    assert save.image == "Assembly-CSharp.dll"
    assert prog.lookup("UnityEngine.MonoBehaviour").image == "UnityEngine.dll"
    assert save.type_size == 0x18
    assert save.base.endswith("ScriptableObject")


def test_attributes_are_skipped_and_nested_blocks_close():
    prog = parse()
    assert not any("Serializable" in c.name for c in prog.classes)
    assert prog.summary()["classes"] == 3


def test_fields_offsets_and_statics():
    save = parse().lookup("Game.Save.SaveData")
    coins = save.get_field("coins")
    unlocked = save.get_field("s_unlocked")
    assert (coins.type, coins.offset, coins.is_static) == ("System.Int32", 0x10, False)
    assert unlocked.is_static and unlocked.is_private
    assert unlocked.static_value == 0x2A4C10
    assert unlocked.offset == 0x0


def test_method_rvas_params_and_modifiers():
    save = parse().lookup("Game.Save.SaveData")
    setter = save.get_method("set_Coins")
    assert setter.rva == 0x1A2B50
    assert setter.return_type == "System.Void"          # never "public System.Void"
    assert [p.name for p in setter.params] == ["value"]
    assert setter.is_prop_accessor and not setter.is_static
    generic = save.get_method("GetStats")
    assert generic.return_type.startswith("System.Collections.Generic.Dictionary")
    assert generic.rva == 0x1A2B60


def test_zero_rva_is_not_addressable():
    save = parse().lookup("Game.Save.SaveData")
    assert not save.get_method("Recalculate").addressable
    assert not save.get_method(".ctor")                  # ctors carry no rva in dumps


def test_override_modifier_is_virtual():
    player = parse().lookup("Game.Play.Player")
    dmg = player.get_method("TakeDamage")
    assert dmg.is_virtual and dmg.rva == 0x1A3000 + 0x10
    assert not player.get_method("Update").is_static


def test_engine_types_excluded_from_user_classes():
    prog = parse()
    names = {c.full_name for c in prog.user_classes()}
    assert "UnityEngine.MonoBehaviour" not in names
    assert {"Game.Save.SaveData", "Game.Play.Player"} <= names


def test_lookup_tolerates_short_and_slashed_names():
    prog = parse()
    assert prog.lookup("SaveData").full_name == "Game.Save.SaveData"
    assert prog.lookup("Game.Save/SaveData").full_name == "Game.Save.SaveData"
    assert prog.lookup("Nope.Nope") is None


def test_find_by_regex():
    prog = parse()
    hits = prog.find(r"(player|savedata)", r"^(get|set)_Coins$")
    assert [(c.name, m.name) for c, m in hits] == [("SaveData", "get_Coins"), ("SaveData", "set_Coins")]


def test_malformed_and_truncated_input_does_not_crash():
    for text in ("", "{", "}", "public class", "\tpublic ;\n", "// only comments\n",
                 "public class Broken {\n\tnot a member at all\n"):
        prog = parse_dump_text(text)
        assert isinstance(prog.classes, list)


def test_fixture_dump_matches_fixture_classes(inputs):
    prog = parse_dump_text(inputs["dump"].read_text())
    summary = prog.summary()
    assert summary["classes"] == 7
    assert summary["addressed_methods"] > 20
    assert all(c.image for c in prog.classes)
