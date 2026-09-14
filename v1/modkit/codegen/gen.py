"""Emits the per-project sources: game.hpp / game.cpp / features.inc + build files.

Templates use {{token}} placeholders (never f-strings) so C++ braces stay literal.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from modkit.arch import arm64
from modkit.ir import Feature, FeatureKind, Plan, c_ident
from modkit.metadata.header import MAGIC
from modkit.ir import INT_C_TYPE

KIND_ENUM = {
    FeatureKind.TOGGLE: "F_TOGGLE",
    FeatureKind.SLIDER: "F_SLIDER",
    FeatureKind.VALUE_SET: "F_VALUE_SET",
    FeatureKind.FIELD_WRITE: "F_FIELD_WRITE",
    FeatureKind.STATIC_WRITE: "F_STATIC_WRITE",
    FeatureKind.CONST_RETURN: "F_CONST_RETURN",
    FeatureKind.HOOK: "F_HOOK",
    FeatureKind.ACTION: "F_ACTION",
}

WIDTH_BY_TYPE = {
    "System.Boolean": 1, "System.Byte": 1, "System.SByte": 1,
    "System.Int16": 2, "System.UInt16": 2, "System.Char": 2,
    "System.Int32": 4, "System.UInt32": 4, "System.Single": 4,
    "System.Int64": 8, "System.UInt64": 8, "System.Double": 8,
    "bool": 1, "byte": 1, "char": 2, "short": 2, "ushort": 2,
    "int": 4, "uint": 4, "float": 4, "long": 8, "ulong": 8, "double": 8,
}


def fmt_num(v: float) -> str:
    try:
        v = float(v)
    except (TypeError, ValueError):
        return "0.0"
    if v == int(v) and abs(v) < 1e15:
        return f"{int(v)}.0"
    return f"{v:.6g}"


def c_type(il2cpp_type: str | None) -> str:
    if not il2cpp_type:
        return "void"
    t = il2cpp_type.strip()
    if t in INT_C_TYPE:
        return INT_C_TYPE[t]
    if t in ("System.Void", "void"):
        return "void"
    if t in ("System.String", "System.Object", "System.Type") or t.endswith("_array"):
        return "void*"
    if re.search(r"[._]Vector[234]$", t):
        return "float"
    return "void*" if "." in t else "int32_t"


def width_of(il2cpp_type: str | None) -> int:
    return WIDTH_BY_TYPE.get((il2cpp_type or "").strip(), 4)


def jni_mangle(pkg: str) -> str:
    return pkg.replace("_", "_1").replace(".", "_")


def fill(template: str, **kw) -> str:
    for k, v in kw.items():
        template = template.replace("{{" + k + "}}", str(v))
    return re.sub(r"\{\{[a-z_]+\}\}", "", template)



# Gradle/AGP knobs and the ignore list live here rather than in templates: they are
# static text, and CI relies on gradle.properties for the JVM heap used by the NDK build.
GRADLE_PROPERTIES = (
    "org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8\n"
    "org.gradle.parallel=true\n"
    "android.useAndroidX=false\n"
    "android.nonTransitiveRClass=true\n"
)

PROJECT_GITIGNORE = (
    "*.iml\n.idea/\n.gradle/\nlocal.properties\nbuild/\n.cxx/\n"
    "app/build/\napp/.cxx/\n*.apk\n*.aab\n"
)

class Generator:
    """`files()` returns {relative path: content}; nothing touches disk here."""

    def __init__(self, plan: Plan, *, package: str, app_name: str, abi: str = "arm64-v8a",
                 overlay: bool = True, dobby: bool = False, imgui: bool = False, autoload: bool = False):
        self.plan = plan
        self.package = package
        self.app_name = re.sub(r"[^A-Za-z0-9_]", "", app_name) or "modmenu"
        self.abi = abi
        self.overlay = overlay
        self.dobby = dobby
        self.imgui = imgui
        self.autoload = autoload

    # ------------------------------------------------------------------ api

    def files(self) -> dict[str, str]:
        from modkit.codegen import runtime_src as rt
        out = {
            "app/src/main/cpp/game.hpp": self.game_hpp(),
            "app/src/main/cpp/game.cpp": self.game_cpp(),
            "app/src/main/cpp/features.inc": self.features_inc(),
            "app/src/main/cpp/CMakeLists.txt": self.cmake(),
            "app/src/main/modkit/build.json": self.build_json(),
            "app/src/main/modkit/features.json": self.features_json(),
            "app/src/main/modkit/patch_plan.json": self.patch_plan_json(),
            "app/src/main/modkit/README-BUILD.md": self.readme(),
            "app/src/main/assets/modkit.properties": self.properties(),
            "app/src/main/java/__PKGPATH__/loader/ModKit.java": self.modkit_java(),
            "app/src/main/java/__PKGPATH__/loader/LoaderActivity.java": self.loader_java(),
            "app/src/main/AndroidManifest.xml": self.manifest(),
            "app/src/main/res/mipmap-anydpi/ic_launcher.xml": self.launcher_icon(),
            "app/src/main/res/mipmap-anydpi/ic_launcher_round.xml": self.launcher_icon(),
            "app/build.gradle": self.gradle(),
            "build.gradle": self.root_gradle(),
            "settings.gradle": self.settings_gradle(),
            "gradle.properties": GRADLE_PROPERTIES,
            ".gitignore": PROJECT_GITIGNORE,
            "build.sh": self.build_sh(),
        }
        for path, content in list(out.items()):
            if "__PKGPATH__" in path:
                out[path.replace("__PKGPATH__", self.package.replace(".", "/"))] = content
                del out[path]
        for path, content in {
            "app/src/main/cpp/modkit.hpp": rt.MODKIT_HPP,
            "app/src/main/cpp/modkit.cpp": rt.MODKIT_CPP,
            "app/src/main/cpp/jni_main.cpp": rt.JNI_MAIN.replace("###PKG_JNI###", jni_mangle(self.package + ".loader")),
            "app/src/main/cpp/overlay.hpp": rt.OVERLAY_HPP,
            "app/src/main/cpp/overlay.cpp": rt.OVERLAY_CPP,
        }.items():
            out[path] = content
        return dict(sorted(out.items()))

    # ------------------------------------------------------------------ offsets

    def offset_block(self) -> str:
        lines = ["namespace off {  // one constant per addressable managed member"]
        seen: set[str] = set()
        for f in self.plan.features:
            if not f.rva or f.kind is FeatureKind.FIELD_WRITE:
                continue      # an instance offset is not an address; don't name it as one
            name = f"{c_ident(f.cls.split('.')[-1])}_{c_ident(f.member)}"
            if name in seen:
                continue
            seen.add(name)
            lines.append(f"    constexpr uint32_t {name} = 0x{f.rva:x};  // {f.key}")
        for h in self.plan.instance_hooks:
            name = f"{c_ident(h.cls.split('.')[-1])}_{c_ident(h.method)}"
            if name not in seen:
                seen.add(name)
                lines.append(f"    constexpr uint32_t {name} = 0x{h.rva:x};  // instance capture")
        if not seen:
            lines.append("    // no addressable members: the dump had no RVAs")
        lines.append("}  // namespace off")
        return "\n".join(lines)

    def game_hpp(self) -> str:
        from modkit.codegen import templates as T
        return fill(T.GAME_HPP, app_name=self.app_name, package=self.package, abi=self.abi,
                    count=len(self.plan.features))

    def features_inc(self) -> str:
        out = ["// AUTO-GENERATED feature table, included by game.cpp.", "// clang-format off", ""]
        patches: list[tuple[str, str]] = []
        for i, f in enumerate(self.plan.features):
            if f.patch:
                patches.append((f"patch_{i}", ", ".join(f"0x{b:02x}" for b in f.patch.bytes)))
        for name, body in patches:
            out.append(f"static const uint8_t {name}[] = {{{body}}};")
        if patches:
            out.append("")
        out.append("static const modkit::FeatureDef g_features[game::kFeatureCount == 0 ? 1"
                   " : game::kFeatureCount] = {")
        out.append("  // id, key, label, group, kind, flags, slot, rva, off, width, def, lo, hi, patch")
        for i, f in enumerate(self.plan.features):
            flags = []
            if f.needs_instance:
                flags.append("modkit::F_NEEDS_INSTANCE")
            if f.is_static:
                flags.append("modkit::F_IS_STATIC")
            if f.enabled_by_default:
                flags.append("modkit::F_DEFAULT_ON")
            flag_str = "|".join(flags) if flags else "modkit::F_NONE"
            slot = self._slot_for(f)
            rva = f"0x{f.rva:x}" if f.rva else "0"
            off = f"0x{f.field_offset:x}" if f.field_offset else "-1"
            wtype = f.c_type if f.kind is FeatureKind.CONST_RETURN else (f.arg_type or f.c_type)
            value = f.value
            d = 1.0 if value is True else (0.0 if value is False else float(value))
            patch = f"patch_{i}, {len(f.patch.bytes)}" if f.patch else "nullptr, 0"
            out.append('  {%d, "%s", "%s", "%s", modkit::%s, %s, %d, %s, %s, %d, %s, %s, %s, %s},'
                       % (i, f.id, f.label, f.group, KIND_ENUM[f.kind], flag_str, slot, rva, off,
                          width_of(wtype), fmt_num(d), fmt_num(f.min_value), fmt_num(f.max_value),
                          patch))
        out.append("};")
        out.append("")
        out.append("static modkit::HookDef g_capture_hooks[] = {")
        for h in self.plan.instance_hooks:
            out.append('  {0x%x, 0, (void *)&rep_%s, (void **)&g_orig_%s, "capture %s.%s"},'
                       % (h.rva, h.slot_name, h.slot_name, h.cls, h.method))
        if not self.plan.instance_hooks:
            out.append("  {0, 0, nullptr, nullptr, nullptr},")
        out.append("};")
        out.append("")
        out.append("static modkit::HookDef g_feature_hooks[] = {")
        # an empty array is ill-formed in C++, so an inert slot keeps it valid when the
        # plan has no hookable method (count is what matters, not the array size)
        hook_rows = ['  {0x%x, 0, (void *)&hk_%d, (void **)&g_hk%d_orig, "%s"},'
                     % (f.rva, i, i, f.key)
                     for i, f in enumerate(self.plan.features)
                     if f.kind is FeatureKind.HOOK and f.rva]
        out.extend(hook_rows or ["  {0, 0, nullptr, nullptr, nullptr},"])
        out.append("};")
        out.append("// clang-format on")
        return "\n".join(out) + "\n"

    def _slot_for(self, f: Feature) -> int:
        if not f.needs_instance:
            return -1
        for i, h in enumerate(self.plan.instance_hooks):
            if h.cls == f.cls:
                return i
        return -1

    # ------------------------------------------------------------------ game.cpp

    def game_cpp(self) -> str:
        L: list[str] = []
        add = L.append
        add("// ---------------------------------------------------------------------------")
        add(f"//  AUTO-GENERATED by modkit for {self.app_name}. Regenerate, do not hand-edit;")
        add("//  custom callbacks belong in a separate TU that includes game.hpp.")
        add("// ---------------------------------------------------------------------------")
        add('#include "game.hpp"')
        add("")
        add("#include <atomic>")
        add("#include <cmath>")
        add("#include <cstdio>")
        add("#include <cstring>")
        add("#include <cstdlib>")
        add("#include <mutex>")
        add("")
        add("#if MODKIT_HAS_IMGUI")
        add('#include "imgui.h"')
        add("#endif")
        add("")
        add("namespace game {")
        add("namespace {")
        add(f"constexpr size_t kN = {len(self.plan.features)};")
        add("double g_value[kN == 0 ? 1 : kN];")
        add("bool g_on[kN == 0 ? 1 : kN];")
        add(f"uint8_t g_saved[kN == 0 ? 1 : kN][{arm64.align_up(24, 4)}];")
        add("bool g_saved_ok[kN == 0 ? 1 : kN];")
        add("bool g_installed = false;")
        add("")
        for h in self.plan.instance_hooks:
            add(f"void *g_orig_{h.slot_name} = nullptr;")
        for i, f in enumerate(self.plan.features):
            if f.kind is FeatureKind.HOOK:
                add(f"void *g_hk{i}_orig = nullptr;")
        if not self.plan.instance_hooks:
            add("// (no instance capture hooks: every feature is static or patch-only)")
        add("}  // namespace")
        add("")
        add("// the tables in features.inc name these, and the callbacks below name the tables,")
        add("// so both sides need a declaration first")
        for h in self.plan.instance_hooks:
            add(f"static void {h.slot_name.replace('inst_', 'rep_inst_')}(void *_this);")
        for i, f in enumerate(self.plan.features):
            if f.kind is FeatureKind.HOOK and f.rva:
                r, d, _n = self.hook_signature(f)
                add(f"static {r} hk_{i}({', '.join(d)});")
        add("")
        add('#include "features.inc"')
        add("")
        add(self.offset_block())
        add("")

        for i, h in enumerate(self.plan.instance_hooks):
            add(f"// ---- instance capture: {h.cls}.{h.method} @ rva 0x{h.rva:x}")
            add("static void rep_%s(void *_this) {" % h.slot_name)
            add(f"    modkit::set_instance({i}, _this);")
            add(f"    if (auto fn = reinterpret_cast<void (*)(void *)>(g_orig_{h.slot_name})) fn(_this);")
            add("}")
            add("")

        for i, f in enumerate(self.plan.features):
            if f.kind is not FeatureKind.HOOK:
                continue
            ret, decls, names = self.hook_signature(f)
            call = ", ".join(names)
            add(f"// ---- hook feature {f.key} ({'swallow' if f.swallow else 'observe-only'})")
            add(f"using Fn_hk_{i} = {ret} (*)({', '.join(decls)});")
            add(f"static Fn_hk_{i} g_hk{i}_fn = reinterpret_cast<Fn_hk_{i}>(g_hk{i}_orig);")
            add(f"static {ret} hk_{i}({', '.join(decls)}) {{")
            add(f'    LOGD("%s hit", g_features[{i}].key);')
            add(f"    if (g_on[{i}]) {{")
            if f.swallow:
                add(f"        {'return;' if ret == 'void' else f'return ({ret})0;'}"
                    "  // swallow: the body is skipped while the feature is on")
            else:
                add("        // observe-only: record here, then fall through to the original")
            add("    }")
            if ret == "void":
                add(f"    if (g_hk{i}_fn) g_hk{i}_fn({call});")
            else:
                add(f"    if (!g_hk{i}_fn) return ({ret})0;")
                add(f"    return g_hk{i}_fn({call});")
            add("}")
            add("")

        add("void apply(size_t index, double value) {")
        if not self.plan.features:
            add("    (void)index; (void)value;")
        else:
            add("    if (index >= kN) return;")
            add("    g_value[index] = value;")
            add("    const bool on = value != 0.0;")
            add("    g_on[index] = on;")
            add("    switch (index) {")
            for i, f in enumerate(self.plan.features):
                add(f"    case {i}: {{  // [{f.kind.value}] {f.label}")
                for line in self._apply_case(f, i):
                    add("        " + line)
                add("        break;")
                add("    }")
            add("    default: break;")
            add("    }")
        add("}")
        add("")
        add("size_t feature_count() { return kN; }")
        add("const modkit::FeatureDef *features() { return g_features; }")
        add('const char *feature_key(size_t i) { return i < kN ? g_features[i].key : ""; }')
        add("double peek_feature(size_t i) { return i < kN ? g_value[i] : 0.0; }")
        add("void set_feature(size_t i, double v) { apply(i, v); }")
        add("")
        add("bool set_feature_by_key(const char *key, double value) {")
        add("    if (!key) return false;")
        add("    for (size_t i = 0; i < kN; ++i)")
        add('        if (!strcmp(g_features[i].key, key)) { apply(i, value); return true; }')
        add('    LOGW("unknown feature key: %s", key);')
        add("    return false;")
        add("}")
        add("")
        add("double get_feature_by_key(const char *key) {")
        add("    for (size_t i = 0; i < kN; ++i)")
        add("        if (!strcmp(g_features[i].key, key)) return g_value[i];")
        add("    return 0.0;")
        add("}")
        add("")
        add("static char g_status[256];")
        add("const char *status_line() {")
        add('    snprintf(g_status, sizeof(g_status), "base=%p n=%zu on=%zu%s",')
        add("             reinterpret_cast<void *>(modkit::self().base), kN,")
        add("             static_cast<size_t>(std::count(g_on, g_on + kN, true)),")
        add("             modkit::self().found() ? \"\" : \" (module unmapped!)\");")
        add("    return g_status;")
        add("}")
        add("")
        add("static const char *kConfigPaths[] = {")
        add(f'    "/sdcard/Android/data/{self.package}/files/modkit.properties",')
        add('    "/data/local/tmp/modkit.properties",')
        add("};")
        add("")
        add("void load_defaults() {")
        add("    for (const char *path : kConfigPaths) {")
        add('        FILE *fp = fopen(path, "re");')
        add("        if (!fp) continue;")
        add("        char line[256];")
        add("        while (fgets(line, sizeof(line), fp)) {")
        add("            char *eq = strchr(line, '=');")
        add("            if (!eq) continue;")
        add("            *eq = 0;")
        add("            char *key = line;")
        add("            while (*key == ' ' || *key == '\\t') ++key;")
        add("            if (*key == '#' || !*key) continue;")
        add("            const double v = strtod(eq + 1, nullptr);")
        add("            for (size_t i = 0; i < kN; ++i) {")
        add('                if (!strcmp(g_features[i].key, key)) {')
        add("                    g_value[i] = v;")
        add("                    g_on[i] = v != 0.0;")
        add("                    break;")
        add("                }")
        add("            }")
        add("        }")
        add("        fclose(fp);")
        add('        LOGI("defaults loaded from %s", path);')
        add("        return;")
        add("    }")
        add("}")
        add("")
        add("void install() {")
        add("    if (g_installed) return;")
        add("    g_installed = true;")
        add("    for (size_t i = 0; i < kN; ++i) {")
        add("        g_value[i] = g_features[i].def;")
        add("        g_on[i] = (g_features[i].flags & modkit::F_DEFAULT_ON) != 0;")
        add("    }")
        add("    load_defaults();")
        add(f'    LOGI("install: {len(self.plan.features)} features, '
            f'{len(self.plan.instance_hooks)} capture hooks, target {self.plan.program.so_name}");')
        add(f"    modkit::install_hooks(g_capture_hooks, {len(self.plan.instance_hooks)});")
        add(f"    modkit::install_hooks(g_feature_hooks, {self._feature_hook_count()});")
        add("    for (size_t i = 0; i < kN; ++i)")
        add("        if (g_on[i]) apply(i, g_value[i]);")
        add("}")
        add("")
        add(self.ui_block())
        add("")
        add("}  // namespace game")
        add("")
        add("// bridge for modkit's own runtime thread (it must not include game.hpp earlier)")
        add('extern "C" void game_install() { game::install(); }')
        return "\n".join(L) + "\n"

    def hook_signature(self, f: Feature) -> tuple[str, list[str], list[str]]:
        """Native prototype of a managed method: `this` in x0, args in x1..

        The arguments already sit in x0-x7 when the hook runs, so forwarding them
        verbatim keeps the original prologue happy without re-marshalling.
        """
        ret = c_type(f.c_type) or "void"
        decls: list[str] = []
        names: list[str] = []
        if not f.is_static:
            decls.append("void *_this")
            names.append("_this")
        for k, t in enumerate(f.arg_c_types):
            decls.append(f"{t} a{k}")
            names.append(f"a{k}")
        if not decls:
            decls.append("void *unused")
            names.append("nullptr")
        return ret, decls, names

    def _feature_hook_count(self) -> int:
        return sum(1 for f in self.plan.features if f.kind is FeatureKind.HOOK and f.rva)

    def _apply_case(self, f: Feature, i: int) -> list[str]:
        slot = self._slot_for(f)
        rva = f"0x{f.rva:x}" if f.rva else "0"
        ctype = c_type(f.arg_type or f.c_type)
        inst_call = f"({ctype})value"
        lines: list[str] = []
        if f.needs_instance:
            lines += [f"auto *_this = static_cast<char *>(modkit::instance({slot}));",
                      'if (!_this) { LOGW("%s: no captured instance", g_features[index].key); break; }']
        arg = "_this, " if f.needs_instance else ""

        if f.kind in (FeatureKind.VALUE_SET, FeatureKind.SLIDER):
            lines += [f"using Fn = void (*)({('void*, ' if f.needs_instance else '')}{ctype});",
                      f"if (auto fn = MODKIT_FN(Fn, {rva})) fn({arg}{inst_call});",
                      f'LOGI("{f.key} -> %g", value);']
        elif f.kind is FeatureKind.TOGGLE:
            lines += [f"using Fn = void (*)({('void*, ' if f.needs_instance else '')}bool);",
                      f"if (auto fn = MODKIT_FN(Fn, {rva})) fn({arg}on);"]
        elif f.kind is FeatureKind.FIELD_WRITE:
            lines += [f"{ctype} v = ({ctype})value;",
                      f"modkit::write_data(reinterpret_cast<uintptr_t>(_this) + 0x{f.field_offset:x}, "
                      f"&v, {width_of(f.arg_type)});"]
        elif f.kind is FeatureKind.STATIC_WRITE:
            lines += [f"{ctype} v = ({ctype})value;",
                      f"modkit::write_data(modkit::rva({rva}), &v, {width_of(f.arg_type)});"]
        elif f.kind is FeatureKind.CONST_RETURN:
            n = len(f.patch.bytes) if f.patch else 16
            lines += [f"if (!g_saved_ok[index]) {{",
                      f"    memcpy(g_saved[index], reinterpret_cast<void *>(modkit::rva({rva})), {n});",
                      "    g_saved_ok[index] = true;",
                      "}",
                      f"const uint8_t *dst = on ? g_features[index].patch : g_saved[index];",
                      f"if (on && !dst) dst = nullptr;",
                      f"if (dst) modkit::patch_memory(modkit::rva({rva}), dst, {n});",
                      f'LOGI("{f.key}: %s", on ? "patched" : "restored");']
        elif f.kind is FeatureKind.ACTION:
            lines += [f"using Fn = void (*)({('void*' if f.needs_instance else '')});",
                      f"if (auto fn = MODKIT_FN(Fn, {rva})) fn({('_this' if f.needs_instance else '')});"]
        elif f.kind is FeatureKind.HOOK:
            lines += [f"// callback hk_{i} is installed once; g_on[{i}] gates its body",
                      f'LOGI("{f.key}: %s", on ? "armed" : "pass-through");']
        else:
            lines += [f'LOGI("{f.key}: nothing wired");']
        return lines

    def ui_block(self) -> str:
        from modkit.codegen import templates as T
        return T.UI_BLOCK.strip()

    # ------------------------------------------------------------------ build files

    def cmake(self) -> str:
        from modkit.codegen import templates as T
        return fill(T.CMAKE, project=self.app_name.lower(), target_so=self.plan.program.so_name,
                    overlay="ON" if self.overlay else "OFF",
                    imgui="ON" if self.imgui else "OFF",
                    dobby="ON" if self.dobby else "OFF",
                    autoload="ON" if self.autoload else "OFF",
                    tag=self.app_name)

    def build_json(self) -> str:
        return json.dumps({
            "generator": "modkit",
            "app_name": self.app_name,
            "package": self.package,
            "abi": self.abi,
            "target_so": self.plan.program.so_name,
            "metadata_magic": f"0x{MAGIC[:4].hex()}",
            "metadata_version": self.plan.program.metadata_version,
            "overlay": self.overlay,
            "imgui": self.imgui,
            "dobby": self.dobby,
            "autoload": self.autoload,
            "features": len(self.plan.features),
            "instance_hooks": len(self.plan.instance_hooks),
            "dump_source": self.plan.program.source,
        }, indent=2) + "\n"

    def features_json(self) -> str:
        return self.plan.to_json(target_package=self.package, abi=self.abi,
                                 overlay=self.overlay, dobby=self.dobby)

    def patch_plan_json(self) -> str:
        items = [{"feature": f.id, "rva": f"0x{f.rva:x}", "length": len(f.patch.bytes),
                  "bytes": f.patch.bytes.hex(), "note": f.patch.note}
                 for f in self.plan.features if f.patch and f.rva]
        return json.dumps({
            "module": self.plan.program.so_name,
            "abi": self.abi,
            "arch": "arm64",
            "applied_by": "modkit::patch_memory at runtime, or `modkit apply` offline",
            "patches": items,
        }, indent=2) + "\n"

    def properties(self) -> str:
        lines = [f"# modkit defaults for {self.app_name}",
                 "# key = value   (0/1 for toggles and locks, numbers for setters)"]
        for f in self.plan.features:
            v = 1.0 if f.value is True else (0.0 if f.value is False else float(f.value))
            lines.append(f"{f.id} = {fmt_num(v)}   # [{f.kind.value}] {f.label}")
        return "\n".join(lines) + "\n"

    def gradle(self) -> str:
        from modkit.codegen import templates as T
        return fill(T.APP_GRADLE, package=self.package, app=self.app_name.lower(), abi=self.abi,
                    overlay="ON" if self.overlay else "OFF", autoload="ON" if self.autoload else "OFF")

    def root_gradle(self) -> str:
        from modkit.codegen import templates as T
        return T.ROOT_GRADLE.strip() + "\n"

    def settings_gradle(self) -> str:
        from modkit.codegen import templates as T
        return fill(T.SETTINGS_GRADLE, app=self.app_name)

    def manifest(self) -> str:
        from modkit.codegen import templates as T
        return fill(T.MANIFEST, app=self.app_name)

    def launcher_icon(self) -> str:
        # Dependency-free vector icon so generated menus never ship with the
        # generic Android placeholder.  The source remains fully editable.
        return """<?xml version=\"1.0\" encoding=\"utf-8\"?>
<vector xmlns:android=\"http://schemas.android.com/apk/res/android\"
    android:width=\"48dp\" android:height=\"48dp\"
    android:viewportWidth=\"48\" android:viewportHeight=\"48\">
    <path android:fillColor=\"#172033\" android:pathData=\"M4,4h40v40h-40z\"/>
    <path android:fillColor=\"#FFFFFF\" android:pathData=\"M11,13h6l7,9 7,-9h6v22h-6v-13l-7,9 -7,-9v13h-6z\"/>
</vector>
"""

    def modkit_java(self) -> str:
        from modkit.codegen import templates as T
        return fill(T.MODKIT_JAVA, package=self.package, lib=self.app_name.lower())

    def loader_java(self) -> str:
        from modkit.codegen import templates as T
        keys = "\n".join(f'        "{f.id}",' for f in self.plan.features) or '        // no features'
        return fill(T.LOADER_JAVA, package=self.package, lib=self.app_name.lower(), keys=keys)

    def build_sh(self) -> str:
        from modkit.codegen import templates as T
        return fill(T.BUILD_SH, lib=self.app_name.lower())

    def readme(self) -> str:
        rows = [f"| {f.group} | {f.label} | {f.kind.value} | {f.cls}.{f.member} | "
                f"{hex(f.rva) if f.rva else '—'} | {f.confidence:.2f} |" for f in self.plan.features]
        notes = [f"- {n}" for n in self.plan.notes] or ["- none"]
        from modkit.codegen import templates as T
        return fill(T.README, app=self.app_name, package=self.package, abi=self.abi,
                    lib=self.app_name.lower(), so=self.plan.program.so_name,
                    version=self.plan.program.metadata_version, source=self.plan.program.source,
                    nfeat=len(self.plan.features), nhooks=len(self.plan.instance_hooks),
                    rows="\n".join(rows) or "| — | no features matched — extend the rules json | | | | |",
                    notes="\n".join(notes), classes=self.plan.program.summary()["classes"],
                    methods=self.plan.program.summary()["methods"])
