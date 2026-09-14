from __future__ import annotations

from .base import ArtifactKind as A
from .base import EngineDescriptor as E
from .base import EngineKind as K
from .base import EngineState as S
from .registry import EngineRegistry


def build_default_registry() -> EngineRegistry:
    """Single source of truth for analysis/reconstruction entry points.

    Optional engines are visible to planners and UI but are never reported as available/bundled.
    This allows future integrations without hard-coding them into WorkerService or activities.
    """
    engines = [
        E("apkset.inventory", "APK / split inventory", "1.0", K.INVENTORY, (A.APK, A.APK_SET), S.BUILTIN,
          "modkit.mobile.apkset", ("split-aware", "sha256", "ownership"), priority=10),
        E("resources.decoder", "Android resources decoder", "1.0", K.DECODER, (A.MANIFEST, A.RESOURCE), S.BUILTIN,
          "modkit.mobile.engine:resource analysis", ("binary-xml", "arsc", "manifest", "resources"), priority=20),
        E("dex.structural", "DEX structural analyzer", "1.0", K.ANALYZER, (A.DEX,), S.BUILTIN,
          "modkit.reworkspace.dex", ("classes", "fields", "methods", "code-offsets", "xrefs"), priority=20),
        E("jadx.android", "JADX Android decompiler", "1.5.6", K.DECOMPILER, (A.APK, A.APK_SET, A.DEX, A.RESOURCE), S.BUILTIN,
          "android:dev.modkit.mobile.DecompilerEngine", ("java-view", "smali-view", "resources", "xrefs", "full-export"),
          fallback_for=("dex.structural",), priority=30, license_note="Apache-2.0",
          notes="Java-like output is a decompiler view; DEX/Smali remains authoritative when recovery fails."),
        E("elf.static", "ELF / ARM64 analyzer", "1.0", K.DISASSEMBLER, (A.ELF,), S.BUILTIN,
          "modkit.reworkspace.native", ("elf", "symbols", "strings", "arm64", "rva", "xrefs"), priority=20),
        E("il2cpp.rodroid", "Rodroid IL2CPP reconstructor", "7", K.RECONSTRUCTOR, (A.IL2CPP, A.ELF), S.BUILTIN,
          "android:dev.modkit.mobile.RodroidRunner", ("metadata", "types", "fields", "methods", "rva", "offsets"), priority=20),
        E("unity.discovery", "Unity / IL2CPP discovery", "1.0", K.ANALYZER, (A.APK, A.APK_SET, A.IL2CPP, A.UNITY_ASSET), S.BUILTIN,
          "modkit.mobile.unityscan", ("engine-detection", "metadata-pair", "addressables", "unity-assets"), priority=20),
        E("semantic.gameplay", "Gameplay semantic evidence", "1.0", K.SEMANTIC, (A.DEX, A.IL2CPP, A.ELF, A.RESOURCE), S.BUILTIN,
          "modkit.mobile.gameplay", ("ownership", "evidence-graph", "health", "damage", "currency", "movement"), priority=40),
        E("security.passive", "Passive security surface analyzer", "1.0", K.SECURITY, (A.APK, A.APK_SET, A.DEX, A.ELF, A.RESOURCE), S.BUILTIN,
          "modkit.mobile.security_scan", ("network", "tls", "crypto", "auth", "storage", "webview"), priority=40,
          safe_defaults={"active_network": False, "secret_extraction": False}),
        E("runtime.root-procfs", "Root procfs runtime session", "1.0", K.RUNTIME, (A.PROCESS,), S.BUILTIN,
          "android:dev.modkit.mobile.RootProcessEngine", ("root-probe", "process-list", "status", "maps", "threads", "modules"), priority=20,
          notes="Explicit user action; read-only runtime observation by default."),
        E("report.evidence-bundle", "Evidence Bundle exporter", "1.0", K.REPORTER, (A.EVIDENCE,), S.BUILTIN,
          "android:dev.modkit.mobile.EvidenceBundleExporter", ("json", "jsonl", "hashes", "toolchain", "runtime-snapshot"), priority=20),

        # Prepared entry points. They are intentionally not bundled or claimed as available.
        E("apktool.external", "Apktool decoder/rebuilder", "entry", K.DECODER, (A.APK, A.APK_SET, A.RESOURCE), S.ENTRY_POINT,
          "adapter:apktool", ("resources", "smali", "rebuild"), priority=60, license_note="Apache-2.0"),
        E("ghidra.external", "Ghidra native decompiler", "entry", K.DECOMPILER, (A.ELF,), S.ENTRY_POINT,
          "adapter:ghidra", ("native-pseudocode", "cfg", "xrefs"), priority=60, license_note="Apache-2.0"),
        E("rizin.external", "Rizin analysis backend", "entry", K.DISASSEMBLER, (A.ELF, A.DEX), S.ENTRY_POINT,
          "adapter:rizin", ("disassembly", "cfg", "xrefs"), priority=60),
        E("cpp2il.external", "Cpp2IL IL2CPP recovery", "entry", K.RECONSTRUCTOR, (A.IL2CPP,), S.ENTRY_POINT,
          "adapter:cpp2il", ("managed-il", "metadata", "cross-check"), priority=60),
        E("flutter.external", "Flutter / Dart AOT recovery", "entry", K.RECONSTRUCTOR, (A.FLUTTER, A.ELF), S.ENTRY_POINT,
          "adapter:flutter", ("dart-aot", "snapshot", "functions"), priority=60),
        E("hermes.external", "React Native Hermes decoder", "entry", K.DECOMPILER, (A.HERMES, A.JAVASCRIPT), S.ENTRY_POINT,
          "adapter:hermes", ("hbc", "disassembly", "javascript-view"), priority=60),
        E("lua.external", "Lua bytecode/source analyzer", "entry", K.DECOMPILER, (A.LUA,), S.ENTRY_POINT,
          "adapter:lua", ("lua-source", "bytecode", "strings"), priority=60),
        E("frida.external", "Frida runtime instrumentation", "entry", K.RUNTIME, (A.PROCESS,), S.OPTIONAL,
          "adapter:frida", ("attach", "modules", "method-trace", "native-trace"), priority=70,
          notes="Optional local runtime pack; never required for static analysis."),
        E("ptrace.external", "Native ptrace debugger", "entry", K.RUNTIME, (A.PROCESS,), S.ENTRY_POINT,
          "adapter:ptrace", ("attach", "registers", "breakpoints"), priority=70),
    ]
    return EngineRegistry(engines)
