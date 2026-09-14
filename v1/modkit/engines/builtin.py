from __future__ import annotations

from .base import ArtifactKind as A
from .base import EngineDescriptor as E
from .base import EngineKind as K
from .base import EngineState as S
from .registry import EngineRegistry


def build_default_registry() -> EngineRegistry:
    """Single source of truth for built-in engines and external bridge contracts."""
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
        E("lua.static", "Lua / xLua / SLua analyzer", "1.0", K.DECOMPILER, (A.LUA,), S.BUILTIN,
          "modkit.mobile.artifact_families", ("source", "bytecode-header", "version", "function-index", "strings", "split-aware"), priority=25,
          notes="Plain Lua source is recoverable; compiled/encrypted chunks remain explicitly bytecode/opaque."),
        E("javascript.static", "JavaScript / React Native bundle analyzer", "1.0", K.DECOMPILER, (A.JAVASCRIPT,), S.BUILTIN,
          "modkit.mobile.artifact_families", ("source", "bundle", "function-index", "react-native-markers", "split-aware"), priority=25),
        E("hermes.static", "Hermes bytecode static analyzer", "1.0", K.DISASSEMBLER, (A.HERMES,), S.BUILTIN,
          "modkit.mobile.artifact_families", ("hbc-inventory", "strings", "bytecode-metadata", "split-aware"), priority=25,
          notes="Does not falsely claim original JavaScript recovery from HBC."),
        E("flutter.static", "Flutter / Dart AOT artifact analyzer", "1.0", K.RECONSTRUCTOR, (A.FLUTTER, A.ELF), S.BUILTIN,
          "modkit.mobile.artifact_families", ("flutter-assets", "snapshots", "libapp", "libflutter", "dart-aot", "native-correlation"), priority=25,
          notes="AOT/snapshot recovery level is reported honestly; original Dart source is not claimed."),
        E("cocos.static", "Cocos2d-x / Cocos Creator analyzer", "1.0", K.ANALYZER, (A.COCOS, A.JAVASCRIPT, A.ELF), S.BUILTIN,
          "modkit.mobile.artifact_families", ("engine-detection", "project-js", "jsc", "native-engine", "split-aware"), priority=25),
        E("semantic.gameplay", "Gameplay semantic evidence", "1.0", K.SEMANTIC, (A.DEX, A.IL2CPP, A.ELF, A.RESOURCE, A.LUA, A.JAVASCRIPT, A.COCOS), S.BUILTIN,
          "modkit.mobile.gameplay", ("ownership", "evidence-graph", "health", "damage", "currency", "movement"), priority=40),
        E("security.passive", "Passive security surface analyzer", "1.0", K.SECURITY, (A.APK, A.APK_SET, A.DEX, A.ELF, A.RESOURCE, A.LUA, A.JAVASCRIPT), S.BUILTIN,
          "modkit.mobile.security_scan", ("network", "tls", "crypto", "auth", "storage", "webview"), priority=40,
          safe_defaults={"active_network": False, "secret_extraction": False}),
        E("runtime.root-procfs", "Root procfs runtime session", "1.0", K.RUNTIME, (A.PROCESS,), S.BUILTIN,
          "android:dev.modkit.mobile.RootProcessEngine", ("root-probe", "process-list", "status", "maps", "threads", "modules"), priority=20,
          notes="Explicit user action; read-only runtime observation by default."),
        E("report.evidence-bundle", "Evidence Bundle exporter", "1.0", K.REPORTER, (A.EVIDENCE,), S.BUILTIN,
          "android:dev.modkit.mobile.EvidenceBundleExporter", ("json", "jsonl", "hashes", "toolchain", "runtime-snapshot"), priority=20),

        E("apktool.bridge", "Apktool import/export bridge", "1.0", K.DECODER, (A.APK, A.APK_SET, A.RESOURCE), S.ENTRY_POINT,
          "adapter:apktool", ("decoded-tree-import", "smali-import", "rebuild-output-import"), priority=60, license_note="Apache-2.0"),
        E("ghidra.bridge", "Ghidra native analysis bridge", "1.0", K.DECOMPILER, (A.ELF,), S.ENTRY_POINT,
          "adapter:ghidra", ("symbol-import", "pseudocode-import", "cfg-import", "xref-import", "evidence-export"), priority=60, license_note="Apache-2.0"),
        E("rizin.bridge", "Rizin analysis bridge", "1.0", K.DISASSEMBLER, (A.ELF, A.DEX), S.ENTRY_POINT,
          "adapter:rizin", ("disassembly-import", "cfg-import", "xref-import", "evidence-export"), priority=60),
        E("cpp2il.bridge", "Cpp2IL IL2CPP cross-check bridge", "1.0", K.RECONSTRUCTOR, (A.IL2CPP,), S.ENTRY_POINT,
          "adapter:cpp2il", ("managed-il-import", "metadata-import", "rodroid-cross-check"), priority=60),
        E("flutter.deep-bridge", "Deep Flutter/Dart recovery bridge", "1.0", K.RECONSTRUCTOR, (A.FLUTTER, A.ELF), S.ENTRY_POINT,
          "adapter:flutter-deep", ("symbol-map-import", "function-map-import", "snapshot-cross-check"), priority=60),
        E("hermes.deep-bridge", "Hermes deep decoder bridge", "1.0", K.DECOMPILER, (A.HERMES, A.JAVASCRIPT), S.ENTRY_POINT,
          "adapter:hermes-deep", ("hbc-disassembly-import", "function-map-import", "source-map-import"), priority=60),
        E("frida.local-bridge", "Frida local runtime bridge", "1.0", K.RUNTIME, (A.PROCESS,), S.OPTIONAL,
          "adapter:frida", ("server-detection", "attach-contract", "module-events", "trace-import"), priority=70,
          notes="Optional rooted local runtime pack; static analysis and root-procfs do not depend on it."),
        E("ptrace.bridge", "Native debugger/ptrace bridge", "1.0", K.RUNTIME, (A.PROCESS,), S.ENTRY_POINT,
          "adapter:ptrace", ("attach-contract", "register-snapshot-import", "breakpoint-evidence-import"), priority=70),

        # Compatibility IDs are retained so saved reports/automation from the pre-1.0 registry keep
        # resolving. They are aliases only and remain explicitly non-bundled.
        E("ghidra.external", "Ghidra external compatibility alias", "1.0", K.DECOMPILER, (A.ELF,), S.ENTRY_POINT,
          "compat-alias:ghidra.bridge", ("compatibility-alias",), priority=95, notes="Use ghidra.bridge for new integrations."),
        E("rizin.external", "Rizin external compatibility alias", "1.0", K.DISASSEMBLER, (A.ELF, A.DEX), S.ENTRY_POINT,
          "compat-alias:rizin.bridge", ("compatibility-alias",), priority=95, notes="Use rizin.bridge for new integrations."),
        E("frida.external", "Frida external compatibility alias", "1.0", K.RUNTIME, (A.PROCESS,), S.OPTIONAL,
          "compat-alias:frida.local-bridge", ("compatibility-alias",), priority=95, notes="Use frida.local-bridge for new integrations."),
        E("flutter.external", "Flutter external compatibility alias", "1.0", K.RECONSTRUCTOR, (A.FLUTTER, A.ELF), S.ENTRY_POINT,
          "compat-alias:flutter.deep-bridge", ("compatibility-alias",), priority=95, notes="Use flutter.deep-bridge for new integrations."),
        E("hermes.external", "Hermes external compatibility alias", "1.0", K.DECOMPILER, (A.HERMES, A.JAVASCRIPT), S.ENTRY_POINT,
          "compat-alias:hermes.deep-bridge", ("compatibility-alias",), priority=95, notes="Use hermes.deep-bridge for new integrations."),
    ]
    return EngineRegistry(engines)
