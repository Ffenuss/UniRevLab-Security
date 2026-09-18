from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class EngineKind(str, Enum):
    INVENTORY = "inventory"
    ANALYZER = "analyzer"
    DECODER = "decoder"
    DISASSEMBLER = "disassembler"
    DECOMPILER = "decompiler"
    RECONSTRUCTOR = "reconstructor"
    SEMANTIC = "semantic"
    SECURITY = "security"
    RUNTIME = "runtime"
    REPORTER = "reporter"


class EngineState(str, Enum):
    BUILTIN = "builtin"
    OPTIONAL = "optional-not-bundled"
    ENTRY_POINT = "entry-point"


class ArtifactKind(str, Enum):
    APK = "apk"
    APK_SET = "apk-set"
    MANIFEST = "manifest"
    RESOURCE = "resource"
    DEX = "dex"
    ELF = "elf"
    IL2CPP = "il2cpp"
    UNITY_ASSET = "unity-asset"
    FLUTTER = "flutter"
    HERMES = "hermes"
    LUA = "lua"
    JAVASCRIPT = "javascript"
    COCOS = "cocos"
    DOTNET = "dotnet"
    UNREAL = "unreal"
    GODOT = "godot"
    DEFOLD = "defold"
    QML = "qml"
    WEBASSEMBLY = "webassembly"
    PROCESS = "process"
    EVIDENCE = "evidence"


@dataclass(frozen=True)
class EngineDescriptor:
    engine_id: str
    name: str
    version: str
    kind: EngineKind
    artifacts: tuple[ArtifactKind, ...]
    state: EngineState
    implementation: str
    capabilities: tuple[str, ...] = ()
    fallback_for: tuple[str, ...] = ()
    priority: int = 100
    license_note: str = "internal"
    notes: str = ""
    safe_defaults: dict[str, Any] = field(default_factory=dict)

    @property
    def bundled(self) -> bool:
        return self.state == EngineState.BUILTIN

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["artifacts"] = [item.value for item in self.artifacts]
        data["state"] = self.state.value
        data["bundled"] = self.bundled
        return data
