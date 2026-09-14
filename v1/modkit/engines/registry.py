from __future__ import annotations

import json
from collections import defaultdict
from typing import Iterable

from .base import ArtifactKind, EngineDescriptor, EngineKind


class EngineRegistry:
    """Deterministic registry used by UI, analysis planning and evidence exports."""

    def __init__(self, engines: Iterable[EngineDescriptor] = ()) -> None:
        self._engines: dict[str, EngineDescriptor] = {}
        for engine in engines:
            self.register(engine)

    def register(self, engine: EngineDescriptor) -> None:
        if engine.engine_id in self._engines:
            raise ValueError(f"duplicate engine id: {engine.engine_id}")
        self._engines[engine.engine_id] = engine

    def get(self, engine_id: str) -> EngineDescriptor:
        return self._engines[engine_id]

    def all(self) -> list[EngineDescriptor]:
        return sorted(self._engines.values(), key=lambda e: (e.priority, e.kind.value, e.engine_id))

    def for_kind(self, kind: EngineKind) -> list[EngineDescriptor]:
        return [engine for engine in self.all() if engine.kind == kind]

    def for_artifact(self, artifact: ArtifactKind) -> list[EngineDescriptor]:
        return [engine for engine in self.all() if artifact in engine.artifacts]

    def catalog(self) -> dict:
        engines = [engine.to_dict() for engine in self.all()]
        return {
            "schema": "modkit-engine-catalog-1.0",
            "count": len(engines),
            "bundled": sum(1 for e in engines if e["bundled"]),
            "optional": sum(1 for e in engines if not e["bundled"]),
            "engines": engines,
        }

    def catalog_json(self, indent: int = 2) -> str:
        return json.dumps(self.catalog(), ensure_ascii=False, indent=indent, sort_keys=True)

    def capability_matrix(self) -> dict[str, list[str]]:
        matrix: dict[str, set[str]] = defaultdict(set)
        for engine in self.all():
            for artifact in engine.artifacts:
                matrix[artifact.value].update(engine.capabilities)
        return {key: sorted(values) for key, values in sorted(matrix.items())}
