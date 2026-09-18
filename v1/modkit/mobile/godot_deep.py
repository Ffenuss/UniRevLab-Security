"""Embedded Godot artifact/scene correlator.

Text scenes/resources and GDScript are parsed into explicit graph evidence. Binary
PCK/resource formats are only header-profiled unless their structure is proven;
the engine never invents source from binary packs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-godot-deep-1.0"
ENGINE_ID = "godot.deep-embedded"
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 1500

NODE_RE = re.compile(r'^\[node\s+([^\]]+)\]$', re.M)
EXT_RE = re.compile(r'^\[ext_resource\s+([^\]]+)\]$', re.M)
SUB_RE = re.compile(r'^\[sub_resource\s+([^\]]+)\]$', re.M)
ATTR_RE = re.compile(r'(\w+)="([^"]*)"|(\w+)=([^\s]+)')
FUNC_RE = re.compile(r'^\s*func\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)', re.M)
SIGNAL_RE = re.compile(r'^\s*signal\s+([A-Za-z_][\w]*)', re.M)
CLASS_RE = re.compile(r'^\s*class_name\s+([A-Za-z_][\w]*)', re.M)
EXTENDS_RE = re.compile(r'^\s*extends\s+([^\r\n#]+)', re.M)
SEMANTIC = (
    "health", "damage", "attack", "mana", "stamina", "energy", "currency",
    "coin", "gold", "gem", "level", "experience", "inventory", "speed",
    "cooldown", "player", "character", "battle", "weapon", "ammo", "armor",
)


class GodotScanCancelled(RuntimeError):
    pass


def _check(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise GodotScanCancelled("godot scan cancelled")


def _workspace_apks(root: Path) -> list[Path]:
    paths: list[Path] = []
    target = root / "installed-target.json"
    if target.is_file():
        try:
            obj = json.loads(target.read_text(encoding="utf-8"))
            for row in obj.get("splits", []) if isinstance(obj, dict) else []:
                if isinstance(row, dict):
                    p = Path(str(row.get("path") or ""))
                    if p.is_file() and p not in paths:
                        paths.append(p)
        except Exception:
            pass
    apk_dir = root / "installed-apks"
    if apk_dir.is_dir():
        for p in sorted(apk_dir.glob("*.apk")):
            if p not in paths:
                paths.append(p)
    game = root / "game.apk"
    if game.is_file() and game not in paths:
        paths.append(game)
    return paths


def _stable(prefix: str, *parts: str) -> str:
    return prefix + ":" + hashlib.sha256("!".join(parts).encode("utf-8", "replace")).hexdigest()[:20]


def _attrs(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in ATTR_RE.finditer(raw):
        if m.group(1):
            out[m.group(1)] = m.group(2)
        else:
            out[m.group(3)] = m.group(4)
    return out


def _domains(value: str) -> list[str]:
    low = value.casefold()
    return sorted({word for word in SEMANTIC if word in low})


def _scene_graph(text: str) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    ext: list[dict[str, Any]] = []
    sub: list[dict[str, Any]] = []
    for m in NODE_RE.finditer(text):
        attrs = _attrs(m.group(1))
        nodes.append({
            "name": attrs.get("name"),
            "type": attrs.get("type"),
            "parent": attrs.get("parent"),
            "instance": attrs.get("instance"),
        })
    for m in EXT_RE.finditer(text):
        attrs = _attrs(m.group(1))
        ext.append({
            "path": attrs.get("path"),
            "type": attrs.get("type"),
            "id": attrs.get("id"),
        })
    for m in SUB_RE.finditer(text):
        attrs = _attrs(m.group(1))
        sub.append({
            "type": attrs.get("type"),
            "id": attrs.get("id"),
        })
    return {"nodes": nodes, "externalResources": ext, "subResources": sub}


def _script_info(text: str) -> dict[str, Any]:
    funcs = [{"name": m.group(1), "args": m.group(2).strip()} for m in FUNC_RE.finditer(text)]
    signals = [m.group(1) for m in SIGNAL_RE.finditer(text)]
    cls = CLASS_RE.search(text)
    extends = EXTENDS_RE.search(text)
    return {
        "className": cls.group(1) if cls else None,
        "extends": extends.group(1).strip() if extends else None,
        "functions": funcs,
        "signals": signals,
    }


def _pck_header(data: bytes) -> dict[str, Any] | None:
    if len(data) < 20 or data[:4] != b"GDPC":
        return None
    try:
        pack_version, engine_major, engine_minor, engine_patch = struct.unpack_from("<IIII", data, 4)
    except struct.error:
        return None
    return {
        "magic": "GDPC",
        "packFormatVersion": int(pack_version),
        "engineVersion": {
            "major": int(engine_major),
            "minor": int(engine_minor),
            "patch": int(engine_patch),
        },
        "headerConfirmed": True,
    }


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scenes: list[dict[str, Any]] = []
    scripts: list[dict[str, Any]] = []
    packs: list[dict[str, Any]] = []
    apk_count = 0

    def add(row: dict[str, Any]) -> None:
        if len(findings) < MAX_FINDINGS:
            findings.append(row)

    for raw in paths:
        _check(cb)
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    _check(cb)
                    if info.is_dir() or info.file_size <= 0:
                        continue
                    low = info.filename.casefold()
                    suffix = Path(low).suffix
                    if suffix == ".pck":
                        try:
                            with zf.open(info, "r") as source:
                                data = source.read(256)
                        except Exception:
                            data = b""
                        header = _pck_header(data)
                        row = {
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                            "header": header,
                            "headerConfirmed": bool(header),
                        }
                        packs.append(row)
                        add({
                            "id": _stable("godot-pck", apk.name, info.filename),
                            "kind": "GODOT_PCK_CONTAINER",
                            "title": f"Godot PCK: {Path(info.filename).name}",
                            "category": "Runtime/Godot",
                            "status": "FOUND_STATIC" if header else "REVIEW",
                            "engineId": ENGINE_ID,
                            **row,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                            "evidenceRole": "godot-pck-header",
                        })
                        continue

                    if suffix not in {".gd", ".tscn", ".tres"}:
                        continue
                    if info.file_size > MAX_TEXT_BYTES:
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            data = source.read(MAX_TEXT_BYTES + 1)
                        text = data.decode("utf-8", "replace")
                    except Exception:
                        continue

                    if suffix == ".gd":
                        info_row = _script_info(text)
                        row = {
                            "apk": apk.name, "entry": info.filename,
                            "size": info.file_size, **info_row,
                        }
                        scripts.append(row)
                        add({
                            "id": _stable("godot-script", apk.name, info.filename),
                            "kind": "GODOT_GDSCRIPT",
                            "title": f"GDScript: {Path(info.filename).name}",
                            "category": "Runtime/Godot Script",
                            "status": "SCRIPT_CONTENT_SEARCH",
                            "engineId": ENGINE_ID,
                            **row,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                            "evidenceRole": "godot-gdscript-structure",
                        })
                        for fn in info_row["functions"]:
                            domains = _domains(str(fn["name"]))
                            if not domains:
                                continue
                            add({
                                "id": _stable("godot-semantic", apk.name, info.filename, str(fn["name"])),
                                "kind": "GODOT_SCRIPT_FUNCTION",
                                "title": str(fn["name"]),
                                "category": "Gameplay/Godot Script",
                                "status": "SCRIPT_CONTENT_SEARCH",
                                "engineId": ENGINE_ID,
                                "apk": apk.name, "entry": info.filename,
                                "function": fn["name"], "args": fn["args"],
                                "semanticDomains": domains,
                                "patchReady": False, "automationExcluded": True,
                                "runtimeConfirmed": False,
                                "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                                "evidenceRole": "godot-script-semantic",
                            })
                    else:
                        graph = _scene_graph(text)
                        row = {
                            "apk": apk.name, "entry": info.filename,
                            "size": info.file_size,
                            "sceneKind": "scene" if suffix == ".tscn" else "resource",
                            **graph,
                        }
                        scenes.append(row)
                        add({
                            "id": _stable("godot-scene", apk.name, info.filename),
                            "kind": "GODOT_TEXT_SCENE_GRAPH",
                            "title": Path(info.filename).name,
                            "category": "Runtime/Godot Scene",
                            "status": "CORRELATED_EVIDENCE",
                            "engineId": ENGINE_ID,
                            **row,
                            "nodeCount": len(graph["nodes"]),
                            "externalResourceCount": len(graph["externalResources"]),
                            "subResourceCount": len(graph["subResources"]),
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                            "evidenceRole": "godot-text-scene-graph",
                        })
                        for node in graph["nodes"]:
                            blob = " ".join(str(node.get(k) or "") for k in ("name", "type", "parent"))
                            domains = _domains(blob)
                            if not domains:
                                continue
                            add({
                                "id": _stable("godot-node", apk.name, info.filename, blob),
                                "kind": "GODOT_SCENE_NODE_SEMANTIC",
                                "title": str(node.get("name") or node.get("type") or "node"),
                                "category": "Gameplay/Godot Scene",
                                "status": "CORRELATED_EVIDENCE",
                                "engineId": ENGINE_ID,
                                "apk": apk.name, "entry": info.filename,
                                "node": node,
                                "semanticDomains": domains,
                                "patchReady": False, "automationExcluded": True,
                                "runtimeConfirmed": False,
                                "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                                "evidenceRole": "godot-scene-semantic",
                            })
        except GodotScanCancelled:
            raise
        except Exception:
            continue

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "packCount": len(packs),
        "sceneCount": len(scenes),
        "scriptCount": len(scripts),
        "findingCount": len(findings),
        "packs": packs,
        "scenes": scenes,
        "scripts": scripts,
        "findings": findings,
        "policy": {
            "claimsOriginalSourceFromPck": False,
            "binaryPckFileTableParsed": False,
            "encryptedPckBypass": False,
            "textSceneGraphAuthoritativeForTextInputOnly": True,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
