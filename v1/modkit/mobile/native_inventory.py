"""Architecture-neutral ELF inventory for Android APK/APK-set inputs.

This complements the deeper ARM64 backend. It parses only the standard ELF header,
so 32-bit ARM and x86 libraries remain visible and routable instead of disappearing.
"""
from __future__ import annotations

import json
from pathlib import Path
import struct
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-native-universal-inventory-1.0"
ENGINE_ID = "elf.universal-inventory"
MAX_ROWS = 4096

_MACHINE = {
    3: "x86",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
}
_ABI_ARCH = {
    "arm64-v8a": "aarch64",
    "armeabi-v7a": "arm",
    "x86": "x86",
    "x86_64": "x86_64",
}


class NativeInventoryCancelled(RuntimeError):
    pass


def _check(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise NativeInventoryCancelled("native inventory cancelled")


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


def _header(data: bytes) -> dict[str, Any] | None:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    elf_class = data[4]
    endian = data[5]
    if endian != 1 or elf_class not in {1, 2}:
        return {
            "bits": 32 if elf_class == 1 else 64 if elf_class == 2 else None,
            "endianness": "big" if endian == 2 else "unknown",
            "supportedHeader": False,
        }
    if elf_class == 1:
        if len(data) < 52:
            return None
        e_type, e_machine, _version, e_entry = struct.unpack_from("<HHII", data, 16)
        bits = 32
    else:
        if len(data) < 64:
            return None
        e_type, e_machine, _version, e_entry = struct.unpack_from("<HHIQ", data, 16)
        bits = 64
    return {
        "bits": bits,
        "endianness": "little",
        "supportedHeader": True,
        "elfType": int(e_type),
        "machine": int(e_machine),
        "arch": _MACHINE.get(int(e_machine), f"machine-{int(e_machine)}"),
        "entryPoint": int(e_entry),
        "dynamicOrPie": int(e_type) == 3,
    }


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    apk_count = 0
    arch_counts: dict[str, int] = {}
    abi_counts: dict[str, int] = {}
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
                    if len(findings) >= MAX_ROWS:
                        break
                    if info.is_dir() or info.file_size < 20:
                        continue
                    low = info.filename.casefold()
                    candidate = low.endswith(".so") or low.startswith("assets/")
                    if not candidate:
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            data = source.read(64)
                    except Exception:
                        continue
                    parsed = _header(data)
                    if not parsed:
                        continue
                    parts = info.filename.split("/")
                    abi = parts[1] if len(parts) >= 3 and parts[0] == "lib" else "asset"
                    arch = str(parsed.get("arch") or "unknown")
                    arch_counts[arch] = arch_counts.get(arch, 0) + 1
                    abi_counts[abi] = abi_counts.get(abi, 0) + 1
                    deep = arch == "aarch64" and int(parsed.get("bits") or 0) == 64
                    findings.append({
                        "id": f"elf-inventory:{apk.name}:{info.filename}",
                        "kind": "ELF_UNIVERSAL_INVENTORY",
                        "title": f"{arch} ELF: {Path(info.filename).name}",
                        "category": "Native/Inventory",
                        "status": "FOUND_STATIC",
                        "engineId": ENGINE_ID,
                        "apk": apk.name,
                        "entry": info.filename,
                        "size": int(info.file_size),
                        "abi": abi,
                        **parsed,
                        "pathAbiMatchesHeader": (
                            abi == "asset" or _ABI_ARCH.get(abi) is None or _ABI_ARCH.get(abi) == arch
                        ),
                        "deepBackend": "native.deep-embedded" if deep else None,
                        "deepAnalysisAvailable": deep,
                        "patchReady": False,
                        "automationExcluded": True,
                        "runtimeConfirmed": False,
                        "ownershipKind": "APP_OR_GAME",
                        "trustBoundary": "local",
                        "evidenceRole": "universal-elf-inventory",
                    })
        except NativeInventoryCancelled:
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
        "findingCount": len(findings),
        "archCounts": dict(sorted(arch_counts.items())),
        "abiCounts": dict(sorted(abi_counts.items())),
        "findings": findings,
        "truncated": len(findings) >= MAX_ROWS,
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
