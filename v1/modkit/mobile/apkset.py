from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import zipfile


_METADATA_MAGIC = 0xFAB11BAF
_EM_AARCH64 = 183


def _check(cb, message=None):
    if cb is None:
        return
    cancelled = getattr(cb, "isCancelled", None)
    if callable(cancelled) and cancelled():
        raise RuntimeError("Операция отменена")
    if message:
        progress = getattr(cb, "progress", None)
        if callable(progress):
            progress(message)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _split_abi(name: str) -> str | None:
    m = re.search(r"(?:^|/)lib/([^/]+)/libil2cpp\.so$", name, re.I)
    if m:
        return m.group(1)
    low = name.casefold()
    if "arm64" in low or "aarch64" in low:
        return "arm64-v8a"
    if "armeabi" in low or "armv7" in low:
        return "armeabi-v7a"
    if "x86_64" in low:
        return "x86_64"
    if re.search(r"(?:^|[/_.-])x86(?:[/_.-]|$)", low):
        return "x86"
    return None


def _entry_score_metadata(entry: str, split_index: int) -> int:
    low = entry.casefold()
    score = 20
    if low.endswith("assets/bin/data/managed/metadata/global-metadata.dat"):
        score += 100
    elif low.endswith("managed/metadata/global-metadata.dat"):
        score += 80
    elif low.endswith("global-metadata.dat"):
        score += 50
    if split_index == 0:
        score += 10
    return score


def _entry_score_library(entry: str, abi: str | None, split_index: int) -> int:
    low = entry.casefold()
    score = 10
    if abi == "arm64-v8a":
        score += 120
    elif abi == "armeabi-v7a":
        score += 30
    elif abi:
        score += 10
    if low == "lib/arm64-v8a/libil2cpp.so":
        score += 30
    if split_index == 0:
        score += 5
    return score


def _validate_metadata(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> dict:
    result = {"structuralValid": False, "magicValid": False, "version": None, "reason": "truncated-header"}
    try:
        with z.open(info) as stream:
            header = stream.read(8)
        if len(header) < 8:
            return result
        magic, version = struct.unpack_from("<II", header, 0)
        result["magicValid"] = magic == _METADATA_MAGIC
        result["version"] = version
        version_ok = 16 <= version <= 64
        result["versionPlausible"] = version_ok
        result["structuralValid"] = result["magicValid"] and version_ok and info.file_size >= 8
        result["reason"] = "ok" if result["structuralValid"] else ("bad-magic" if not result["magicValid"] else "implausible-version")
    except Exception as exc:
        result["reason"] = f"read-error:{type(exc).__name__}"
    return result


def _validate_library(z: zipfile.ZipFile, info: zipfile.ZipInfo, path_abi: str | None) -> dict:
    result = {
        "structuralValid": False,
        "elfValid": False,
        "elfClass": None,
        "machine": None,
        "pathAbi": path_abi,
        "reason": "truncated-header",
    }
    try:
        with z.open(info) as stream:
            header = stream.read(64)
        if len(header) < 20:
            return result
        result["elfValid"] = header[:4] == b"\x7fELF"
        if not result["elfValid"]:
            result["reason"] = "bad-elf-magic"
            return result
        result["elfClass"] = {1: "ELF32", 2: "ELF64"}.get(header[4], f"class-{header[4]}")
        little = header[5] == 1
        if not little:
            result["reason"] = "unsupported-endian"
            return result
        machine = struct.unpack_from("<H", header, 18)[0]
        result["machine"] = machine
        if path_abi == "arm64-v8a":
            result["machineMatchesPathAbi"] = machine == _EM_AARCH64 and header[4] == 2
        else:
            result["machineMatchesPathAbi"] = True
        result["structuralValid"] = bool(result["elfValid"] and result["machineMatchesPathAbi"] and info.file_size >= 20)
        result["reason"] = "ok" if result["structuralValid"] else "machine-abi-mismatch"
    except Exception as exc:
        result["reason"] = f"read-error:{type(exc).__name__}"
    return result


def _extract(apk_path: Path, entry: str, destination: str | os.PathLike, cb=None):
    dest = Path(destination)
    tmp = Path(str(dest) + ".tmp")
    try:
        with zipfile.ZipFile(apk_path) as z, z.open(entry) as src, tmp.open("wb") as out:
            while True:
                _check(cb)
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
        tmp.replace(dest)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def inspect_apk_paths(paths_json, metadata_out=None, library_out=None, report_out=None, cb=None, scan_trust=False):
    """Inspect one installed package represented by base.apk + split APK paths.

    The caller is responsible for obtaining/copying package paths. This function
    never mutates the source APKs. It independently locates metadata and native
    owners, validates the metadata/ELF headers before declaring a complete
    ARM64 IL2CPP pair, and records every split for later package-target builds.
    """
    paths = json.loads(paths_json) if isinstance(paths_json, str) else list(paths_json or [])
    paths = [Path(str(p)) for p in paths if p and Path(str(p)).is_file()]
    if not paths:
        raise ValueError("APK set пуст")

    report = {
        "schema": "modkit-installed-apk-set-1.1",
        "splits": [],
        "selected": {"metadata": None, "library": None},
        "availableAbis": [],
        "fullIl2cppPair": False,
        "pairConfidence": "NONE",
        "pairValidation": {},
        "mode": "split-discovery",
    }
    metadata_candidates = []
    library_candidates = []
    abis = set()
    dex_trust_rows = []
    dex_trust_errors = []

    for index, path in enumerate(paths):
        _check(cb, f"Installed scan: {index + 1}/{len(paths)} · {path.name}")
        row = {
            "index": index,
            "name": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
            "dexCount": 0,
            "nativeCount": 0,
            "metadataEntries": [],
            "il2cppEntries": [],
            "unityMarkers": 0,
            "cocosMarkers": 0,
            "luaEntries": 0,
            "jsEntries": 0,
            "contentMarkers": 0,
        }
        try:
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    name = info.filename
                    low = name.casefold()
                    if re.search(r"(?:^|/)classes\d*\.dex$", low):
                        row["dexCount"] += 1
                        if scan_trust and info.file_size <= 256 * 1024 * 1024:
                            try:
                                from modkit.reworkspace.trust import analyze_dex_trust
                                trust = analyze_dex_trust([(f"{path.name}!{name}", z.read(info))], max_methods_per_surface=32)
                                for surface, data in (trust.get("surfaces") or {}).items():
                                    for method in data.get("methods") or []:
                                        dex_trust_rows.append(method)
                                dex_trust_errors.extend(trust.get("errors") or [])
                            except Exception as exc:
                                dex_trust_errors.append({"artifact": f"{path.name}!{name}", "error": str(exc)})
                    if low.endswith(".so") and "/lib/" in "/" + low:
                        row["nativeCount"] += 1
                    if ("assets/bin/data/" in low or low.endswith("/libunity.so") or low.endswith("libunity.so")
                            or "globalgamemanagers" in low):
                        row["unityMarkers"] += 1
                    if ("streamingassets/" in low or "addressable" in low or low.endswith((".bundle", ".lua", ".luac", ".luae", ".js", ".jsc"))):
                        row["contentMarkers"] += 1
                    base = low.rsplit("/", 1)[-1]
                    if base in {"libcocos2dcpp.so", "libcocos.so", "libcocos2d.so"} or "jsb-adapter" in low or low.endswith((".csb", ".ccb")):
                        row["cocosMarkers"] += 1
                    if low.endswith((".lua", ".luac", ".luae")) or "liblua" in base or "xlua" in low or "slua" in low:
                        row["luaEntries"] += 1
                    if low.endswith((".js", ".jsc")) or "jsb-adapter" in low:
                        row["jsEntries"] += 1
                    if low.endswith("global-metadata.dat"):
                        validation = _validate_metadata(z, info)
                        item = {"splitIndex": index, "split": path.name, "entry": name,
                                "size": info.file_size, "score": _entry_score_metadata(name, index),
                                "validation": validation}
                        row["metadataEntries"].append(item)
                        metadata_candidates.append(item | {"apkPath": str(path)})
                    if low.endswith("libil2cpp.so"):
                        abi = _split_abi(name)
                        if abi:
                            abis.add(abi)
                        validation = _validate_library(z, info, abi)
                        item = {"splitIndex": index, "split": path.name, "entry": name, "abi": abi,
                                "size": info.file_size, "score": _entry_score_library(name, abi, index),
                                "validation": validation}
                        row["il2cppEntries"].append(item)
                        library_candidates.append(item | {"apkPath": str(path)})
        except zipfile.BadZipFile as exc:
            row["error"] = f"invalid-apk: {exc}"
        report["splits"].append(row)

    report["availableAbis"] = sorted(abis)
    valid_metadata = [x for x in metadata_candidates if (x.get("validation") or {}).get("structuralValid")]
    valid_arm64 = [x for x in library_candidates if x.get("abi") == "arm64-v8a" and (x.get("validation") or {}).get("structuralValid")]
    metadata = max(valid_metadata, key=lambda x: (x["score"], x["size"]), default=None)
    library = max(valid_arm64, key=lambda x: (x["score"], x["size"]), default=None)
    best_any_library = max(library_candidates, key=lambda x: (x["score"], x["size"]), default=None)

    if metadata:
        report["selected"]["metadata"] = {k: metadata.get(k) for k in ("splitIndex", "split", "entry", "size")}
        if metadata_out:
            _check(cb, f"Installed scan: извлечение global-metadata.dat из {metadata['split']}…")
            _extract(Path(metadata["apkPath"]), metadata["entry"], metadata_out, cb)
    if library:
        report["selected"]["library"] = {k: library.get(k) for k in ("splitIndex", "split", "entry", "abi", "size")}
        if library_out:
            _check(cb, f"Installed scan: извлечение ARM64 libil2cpp.so из {library['split']}…")
            _extract(Path(library["apkPath"]), library["entry"], library_out, cb)
    elif best_any_library:
        report["selected"]["unsupportedLibrary"] = {k: best_any_library.get(k) for k in ("splitIndex", "split", "entry", "abi", "size")}

    report["pairValidation"] = {
        "metadataValidCandidates": len(valid_metadata),
        "arm64ElfValidCandidates": len(valid_arm64),
        "metadataRejected": len(metadata_candidates) - len(valid_metadata),
        "libraryRejected": len([x for x in library_candidates if x.get("abi") == "arm64-v8a"]) - len(valid_arm64),
    }
    report["fullIl2cppPair"] = bool(metadata and library)
    report["pairConfidence"] = "HIGH" if report["fullIl2cppPair"] else "NONE"
    report["mode"] = "il2cpp-auto" if report["fullIl2cppPair"] else "split-discovery"
    total_unity = sum(int(r.get("unityMarkers", 0)) for r in report["splits"])
    total_cocos = sum(int(r.get("cocosMarkers", 0)) for r in report["splits"])
    total_lua = sum(int(r.get("luaEntries", 0)) for r in report["splits"])
    total_js = sum(int(r.get("jsEntries", 0)) for r in report["splits"])
    detected = []
    if report["fullIl2cppPair"]: detected.append("unity-il2cpp")
    elif total_unity: detected.append("unity")
    if total_cocos:
        detected.append("cocos-creator" if total_js else "cocos2d-x")
    if total_lua: detected.append("lua-runtime")
    if total_js: detected.append("javascript-runtime")
    if sum(int(r.get("dexCount", 0)) for r in report["splits"]): detected.append("android-dex")
    if sum(int(r.get("nativeCount", 0)) for r in report["splits"]): detected.append("native-elf")
    report["engineDetection"] = {"detected": detected, "unityMarkers": total_unity, "cocosMarkers": total_cocos, "luaEntries": total_lua, "jsEntries": total_js}
    if scan_trust:
        from modkit.reworkspace.trust import SURFACE_NAMES
        surfaces = {}
        for surface in SURFACE_NAMES:
            rows = [x for x in dex_trust_rows if x.get("surface") == surface]
            rows.sort(key=lambda x: (
                x.get("evidenceRole") == "application/bundled-sdk",
                x.get("trustBoundary") == "server-backed",
                float(x.get("behaviorConfidence", 0.0)),
                len(x.get("directInvokes") or []),
            ), reverse=True)
            app = [x for x in rows if x.get("evidenceRole") == "application/bundled-sdk"]
            boundaries = [str(x.get("trustBoundary") or "unknown") for x in app]
            boundary = ("server-backed" if "server-backed" in boundaries else
                        "platform-backed" if "platform-backed" in boundaries else
                        "local" if "local" in boundaries else "unknown")
            surfaces[surface] = {
                "methods": rows[:120], "totalMatches": len(rows), "applicationMatches": len(app),
                "trustBoundaries": sorted({str(x.get("trustBoundary", "unknown")) for x in rows}),
                "presenceConfidence": round(max((float(x.get("presenceConfidence", 0.0)) for x in rows), default=0.0), 2),
                "behaviorConfidence": round(max((float(x.get("behaviorConfidence", 0.0)) for x in rows), default=0.0), 2),
                "trustBoundary": boundary,
                "localAuthority": ("possible-local" if any(x.get("localAuthority") == "possible-local" for x in app) else
                                   "not-confirmed" if boundary in {"server-backed", "platform-backed"} and app else "unknown"),
            }
        report["dexTrust"] = {"schema": "modkit-dex-trust-2", "methodsScanned": len(dex_trust_rows),
                              "errors": dex_trust_errors[:80], "surfaceNames": SURFACE_NAMES, "surfaces": surfaces}
        from modkit.mobile.app_discovery import build_application_discovery
        report["applicationDiscovery"] = build_application_discovery(report)

    report["summary"] = {
        "splitCount": len(report["splits"]),
        "dexCount": sum(int(x.get("dexCount") or 0) for x in report["splits"]),
        "nativeCount": sum(int(x.get("nativeCount") or 0) for x in report["splits"]),
        "unityMarkerCount": sum(int(x.get("unityMarkers") or 0) for x in report["splits"]),
        "contentMarkerCount": sum(int(x.get("contentMarkers") or 0) for x in report["splits"]),
        "metadataCandidates": len(metadata_candidates),
        "metadataValidCandidates": len(valid_metadata),
        "il2cppCandidates": len(library_candidates),
        "arm64Il2cppCandidates": len([x for x in library_candidates if x.get("abi") == "arm64-v8a"]),
        "arm64ValidIl2cppCandidates": len(valid_arm64),
    }
    if report_out:
        Path(report_out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps(report, ensure_ascii=False, separators=(",", ":"))
