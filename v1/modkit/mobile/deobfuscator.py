"""Passive deobfuscation/protection profiler for Android release packages.

The engine does not pretend to recover names that are absent from a release APK.
It records reversible structure, stable aliases and protection/packing indicators,
so later analyzers can correlate evidence even when identifiers are minimized.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-deobfuscation-1.0"
ENGINE_ID = "protection.deobfuscator"
MAX_DEX_SAMPLE = 24 * 1024 * 1024
MAX_ASSET_SAMPLE = 256 * 1024
MAX_FINDINGS = 512
MAX_ALIASES = 512

_DESCRIPTOR_RE = re.compile(rb"L(?:[A-Za-z0-9_$]{1,64}/){1,24}[A-Za-z0-9_$]{1,96};")
_PACKER_MARKERS = (
    "secneo", "bangcle", "ijiami", "jiagu", "legu", "dexprotector", "dexguard",
    "libshell", "shell-super", "stubapp", "stubapplication",
)
_DYNAMIC_LOADER_MARKERS = (
    b"dalvik/system/DexClassLoader", b"dalvik/system/InMemoryDexClassLoader",
    b"dalvik/system/PathClassLoader", b"BaseDexClassLoader", b"loadDex",
)
_ANTI_DEBUG_MARKERS = (
    b"isDebuggerConnected", b"waitingForDebugger", b"TracerPid", b"/proc/self/status",
    b"ptrace", b"JDWP", b"android/os/Debug",
)
_TOOLING_MARKERS = (
    b"frida", b"xposed", b"substrate", b"magisk", b"zygisk", b"/system/xbin/su",
    b"/system/bin/su", b"ro.kernel.qemu", b"genymotion",
)
_INTEGRITY_MARKERS = (
    b"getApkContentsSigners", b"GET_SIGNING_CERTIFICATES", b"PlayIntegrity",
    b"play/core/integrity", b"SafetyNet", b"MessageDigest", b"SigningInfo",
)


class DeobfuscationCancelled(RuntimeError):
    pass


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    if callable(cb):
        return bool(cb())
    return False


def _check(cb: Any | None) -> None:
    if _cancelled(cb):
        raise DeobfuscationCancelled("deobfuscation scan cancelled")


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


def _read_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    with zf.open(info, "r") as source:
        return source.read(min(max(0, info.file_size), limit))


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    n = float(len(data))
    return -sum((count / n) * math.log2(count / n) for count in counts if count)


def _leaf(descriptor: str) -> str:
    body = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    return body.rsplit("/", 1)[-1]


def _suspicious_identifier(descriptor: str) -> bool:
    body = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    segments = [x for x in body.split("/") if x]
    if not segments:
        return False
    leaf = segments[-1].split("$", 1)[0]
    short_segments = sum(1 for x in segments if len(x) <= 2)
    return len(leaf) <= 2 or (len(segments) >= 3 and short_segments >= max(2, len(segments) // 2))


def _finding(fid: str, kind: str, title: str, category: str, evidence: dict[str, Any],
             *, confidence: str = "MEDIUM", status: str = "REVIEW") -> dict[str, Any]:
    return {
        "id": fid,
        "kind": kind,
        "title": title,
        "category": category,
        "status": status,
        "confidence": confidence,
        "engineId": ENGINE_ID,
        "evidence": evidence,
        "patchReady": False,
        "automationExcluded": True,
        "runtimeConfirmed": False,
        "ownershipKind": "ENGINE",
        "trustBoundary": "local",
        "evidenceRole": "deobfuscation-protection-profile",
    }


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    apk_count = 0
    dex_count = 0
    descriptors: set[str] = set()
    suspicious: set[str] = set()
    packer_hits: set[str] = set()
    dynamic_hits: set[str] = set()
    anti_debug_hits: set[str] = set()
    tooling_hits: set[str] = set()
    integrity_hits: set[str] = set()
    opaque_assets: list[dict[str, Any]] = []
    embedded_payloads: list[str] = []

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
                infos = zf.infolist()
                for info in infos:
                    _check(cb)
                    if info.is_dir() or info.file_size <= 0:
                        continue
                    low = info.filename.casefold()
                    base = low.rsplit("/", 1)[-1]

                    for marker in _PACKER_MARKERS:
                        if marker in low:
                            packer_hits.add(f"{apk.name}:{info.filename}:{marker}")

                    if low.startswith("assets/") and (
                        low.endswith((".dex", ".jar", ".apk", ".so"))
                        or base.startswith(("lib", "payload", "shell"))
                    ):
                        embedded_payloads.append(f"{apk.name}:{info.filename}")

                    if base.startswith("classes") and base.endswith(".dex"):
                        dex_count += 1
                        try:
                            data = _read_bounded(zf, info, MAX_DEX_SAMPLE)
                        except Exception:
                            continue
                        for raw_desc in _DESCRIPTOR_RE.findall(data):
                            try:
                                desc = raw_desc.decode("ascii")
                            except Exception:
                                continue
                            descriptors.add(desc)
                            if _suspicious_identifier(desc):
                                suspicious.add(desc)

                        lower = data.lower()
                        for marker in _DYNAMIC_LOADER_MARKERS:
                            if marker.lower() in lower:
                                dynamic_hits.add(f"{apk.name}:{info.filename}:{marker.decode('ascii', 'replace')}")
                        for marker in _ANTI_DEBUG_MARKERS:
                            if marker.lower() in lower:
                                anti_debug_hits.add(f"{apk.name}:{info.filename}:{marker.decode('ascii', 'replace')}")
                        for marker in _TOOLING_MARKERS:
                            if marker.lower() in lower:
                                tooling_hits.add(f"{apk.name}:{info.filename}:{marker.decode('ascii', 'replace')}")
                        for marker in _INTEGRITY_MARKERS:
                            if marker.lower() in lower:
                                integrity_hits.add(f"{apk.name}:{info.filename}:{marker.decode('ascii', 'replace')}")
                        for marker in _PACKER_MARKERS:
                            if marker.encode() in lower:
                                packer_hits.add(f"{apk.name}:{info.filename}:{marker}")

                    if low.startswith("assets/") and low.endswith((".bin", ".dat", ".blob", ".pack", ".enc")):
                        try:
                            data = _read_bounded(zf, info, MAX_ASSET_SAMPLE)
                        except Exception:
                            continue
                        if len(data) >= 4096:
                            entropy = _entropy(data)
                            printable = sum(1 for b in data if 0x20 <= b <= 0x7E) / len(data)
                            if entropy >= 7.6 and printable <= 0.45:
                                opaque_assets.append({
                                    "apk": apk.name, "entry": info.filename,
                                    "sampleBytes": len(data), "entropy": round(entropy, 3),
                                    "printableRatio": round(printable, 4),
                                })
        except DeobfuscationCancelled:
            raise
        except Exception:
            continue

    descriptor_count = len(descriptors)
    suspicious_ratio = (len(suspicious) / descriptor_count) if descriptor_count else 0.0
    if descriptor_count >= 20 and suspicious_ratio >= 0.30:
        confidence = "HIGH" if suspicious_ratio >= 0.55 and descriptor_count >= 50 else "MEDIUM"
        add(_finding(
            "deobf:identifier-minification",
            "IDENTIFIER_MINIFICATION_HEURISTIC",
            "Likely identifier minification / name obfuscation",
            "Protection/Obfuscation",
            {
                "descriptorCount": descriptor_count,
                "suspiciousDescriptorCount": len(suspicious),
                "suspiciousRatio": round(suspicious_ratio, 4),
                "examples": sorted(suspicious)[:32],
                "originalNamesRecoverable": False,
            },
            confidence=confidence,
        ))

    for desc in sorted(suspicious)[:MAX_ALIASES]:
        aliases.append({
            "originalDescriptor": desc,
            "stableAlias": "StructuralClass_" + hashlib.sha256(desc.encode()).hexdigest()[:10],
            "leaf": _leaf(desc),
            "reason": "short/minified identifier; alias preserves cross-report identity only",
            "semanticRecoveryClaimed": False,
        })

    if packer_hits:
        add(_finding(
            "deobf:packer-markers", "PACKER_OR_PROTECTOR_MARKERS",
            "Packer / protector markers detected", "Protection/Packing",
            {"markers": sorted(packer_hits)[:64]},
            confidence="HIGH" if len(packer_hits) >= 2 else "MEDIUM",
        ))
    if embedded_payloads:
        add(_finding(
            "deobf:embedded-payloads", "EMBEDDED_CODE_PAYLOAD",
            "Embedded executable/code payloads in assets", "Protection/Loading",
            {"entries": sorted(set(embedded_payloads))[:64]},
            confidence="MEDIUM",
        ))
    if dynamic_hits:
        add(_finding(
            "deobf:dynamic-loader", "DYNAMIC_CODE_LOADING",
            "Dynamic class/code loading markers", "Protection/Loading",
            {"markers": sorted(dynamic_hits)[:64]},
            confidence="HIGH",
            status="FOUND_STATIC",
        ))
    if anti_debug_hits:
        add(_finding(
            "deobf:anti-debug", "ANTI_DEBUG_MARKERS",
            "Anti-debug / debugger-detection markers", "Protection/Resilience",
            {"markers": sorted(anti_debug_hits)[:64]},
            confidence="MEDIUM",
        ))
    if tooling_hits:
        add(_finding(
            "deobf:tooling-detection", "TOOLING_ROOT_EMULATOR_MARKERS",
            "Root / instrumentation / emulator detection markers", "Protection/Resilience",
            {"markers": sorted(tooling_hits)[:64]},
            confidence="MEDIUM",
        ))
    if integrity_hits:
        add(_finding(
            "deobf:integrity", "INTEGRITY_SIGNATURE_MARKERS",
            "Package integrity / signature verification markers", "Protection/Integrity",
            {"markers": sorted(integrity_hits)[:64]},
            confidence="MEDIUM",
        ))
    if opaque_assets:
        add(_finding(
            "deobf:opaque-assets", "OPAQUE_HIGH_ENTROPY_ASSETS",
            "Opaque high-entropy assets require format/protector recovery", "Protection/Assets",
            {"assets": opaque_assets[:64], "encryptionConfirmed": False},
            confidence="LOW",
        ))

    recovery_plan: list[dict[str, Any]] = []
    if suspicious:
        recovery_plan.append({
            "stage": "identifier-normalization",
            "status": "AVAILABLE",
            "strategy": "stable structural aliases + call/xref/ownership correlation",
            "originalNameRecovery": "NOT_CLAIMED_WITHOUT_MAPPING",
        })
    if packer_hits or dynamic_hits or embedded_payloads:
        recovery_plan.append({
            "stage": "loader-unwrapping",
            "status": "REVIEW_REQUIRED",
            "strategy": "identify loader boundary and inventory statically delivered secondary code",
            "executesTargetCode": False,
        })
    if opaque_assets:
        recovery_plan.append({
            "stage": "asset-format-recovery",
            "status": "REVIEW_REQUIRED",
            "strategy": "identify container/codec/key derivation before claiming decryption",
            "encryptionConfirmed": False,
        })
    if not recovery_plan:
        recovery_plan.append({
            "stage": "generic-structure",
            "status": "NO_STRONG_OBFUSCATION_MARKERS",
            "strategy": "continue normal DEX/ELF/resource analysis",
        })

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "dexCount": dex_count,
        "descriptorCount": descriptor_count,
        "suspiciousDescriptorCount": len(suspicious),
        "suspiciousDescriptorRatio": round(suspicious_ratio, 4),
        "findingCount": len(findings),
        "findings": findings,
        "normalizedIdentifierCount": len(aliases),
        "normalizedIdentifiers": aliases,
        "recoveryPlan": recovery_plan,
        "policy": {
            "inventOriginalNames": False,
            "treatEntropyAsEncryptionProof": False,
            "executePackedPayloads": False,
            "patchReadyFromObfuscationEvidence": False,
        },
    }
    _check(cb)
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
