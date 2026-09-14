"""Validate and apply a ModKit patch pack (DEX + native libraries) to an APK copy."""
from __future__ import annotations

from dataclasses import dataclass, asdict
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile
import zipfile

from modkit.elf.reader import ElfFile

_DEX_CLASS = re.compile(rb"L(?:[A-Za-z0-9_$]+/)+[A-Za-z0-9_$]+;")
ABI_BY_MACHINE = {183: "arm64-v8a", 62: "x86_64", 40: "armeabi-v7a", 3: "x86"}


@dataclass(slots=True)
class PackIssue:
    severity: str
    code: str
    message: str
    artifact: str = ""



def _sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()

def dex_classes(blob: bytes) -> set[str]:
    if not blob.startswith(b"dex\n"):
        return set()
    return {m.group().decode("ascii", "replace") for m in _DEX_CLASS.finditer(blob)}


def _classify_pack_name(name: str, blob: bytes) -> tuple[str, str] | None:
    base = Path(name).name
    if re.fullmatch(r"classes\d*\.dex", base, re.I) and blob.startswith(b"dex\n"):
        return "dex", base
    if base.lower().endswith(".so") and blob.startswith(b"\x7fELF"):
        try:
            elf = ElfFile(blob)
        except Exception:
            return "native", f"lib/unknown/{base}"
        abi = ABI_BY_MACHINE.get(elf.e_machine, f"machine-{elf.e_machine}")
        return "native", f"lib/{abi}/{base}"
    return None



def _aligned_extra(output_zip: zipfile.ZipFile, filename: str, alignment: int) -> bytes:
    """Pad a local ZIP header so the stored entry data begins at `alignment`."""
    position = output_zip.fp.tell()
    base = position + 30 + len(filename.encode("utf-8"))
    padding = (-base) % alignment
    if padding and padding < 4:
        padding += alignment
    return b"" if not padding else struct.pack("<HH", 0xCAFE, padding - 4) + bytes(padding - 4)




def _workspace_manifest(z: zipfile.ZipFile) -> tuple[dict | None, list[PackIssue]]:
    """Parse a generic file-workspace replacement manifest.

    This deliberately supports only explicit APK entry replacements/additions. It
    does not infer paths from arbitrary filenames.
    """
    name = "modkit-workspace.json"
    if name not in z.namelist():
        return None, []
    info = z.getinfo(name)
    if info.file_size > 512 * 1024:
        return None, [PackIssue("BLOCK", "WORKSPACE_MANIFEST_TOO_LARGE", "modkit-workspace.json exceeds 512 KiB", name)]
    try:
        data = json.loads(z.read(info).decode("utf-8"))
    except Exception as exc:
        return None, [PackIssue("BLOCK", "WORKSPACE_MANIFEST_INVALID", f"invalid JSON: {exc}", name)]
    if not isinstance(data, dict) or data.get("schema") != "modkit-workspace-patch-1.0":
        return None, [PackIssue("BLOCK", "WORKSPACE_SCHEMA_UNSUPPORTED", "expected schema modkit-workspace-patch-1.0", name)]
    entries = data.get("entries")
    if not isinstance(entries, list) or len(entries) > 4096:
        return None, [PackIssue("BLOCK", "WORKSPACE_ENTRIES_INVALID", "entries must be a list with at most 4096 rows", name)]
    return data, []


def _workspace_mappings(manifest: dict | None, z: zipfile.ZipFile, source_names: set[str]) -> tuple[list[dict], list[PackIssue]]:
    if not manifest:
        return [], []
    mappings: list[dict] = []
    issues: list[PackIssue] = []
    for i, row in enumerate(manifest.get("entries", [])):
        if not isinstance(row, dict):
            issues.append(PackIssue("BLOCK", "WORKSPACE_ENTRY_INVALID", f"entries[{i}] must be an object", "modkit-workspace.json")); continue
        pack = str(row.get("packPath") or "")
        target = str(row.get("targetPath") or "").replace("\\", "/")
        if not pack or pack not in z.namelist():
            issues.append(PackIssue("BLOCK", "WORKSPACE_PAYLOAD_MISSING", f"payload member is missing: {pack!r}", pack)); continue
        if (not target or target.startswith("/") or ".." in Path(target).parts or "\x00" in target
                or target.upper().startswith("META-INF/")):
            issues.append(PackIssue("BLOCK", "WORKSPACE_TARGET_INVALID", f"unsafe APK target path: {target!r}", target)); continue
        info = z.getinfo(pack)
        if info.file_size > 512 * 1024 * 1024:
            issues.append(PackIssue("BLOCK", "WORKSPACE_PAYLOAD_TOO_LARGE", f"{pack} exceeds 512 MiB", pack)); continue
        blob = z.read(info)
        operation = "replace" if target in source_names else "add"
        if operation == "add" and not target.startswith(("assets/", "res/raw/")):
            issues.append(PackIssue("BLOCK", "WORKSPACE_ADD_PATH_BLOCKED", "new generic files may only be added under assets/ or res/raw/", target)); continue
        if target in {"AndroidManifest.xml", "resources.arsc"}:
            issues.append(PackIssue("WARN", "WORKSPACE_STRUCTURAL_RESOURCE", f"editing {target} can invalidate resource references; build will preserve ZIP storage/alignment but cannot prove semantic validity", target))
        mappings.append({
            "packPath": pack, "targetPath": target, "kind": "workspace", "operation": operation,
            "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest(),
        })
    return mappings, issues


def _payload_manifest(z: zipfile.ZipFile) -> tuple[dict | None, list[PackIssue]]:
    name = 'modkit-payload.json'
    if name not in z.namelist():
        return None, []
    info = z.getinfo(name)
    if info.file_size > 256 * 1024:
        return None, [PackIssue('BLOCK', 'PAYLOAD_MANIFEST_TOO_LARGE', 'modkit-payload.json exceeds 256 KiB', name)]
    try:
        data = json.loads(z.read(info).decode('utf-8'))
    except Exception as exc:
        return None, [PackIssue('BLOCK', 'PAYLOAD_MANIFEST_INVALID', f'invalid JSON: {exc}', name)]
    if not isinstance(data, dict) or data.get('schema') != 'modkit-payload-1.0':
        return None, [PackIssue('BLOCK', 'PAYLOAD_SCHEMA_UNSUPPORTED', 'expected schema modkit-payload-1.0', name)]
    autoload = data.get('autoload', [])
    if not isinstance(autoload, list) or len(autoload) > 16:
        return None, [PackIssue('BLOCK', 'PAYLOAD_AUTOLOAD_INVALID', 'autoload must be a list with at most 16 entries', name)]
    return data, []


def _validate_payload_integrity(manifest: dict | None, z: zipfile.ZipFile, source_apk: Path) -> list[PackIssue]:
    """Verify payload hashes recorded by Menu Builder before any mapping is trusted.

    Older hand-authored payload manifests remain compatible: a digest is enforced
    only when the corresponding field is present.  Menu Builder-generated packs
    include all of these fields.
    """
    if not manifest:
        return []
    issues: list[PackIssue] = []

    expected_source = manifest.get('sourceApkSha256')
    if expected_source is not None:
        actual_source = _sha256_file(source_apk)
        if not isinstance(expected_source, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', expected_source):
            issues.append(PackIssue('BLOCK', 'PAYLOAD_SOURCE_HASH_INVALID', 'sourceApkSha256 must be a 64-character SHA-256 hex digest', 'modkit-payload.json'))
        elif actual_source.lower() != expected_source.lower():
            issues.append(PackIssue('BLOCK', 'PAYLOAD_SOURCE_MISMATCH', f'payload was generated for source APK {expected_source.lower()}, got {actual_source}', str(source_apk)))

    abi = str(manifest.get('abi', 'arm64-v8a'))
    runtime = manifest.get('runtime')
    runtime_hash = manifest.get('runtimeSha256')
    if runtime_hash is not None:
        if not isinstance(runtime, str) or not re.fullmatch(r'lib[^/\\\x00]+\.so', runtime):
            issues.append(PackIssue('BLOCK', 'PAYLOAD_RUNTIME_INVALID', 'runtime must name a plain lib*.so when runtimeSha256 is present', 'modkit-payload.json'))
        else:
            runtime_path = f'lib/{abi}/{runtime}'
            if runtime_path not in z.namelist():
                issues.append(PackIssue('BLOCK', 'PAYLOAD_RUNTIME_MISSING', f'{runtime_path} is missing from the payload', runtime_path))
            else:
                actual = _sha256_bytes(z.read(runtime_path))
                if not isinstance(runtime_hash, str) or actual.lower() != runtime_hash.lower():
                    issues.append(PackIssue('BLOCK', 'PAYLOAD_RUNTIME_HASH_MISMATCH', f'{runtime_path} SHA-256 does not match modkit-payload.json', runtime_path))

    for field, member, code in (
        ('menuSpecSha256', 'MENU-SPEC.json', 'PAYLOAD_MENU_SPEC_HASH_MISMATCH'),
        ('bindingValidationSha256', 'binding-validation.json', 'PAYLOAD_BINDING_VALIDATION_HASH_MISMATCH'),
    ):
        expected = manifest.get(field)
        if expected is None:
            continue
        if member not in z.namelist():
            issues.append(PackIssue('BLOCK', code.replace('_HASH_MISMATCH', '_MISSING'), f'{member} is missing from the payload', member))
            continue
        actual = _sha256_bytes(z.read(member))
        if not isinstance(expected, str) or actual.lower() != expected.lower():
            issues.append(PackIssue('BLOCK', code, f'{member} SHA-256 does not match modkit-payload.json', member))
    return issues


def _validate_autoload(manifest: dict | None, source_apk: Path, source_names: set[str],
                       mappings: list[dict], pack_blobs: dict[str, bytes]) -> tuple[list[dict], list[PackIssue]]:
    if not manifest:
        return [], []
    issues: list[PackIssue] = []
    out: list[dict] = []
    by_target = {m['targetPath']: m for m in mappings}
    with zipfile.ZipFile(source_apk) as src:
        for i, item in enumerate(manifest.get('autoload', [])):
            if not isinstance(item, dict):
                issues.append(PackIssue('BLOCK', 'AUTOLOAD_ENTRY_INVALID', f'autoload[{i}] must be an object', 'modkit-payload.json'))
                continue
            host = str(item.get('host', ''))
            dep = str(item.get('dependency', ''))
            if not re.fullmatch(r'lib/(arm64-v8a|x86_64)/[^/]+\.so', host):
                issues.append(PackIssue('BLOCK', 'AUTOLOAD_HOST_INVALID', f'invalid host path: {host!r}', 'modkit-payload.json'))
                continue
            if not re.fullmatch(r'lib[^/\\\x00]+\.so', dep):
                issues.append(PackIssue('BLOCK', 'AUTOLOAD_DEPENDENCY_INVALID', f'invalid dependency soname: {dep!r}', 'modkit-payload.json'))
                continue
            abi = host.split('/')[1]
            dep_target = f'lib/{abi}/{dep}'
            if dep_target not in by_target:
                issues.append(PackIssue('BLOCK', 'AUTOLOAD_DEPENDENCY_MISSING', f'{dep_target} is not present in the patch pack', dep))
                continue
            host_blob = pack_blobs.get(host)
            if host_blob is None:
                if host not in source_names:
                    issues.append(PackIssue('BLOCK', 'AUTOLOAD_HOST_MISSING', f'{host} is not present in the source APK or patch pack', host))
                    continue
                info = src.getinfo(host)
                if info.file_size > 512 * 1024 * 1024:
                    issues.append(PackIssue('BLOCK', 'AUTOLOAD_HOST_TOO_LARGE', f'{host} exceeds 512 MiB safety limit', host))
                    continue
                host_blob = src.read(info)
            try:
                elf = ElfFile(host_blob)
                strategy = str(item.get('strategy', 'add-only'))
                try:
                    edit = elf.add_needed(dep)
                except Exception as add_exc:
                    if strategy != 'safe-system-chain':
                        raise
                    runtime_blob = pack_blobs.get(dep_target)
                    if runtime_blob is None:
                        raise ValueError('runtime payload bytes are unavailable for chain validation') from add_exc
                    runtime_elf = ElfFile(runtime_blob)
                    edit = elf.replace_needed_chain(dep, runtime_needed=tuple(runtime_elf.needed()))
                    edit['addNeededFailure'] = str(add_exc)
                verified = ElfFile(elf.blob)
                if dep not in verified.needed():
                    raise ValueError('dependency did not appear in DT_NEEDED after edit')
                out.append({'host': host, 'dependency': dep, 'dependencyTarget': dep_target,
                            'requestedStrategy': strategy, 'edit': edit})
            except Exception as exc:
                issues.append(PackIssue('BLOCK', 'AUTOLOAD_NO_SAFE_SLACK', f'{host}: {exc}', host))
    return out, issues

def inspect_pack(source_apk: str | Path, patch_zip: str | Path) -> dict:
    source_apk, patch_zip = Path(source_apk), Path(patch_zip)
    issues: list[PackIssue] = []
    mappings: list[dict] = []
    with zipfile.ZipFile(source_apk) as z:
        source_infos = {info.filename: info for info in z.infolist()}
    source_names = set(source_infos)

    manifest = None
    workspace_manifest = None
    pack_blobs: dict[str, bytes] = {}
    payload_manifest_sha256 = None
    with zipfile.ZipFile(patch_zip) as z:
        manifest, manifest_issues = _payload_manifest(z)
        issues.extend(manifest_issues)
        workspace_manifest, workspace_issues = _workspace_manifest(z)
        issues.extend(workspace_issues)
        workspace_mappings, workspace_mapping_issues = _workspace_mappings(workspace_manifest, z, source_names)
        issues.extend(workspace_mapping_issues)
        mappings.extend(workspace_mappings)
        for m in workspace_mappings:
            pack_blobs[m["targetPath"]] = z.read(m["packPath"])
        if 'modkit-payload.json' in z.namelist():
            payload_manifest_sha256 = _sha256_bytes(z.read('modkit-payload.json'))
        issues.extend(_validate_payload_integrity(manifest, z, source_apk))
        workspace_pack_names = {m["packPath"] for m in workspace_mappings}
        for info in z.infolist():
            if info.filename in workspace_pack_names or info.filename == "modkit-workspace.json":
                continue
            if info.is_dir() or info.file_size > 512 * 1024 * 1024:
                continue
            blob = z.read(info)
            cls = _classify_pack_name(info.filename, blob)
            if cls is None:
                continue
            kind, target = cls
            # Preserve explicit lib/<abi>/ path when supplied and consistent.
            if kind == "native" and info.filename.startswith("lib/"):
                parts = Path(info.filename).parts
                if len(parts) >= 3:
                    target = "/".join(parts[-3:])
            mappings.append({
                "packPath": info.filename,
                "targetPath": target,
                "kind": kind,
                "size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
            })
            pack_blobs[target] = blob

            if kind == "dex" and target in source_names:
                src_info = source_infos[target]
                if src_info.file_size <= 512 * 1024 * 1024:
                    with zipfile.ZipFile(source_apk) as src:
                        old_classes = dex_classes(src.read(src_info))
                    new_classes = dex_classes(blob)
                    missing = sorted(old_classes - new_classes)
                    if missing:
                        issues.append(PackIssue(
                            "BLOCK", "DEX_CLASS_LOSS",
                            f"replacement {target} would remove {len(missing)} existing classes; first missing: {missing[:8]}",
                            info.filename,
                        ))
                else:
                    issues.append(PackIssue("BLOCK", "DEX_SOURCE_TOO_LARGE", f"{target} exceeds 512 MiB safety limit", target))
            if kind == "native":
                try:
                    elf = ElfFile(blob)
                    expected_abi = target.split("/")[1] if target.startswith("lib/") else ""
                    actual_abi = ABI_BY_MACHINE.get(elf.e_machine, f"machine-{elf.e_machine}")
                    if expected_abi and expected_abi != actual_abi:
                        issues.append(PackIssue("BLOCK", "ABI_MISMATCH", f"{target} expects {expected_abi}, ELF is {actual_abi}", info.filename))
                    available = {Path(k).name for k in source_names if k.startswith(f"lib/{actual_abi}/")}
                    available |= {Path(m["targetPath"]).name for m in mappings if m["targetPath"].startswith(f"lib/{actual_abi}/")}
                    system = {"libc.so", "libdl.so", "liblog.so", "libm.so", "libandroid.so", "libEGL.so", "libGLESv2.so", "libz.so"}
                    missing_needed = [n for n in elf.needed() if n not in available and n not in system]
                    if missing_needed:
                        issues.append(PackIssue("WARN", "MISSING_DT_NEEDED", f"dependencies not present in APK/pack: {missing_needed}", info.filename))
                except Exception as exc:
                    issues.append(PackIssue("BLOCK", "INVALID_ELF", str(exc), info.filename))

    autoload, autoload_issues = _validate_autoload(manifest, source_apk, source_names, mappings, pack_blobs)
    issues.extend(autoload_issues)

    targets = [m["targetPath"] for m in mappings]
    for target in sorted(set(targets)):
        if targets.count(target) > 1:
            issues.append(PackIssue("BLOCK", "DUPLICATE_TARGET", f"multiple pack files map to {target}", target))

    return {
        "schema": "modkit-patchpack-1.0",
        "sourceApkSha256": _sha256_file(source_apk),
        "patchPackSha256": _sha256_file(patch_zip),
        "mappings": mappings,
        "payloadManifest": manifest,
        "workspaceManifest": workspace_manifest,
        "payloadManifestSha256": payload_manifest_sha256,
        "autoload": autoload,
        "issues": [asdict(i) for i in issues],
        "blocked": any(i.severity == "BLOCK" for i in issues),
    }


def apply_pack(source_apk: str | Path, patch_zip: str | Path, output_apk: str | Path) -> dict:
    report = inspect_pack(source_apk, patch_zip)
    if report["blocked"]:
        raise ValueError("patch pack blocked by compatibility checks")

    replacements: dict[str, bytes] = {}
    with zipfile.ZipFile(patch_zip) as pz:
        by_pack = {m["packPath"]: m["targetPath"] for m in report["mappings"]}
        for pack_name, target in by_pack.items():
            replacements[target] = pz.read(pack_name)

    if report.get("autoload"):
        with zipfile.ZipFile(source_apk) as src:
            source_names = set(src.namelist())
            for item in report["autoload"]:
                host = item["host"]
                blob = replacements.get(host)
                if blob is None:
                    if host not in source_names:
                        raise ValueError(f"autoload host disappeared: {host}")
                    blob = src.read(host)
                elf = ElfFile(blob)
                planned = item.get("edit", {})
                if planned.get("strategy") == "needed-chain":
                    dep_blob = replacements.get(item["dependencyTarget"])
                    if dep_blob is None:
                        raise ValueError(f"autoload runtime disappeared: {item['dependencyTarget']}")
                    edit = elf.replace_needed_chain(item["dependency"], runtime_needed=tuple(ElfFile(dep_blob).needed()))
                else:
                    edit = elf.add_needed(item["dependency"])
                if item["dependency"] not in ElfFile(elf.blob).needed():
                    raise ValueError(f"autoload verification failed for {host}")
                replacements[host] = elf.blob
                item["appliedEdit"] = edit

    # Produce a deterministic, self-contained receipt before writing the output.
    # The final APK hash is returned outside the receipt to avoid a circular hash.
    with zipfile.ZipFile(source_apk) as src:
        source_names = set(src.namelist())
        modification_targets = set(replacements)
        modifications = []
        mapping_by_target = {m["targetPath"]: m for m in report.get("mappings", [])}
        autoload_hosts = {a["host"] for a in report.get("autoload", [])}
        for target in sorted(modification_targets):
            before = src.read(target) if target in source_names else None
            after = replacements[target]
            kind = mapping_by_target.get(target, {}).get("kind", "native-host" if target in autoload_hosts else "artifact")
            modifications.append({
                "targetPath": target,
                "kind": kind,
                "operation": "replace" if before is not None else "add",
                "beforeSha256": _sha256_bytes(before) if before is not None else None,
                "afterSha256": _sha256_bytes(after),
                "sizeBefore": len(before) if before is not None else 0,
                "sizeAfter": len(after),
            })

    receipt = {
        "schema": "modkit-patch-receipt-1.0",
        "sourceApkSha256": report["sourceApkSha256"],
        "patchPackSha256": report["patchPackSha256"],
        "payloadManifestSha256": report.get("payloadManifestSha256"),
        "modifications": modifications,
        "autoload": [{
            "host": a.get("host"),
            "dependency": a.get("dependency"),
            "requestedStrategy": a.get("requestedStrategy"),
            "edit": a.get("appliedEdit", a.get("edit")),
        } for a in report.get("autoload", [])],
        "alignment": {"storedSo": 16384, "otherStored": 4},
    }
    receipt_bytes = json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    receipt_path = "assets/modkit-patch-receipt.json"
    replacements[receipt_path] = receipt_bytes

    output_apk = Path(output_apk)
    with zipfile.ZipFile(source_apk) as zin, zipfile.ZipFile(output_apk, "w", allowZip64=True) as zout:
        seen = set()
        for info in zin.infolist():
            name = info.filename
            upper = name.upper()
            if upper.startswith("META-INF/") and upper.endswith((".RSA", ".DSA", ".EC", ".SF", "/MANIFEST.MF")):
                continue  # signatures must be regenerated after modifications
            zi = copy.copy(info)
            zi.extra = b""
            zi.flag_bits &= ~0x08
            if name in replacements:
                data = replacements[name]
                zi.compress_type = zipfile.ZIP_STORED if name.endswith(".so") else info.compress_type
                seen.add(name)
            else:
                data = zin.read(info)
            if zi.compress_type == zipfile.ZIP_STORED:
                zi.extra = _aligned_extra(zout, zi.filename, 16384 if name.endswith(".so") else 4)
            zout.writestr(zi, data)

        for name, data in replacements.items():
            if name in seen:
                continue
            zi = zipfile.ZipInfo(name)
            zi.compress_type = zipfile.ZIP_STORED if name.endswith(".so") else zipfile.ZIP_DEFLATED
            if zi.compress_type == zipfile.ZIP_STORED:
                zi.extra = _aligned_extra(zout, zi.filename, 16384 if name.endswith(".so") else 4)
            zout.writestr(zi, data)

    report["alignment"] = {"storedSo": 16384, "otherStored": 4}
    report["receipt"] = receipt
    report["receiptPath"] = receipt_path
    report["receiptSha256"] = _sha256_bytes(receipt_bytes)
    report["outputApkSha256"] = _sha256_file(output_apk)
    report["outputPath"] = str(output_apk)
    return report

