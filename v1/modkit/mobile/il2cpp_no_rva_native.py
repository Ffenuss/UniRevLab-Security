"""Recover exact native RVAs for IL2CPP catalogue rows which still have no RVA.

This backend targets one specific ambiguity in the primary resolver: multiple
structurally plausible Il2CppCodeGenModule records may reference the same image-name
string. The global metadata already tells us the exact MethodDef token domain for
that image. We therefore reject every candidate whose methodPointerCount does not
match that domain before deciding whether the module is ambiguous.

Every no-RVA catalogue row gets a streamed provenance row. Successful recovery is
emitted only when metadata identity, exact CodeGenModule selection, executable
pointer validation, and global pointer uniqueness all agree. Failure rows retain the
precise blocker but remain non-actionable/non-buildable.
"""
from __future__ import annotations

import bisect
import collections
import json
import re
import struct
from pathlib import Path
from typing import Any

from modkit.mobile.engine import Elf, Metadata, check

SCHEMA = "modkit-il2cpp-no-rva-native-1.0"
_SUCCESS = "NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE"


def _number(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return None
        try:
            return int(text, 16 if text.startswith("0x") else 10)
        except ValueError:
            return None
    return None


def _name(value: Any) -> str:
    text = str(value or "").strip()
    if "::" in text:
        text = text.rsplit("::", 1)[1]
    if "(" in text:
        text = text.split("(", 1)[0]
    return text.strip()


def _class(value: Any) -> str:
    return str(value or "").strip().replace("/", ".")


def _class_identity_match(catalog_class: Any, metadata_class: Any) -> bool:
    """Require the complete canonical declaring type, never a short-name fallback."""
    catalog = _class(catalog_class)
    metadata = _class(metadata_class)
    return bool(catalog and metadata and catalog == metadata)


def _catalog_identity(row: dict[str, Any]) -> tuple[int | None, int | None, str, str, str]:
    mid = _number(row.get("metadata_method_id"))
    if mid is None:
        mid = _number(row.get("metadataMethodId"))
    if mid is None:
        mid = _number(row.get("methodId"))
    if mid is None and row.get("catalog_schema") == "modkit-full-metadata-method-catalog-1.0":
        mid = _number(row.get("id"))

    token = _number(row.get("metadata_token"))
    if token is None:
        token = _number(row.get("metadataToken"))
    if token is None:
        token = _number(row.get("token"))

    image = str(row.get("image") or "").strip()
    cls = _class(row.get("class") or row.get("cls") or row.get("declaringType"))
    method = _name(row.get("name") or row.get("method") or row.get("methodName") or row.get("label"))
    return mid, token, image, cls, method


def _metadata_image_ranges(meta: Metadata) -> tuple[list[int], list[tuple[int, int, str]]]:
    starts: list[int] = []
    rows: list[tuple[int, int, str]] = []
    for pos in range(meta.images[0], sum(meta.images), 40):
        name_index, _assembly, first, count = meta.unpack("<IiII", pos)
        if not count:
            continue
        start = int(first)
        end = start + int(count)
        if start < 0 or end > meta.type_count:
            raise ValueError("metadata image type range is invalid")
        starts.append(start)
        rows.append((start, end, meta.string(name_index)))
    order = sorted(range(len(starts)), key=starts.__getitem__)
    return [starts[i] for i in order], [rows[i] for i in order]


def _image_for_type(type_index: int, starts: list[int], ranges: list[tuple[int, int, str]]) -> str:
    pos = bisect.bisect_right(starts, int(type_index)) - 1
    if pos < 0:
        return ""
    start, end, image = ranges[pos]
    return image if start <= int(type_index) < end else ""


def _metadata_token_domains(meta: Metadata, cb=None) -> tuple[dict[str, int], dict[str, int]]:
    counts: dict[str, int] = collections.defaultdict(int)
    max_rid: dict[str, int] = collections.defaultdict(int)
    for index, row in enumerate(meta.iter_rows(cb)):
        if index % 4096 == 0:
            check(cb)
        token = int(row.get("token") or 0)
        if token >> 24 != 6:
            continue
        rid = token & 0x00FFFFFF
        image = str(row.get("image") or "")
        if not image or rid <= 0:
            continue
        counts[image] += 1
        max_rid[image] = max(max_rid[image], rid)
    # Require a contiguous 1..N MethodDef token domain. If metadata itself has a
    # hole, count cannot safely discriminate a CodeGenModule.
    exact = {name: max_rid[name] for name in max_rid if counts.get(name) == max_rid[name]}
    rejected = {name: max_rid[name] for name in max_rid if counts.get(name) != max_rid[name]}
    return exact, rejected


def _resolve_modules_expected(elf: Elf, expected_counts: dict[str, int], cb=None) -> tuple[dict[str, tuple[int, int]], dict[str, Any]]:
    """Resolve CodeGenModule tables after exact MethodDef-count filtering."""
    names = sorted(name for name, count in expected_counts.items() if name and int(count) > 0)
    if not names:
        return {}, {"requested": 0, "resolved": 0, "ambiguous": 0, "noString": 0, "noCandidate": 0, "modules": {}}

    name_vas: dict[str, list[int]] = collections.defaultdict(list)
    wanted_vas: set[int] = set()
    matcher = re.compile(b"|".join(re.escape(name.encode("utf-8") + b"\0") for name in names))
    raw = memoryview(elf.b)
    try:
        for index, hit in enumerate(matcher.finditer(raw)):
            if index % 4096 == 0:
                check(cb)
            try:
                va = int(elf.virtual(hit.start()))
            except ValueError:
                continue
            value = bytes(hit.group(0)[:-1]).decode("utf-8", "strict")
            name_vas[value].append(va)
            wanted_vas.add(va)
    finally:
        raw.release()

    reloc_refs: dict[int, list[int]] = collections.defaultdict(list)
    if wanted_vas:
        for index, (off, value) in enumerate(elf.reloc.items()):
            if index % 65536 == 0:
                check(cb)
            if value in wanted_vas:
                reloc_refs[int(value)].append(int(off))

    out: dict[str, tuple[int, int]] = {}
    detail: dict[str, Any] = {}
    ambiguous = no_string = no_candidate = 0
    for index, name in enumerate(names):
        check(cb, f"No-RVA native recovery: CodeGenModule {index + 1}/{len(names)} — {name}")
        expected = int(expected_counts[name])
        candidates: set[tuple[int, int]] = set()
        vas = name_vas.get(name, [])
        if not vas:
            no_string += 1
        for va in vas:
            refs = set(reloc_refs.get(int(va), []))
            if not refs:
                refs.update(p for p in elf.finds(struct.pack("<Q", int(va))) if p % 8 == 0)
            for pointer_ref in refs:
                try:
                    count = int(elf.unpack("<Q", pointer_ref + 8)[0])
                    if count != expected:
                        continue
                    table = int(elf.offset(elf.ptr(pointer_ref + 16), count * 8))
                    sample_positions = sorted({0, max(0, count // 2), count - 1})
                    observed = 0
                    for sample_index in sample_positions:
                        address = int(elf.ptr(table + sample_index * 8) or 0)
                        if not address:
                            continue
                        elf.offset(address, 4, True)
                        observed += 1
                    if observed == 0:
                        continue
                    candidates.add((count, table))
                except (ValueError, struct.error):
                    continue
        if len(candidates) == 1:
            out[name] = next(iter(candidates))
            detail[name] = {"status": "EXACT_EXPECTED_METHOD_COUNT", "expectedMethodCount": expected, "candidateCount": 1}
        elif len(candidates) > 1:
            ambiguous += 1
            detail[name] = {"status": "AMBIGUOUS_AFTER_EXPECTED_COUNT", "expectedMethodCount": expected, "candidateCount": len(candidates)}
        else:
            no_candidate += 1
            detail[name] = {"status": "NO_EXACT_COUNT_CANDIDATE", "expectedMethodCount": expected, "candidateCount": 0}

    return out, {
        "requested": len(names),
        "resolved": len(out),
        "ambiguous": ambiguous,
        "noString": no_string,
        "noCandidate": no_candidate,
        "modules": detail,
    }


def _method_pointer(elf: Elf, module: tuple[int, int] | None, token: int) -> tuple[int | None, str]:
    if module is None:
        return None, "MODULE_UNRESOLVED"
    count, table = module
    rid = int(token) & 0x00FFFFFF
    if int(token) >> 24 != 6 or not 0 < rid <= int(count):
        return None, "TOKEN_OUT_OF_MODULE_RANGE"
    raw = int(elf.ptr(int(table) + (rid - 1) * 8) or 0)
    if raw <= 0:
        return None, "NULL_METHOD_POINTER"
    try:
        elf.offset(raw, 4, True)
    except ValueError:
        return None, "NON_EXECUTABLE_METHOD_POINTER"
    return raw, "EXECUTABLE_METHOD_POINTER"


def _unresolved_status(pointer_status: str) -> str:
    return {
        "MODULE_UNRESOLVED": "NATIVE_RVA_MODULE_UNRESOLVED",
        "TOKEN_OUT_OF_MODULE_RANGE": "NATIVE_RVA_TOKEN_OUT_OF_MODULE_RANGE",
        "NULL_METHOD_POINTER": "NATIVE_RVA_POINTER_ABSENT",
        "NON_EXECUTABLE_METHOD_POINTER": "NATIVE_RVA_NON_EXECUTABLE_POINTER",
    }.get(str(pointer_status or ""), "NATIVE_RVA_UNRESOLVED")


def _evidence(mid: int | None, token: int | None, image: str, cls: str, method: str,
              status: str, blockers: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": mid,
        "metadataMethodId": mid,
        "metadataToken": f"0x{int(token):08x}" if token is not None else None,
        "image": image or None,
        "class": cls or None,
        "methodName": method or None,
        "status": status,
        "blockers": list(blockers or []),
        "rva": None,
        "rvaHex": None,
        "addressConfirmed": False,
        "associationConfirmed": False,
        "uniqueExecutablePointer": False,
        "executesTargetCode": False,
        "writesTarget": False,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }
    row.update(extra)
    return row


def recover_no_rva(metadata_path: str | Path, library_path: str | Path, catalog_path: str | Path,
                   output_path: str | Path, rows_path: str | Path | None = None, cb=None) -> dict[str, Any]:
    metadata_path = Path(metadata_path)
    library_path = Path(library_path)
    catalog_path = Path(catalog_path)
    output_path = Path(output_path)
    rows_path = Path(rows_path) if rows_path else output_path.with_name("il2cpp-no-rva-native.methods.jsonl")
    if not metadata_path.is_file() or not library_path.is_file() or not catalog_path.is_file():
        raise ValueError("metadata.bin, library.so and analysis.methods.jsonl are required")

    meta = None
    elf = None
    try:
        meta = Metadata(metadata_path)
        starts, image_ranges = _metadata_image_ranges(meta)
        expected_counts, non_contiguous = _metadata_token_domains(meta, cb)
        elf = Elf(library_path, cb)
        modules, module_stats = _resolve_modules_expected(elf, expected_counts, cb)

        pointer_counts: collections.Counter[int] = collections.Counter()
        for index, row in enumerate(meta.iter_rows(cb)):
            if index % 4096 == 0:
                check(cb)
            pointer, status = _method_pointer(elf, modules.get(str(row.get("image") or "")), int(row.get("token") or 0))
            if pointer is not None and status == "EXECUTABLE_METHOD_POINTER":
                pointer_counts[int(pointer)] += 1

        counts = collections.Counter()
        status_counts = collections.Counter()
        samples: list[dict[str, Any]] = []
        failure_samples: list[dict[str, Any]] = []
        rows_path.parent.mkdir(parents=True, exist_ok=True)
        with catalog_path.open("r", encoding="utf-8", errors="replace") as source, rows_path.open("w", encoding="utf-8") as sink:
            def emit(row: dict[str, Any]) -> None:
                sink.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
                status_counts[str(row.get("status") or "NATIVE_RVA_UNRESOLVED")] += 1
                if row.get("status") == _SUCCESS:
                    if len(samples) < 64:
                        samples.append(row)
                elif len(failure_samples) < 64:
                    failure_samples.append(row)

            for line_no, line in enumerate(source):
                if line_no % 4096 == 0:
                    check(cb)
                if not line.strip():
                    continue
                try:
                    catalog = json.loads(line)
                except json.JSONDecodeError:
                    counts["malformedRows"] += 1
                    continue
                if not isinstance(catalog, dict):
                    continue
                counts["catalogRows"] += 1
                current_rva = _number(catalog.get("rva"))
                if current_rva is not None and current_rva > 0:
                    continue
                counts["rowsWithoutRva"] += 1
                mid, token, image, cls, method = _catalog_identity(catalog)
                if mid is None or token is None or mid < 0 or mid >= meta.method_count:
                    counts["identityUnavailable"] += 1
                    blockers = []
                    if mid is None or mid < 0 or mid >= meta.method_count:
                        blockers.append("metadata-method-id-unavailable")
                    if token is None:
                        blockers.append("metadata-token-unavailable")
                    emit(_evidence(mid, token, image, cls, method, "NATIVE_RVA_IDENTITY_UNAVAILABLE", blockers))
                    continue

                md = meta.method_definition(mid)
                metadata_class = meta.type_definition(int(md["declaringTypeIndex"]))["label"]
                metadata_image = _image_for_type(int(md["declaringTypeIndex"]), starts, image_ranges)
                metadata_method = str(md.get("name") or "")
                metadata_token = int(md.get("token") or 0)
                token_match = metadata_token == int(token)
                image_match = bool(image and metadata_image and image == metadata_image)
                class_match = _class_identity_match(cls, metadata_class)
                method_match = bool(method and metadata_method == method)
                if not (token_match and image_match and class_match and method_match):
                    counts["identityMismatch"] += 1
                    blockers = []
                    if not token_match:
                        blockers.append("metadata-token-mismatch")
                    if not image_match:
                        blockers.append("image-mismatch")
                    if not class_match:
                        blockers.append("declaring-type-mismatch")
                    if not method_match:
                        blockers.append("method-name-mismatch")
                    status = "NATIVE_RVA_TOKEN_MISMATCH" if not token_match else "NATIVE_RVA_IDENTITY_CONFLICT"
                    emit(_evidence(
                        mid, token, image, cls, method, status, blockers,
                        metadataResolvedToken=f"0x{metadata_token:08x}",
                        metadataResolvedImage=metadata_image,
                        metadataResolvedClass=metadata_class,
                        metadataResolvedMethodName=metadata_method,
                        identityConfirmed=False,
                    ))
                    continue

                if metadata_image in non_contiguous:
                    counts["nonContiguousTokenDomain"] += 1
                    emit(_evidence(
                        mid, token, metadata_image, metadata_class, metadata_method,
                        "NATIVE_RVA_NONCONTIGUOUS_TOKEN_DOMAIN",
                        ["metadata-method-token-domain-not-contiguous"],
                        identityConfirmed=True,
                        expectedMaxTokenRid=int(non_contiguous[metadata_image]),
                    ))
                    continue

                module = modules.get(metadata_image)
                if module is None:
                    counts["moduleUnresolved"] += 1
                    detail = (module_stats.get("modules") or {}).get(metadata_image) or {}
                    module_status = str(detail.get("status") or "NO_EXACT_COUNT_CANDIDATE")
                    if module_status == "AMBIGUOUS_AFTER_EXPECTED_COUNT":
                        status = "NATIVE_RVA_AMBIGUOUS_MODULE"
                        blocker = "multiple-codegenmodule-candidates-after-exact-method-count"
                    else:
                        status = "NATIVE_RVA_MODULE_UNRESOLVED"
                        blocker = "exact-codegenmodule-candidate-not-found"
                    emit(_evidence(
                        mid, token, metadata_image, metadata_class, metadata_method,
                        status, [blocker],
                        identityConfirmed=True,
                        moduleResolution=module_status,
                        codeGenModuleCandidateCount=int(detail.get("candidateCount") or 0),
                        expectedMethodCount=detail.get("expectedMethodCount"),
                    ))
                    continue

                counts["rowsInResolvedModule"] += 1
                pointer, pointer_status = _method_pointer(elf, module, int(token))
                if pointer is None:
                    counts[pointer_status] += 1
                    status = _unresolved_status(pointer_status)
                    emit(_evidence(
                        mid, token, metadata_image, metadata_class, metadata_method,
                        status, [pointer_status.lower().replace("_", "-")],
                        identityConfirmed=True,
                        moduleResolution="EXACT_EXPECTED_METHOD_COUNT",
                        codeGenModuleMethodCount=int(module[0]),
                        pointerStatus=pointer_status,
                    ))
                    continue

                pointer_uses = int(pointer_counts.get(int(pointer), 0))
                if pointer_uses != 1:
                    counts["sharedExecutablePointer"] += 1
                    emit(_evidence(
                        mid, token, metadata_image, metadata_class, metadata_method,
                        "NATIVE_RVA_SHARED_EXECUTABLE_POINTER",
                        ["executable-method-pointer-not-unique"],
                        identityConfirmed=True,
                        moduleResolution="EXACT_EXPECTED_METHOD_COUNT",
                        codeGenModuleMethodCount=int(module[0]),
                        candidatePointer=int(pointer),
                        candidatePointerHex=f"0x{int(pointer):x}",
                        executablePointerUseCount=pointer_uses,
                    ))
                    continue

                evidence = _evidence(
                    mid, token, metadata_image, metadata_class, metadata_method,
                    _SUCCESS, [],
                    identityConfirmed=True,
                    rva=int(pointer),
                    rvaHex=f"0x{int(pointer):x}",
                    addressConfirmed=True,
                    associationConfirmed=True,
                    uniqueExecutablePointer=True,
                    codeGenModuleMethodCount=int(module[0]),
                    moduleResolution="EXACT_EXPECTED_METHOD_COUNT",
                    identityProof="metadataMethodId+token+image+declaringType+methodName",
                )
                emit(evidence)
                counts["recoveredExact"] += 1

        result = {
            "schema": SCHEMA,
            "engine": "il2cpp.codegenmodule-native-recovery",
            "mode": "STATIC_EXACT_CODEGENMODULE_METHOD_POINTER",
            "metadataVersion": int(meta.version),
            "moduleResolution": module_stats,
            "nonContiguousMetadataTokenDomains": len(non_contiguous),
            "resolvedModuleCount": len(modules),
            "counts": dict(counts),
            "statusCounts": dict(sorted(status_counts.items())),
            "rowsFile": rows_path.name,
            "rowsAreFileBacked": True,
            "rowsIncludeUnresolvedProvenance": True,
            "addressResolver": True,
            "requiresUniqueExecutablePointer": True,
            "executesTargetCode": False,
            "writesTarget": False,
            "actionable": False,
            "buildable": False,
            "promotesBuildability": False,
            "note": "Every no-RVA row records its exact blocker. Only exact metadata identity + unique exact-count CodeGenModule + unique executable pointer yields a recovered RVA; normal binding/preflight is still mandatory.",
            "samples": samples,
            "failureSamples": failure_samples,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return result
    finally:
        if meta is not None:
            meta.close()
        if elf is not None:
            elf.close()


def recover_workspace(workspace: str | Path, output_path: str | Path | None = None, cb=None) -> dict[str, Any]:
    root = Path(workspace)
    output = Path(output_path) if output_path else root / "il2cpp-no-rva-native.json"
    return recover_no_rva(
        root / "metadata.bin",
        root / "library.so",
        root / "analysis.methods.jsonl",
        output,
        root / "il2cpp-no-rva-native.methods.jsonl",
        cb,
    )
