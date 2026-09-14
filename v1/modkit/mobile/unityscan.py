"""Small, dependency-free Android Unity/Addressables inspector.

Reconstructed as source from the 0.8.1 behavior.  The scanner never executes
payloads. It connects APK entries, Addressables catalog locations and owning
UnityFS bundles, and keeps each piece of evidence separate.
"""
from __future__ import annotations

import base64
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import zipfile

DEFAULT_TERMS = (
    "cheat", "terminal", "console", "debug", "godmode", "noclip", "health",
    "damage", "money", "currency", "developer",
)
MAX_BUNDLE_BYTES = 128 * 1024 * 1024


def _check(cb, text=None):
    if cb is not None:
        if cb.isCancelled():
            raise RuntimeError("Операция отменена")
        if text:
            cb.progress(text)


def _read_keys(encoded: str) -> list:
    data = base64.b64decode(encoded)
    if len(data) < 4:
        return []
    count = struct.unpack_from("<I", data, 0)[0]
    pos, values = 4, []
    try:
        for _ in range(count):
            kind = data[pos]; pos += 1
            if kind in (0, 1, 6, 7):
                size = struct.unpack_from("<I", data, pos)[0]; pos += 4
                raw = data[pos:pos + size]; pos += size
                # Addressables uses UTF-16 for one of its string-key variants and
                # UTF-8 for the others. Decode defensively and preserve evidence.
                if kind == 1 and len(raw) % 2 == 0:
                    values.append(raw.decode("utf-16-le", "replace").rstrip("\x00"))
                else:
                    values.append(raw.decode("utf-8", "replace").rstrip("\x00"))
            elif kind == 2:
                values.append(struct.unpack_from("<H", data, pos)[0]); pos += 2
            elif kind in (3, 4):
                values.append(struct.unpack_from("<i", data, pos)[0]); pos += 4
            elif kind == 5:
                values.append(data[pos:pos + 16].hex()); pos += 16
            else:
                raise ValueError("Неизвестный тип ключа Addressables: %d" % kind)
    except (IndexError, struct.error):
        raise ValueError("Повреждена таблица ключей Addressables")
    return values


def _read_buckets(encoded: str) -> list[tuple[int, tuple[int, ...]]]:
    data = base64.b64decode(encoded)
    if len(data) < 4:
        return []
    count = struct.unpack_from("<I", data, 0)[0]
    pos, buckets = 4, []
    try:
        for _ in range(count):
            offset, amount = struct.unpack_from("<II", data, pos); pos += 8
            indexes = struct.unpack_from("<" + "I" * amount, data, pos) if amount else ()
            pos += amount * 4
            buckets.append((offset, tuple(indexes)))
    except (IndexError, struct.error):
        raise ValueError("Повреждена таблица связей Addressables")
    return buckets


def decode_catalog(raw: bytes, terms=DEFAULT_TERMS) -> dict:
    catalog = json.loads(raw.decode("utf-8"))
    internal = list(catalog.get("m_InternalIds") or [])
    keys = _read_keys(catalog.get("m_KeyDataString", ""))
    buckets = _read_buckets(catalog.get("m_BucketDataString", ""))
    data = base64.b64decode(catalog.get("m_EntryDataString", ""))
    if len(data) < 4:
        count, entries = 0, []
    else:
        count = struct.unpack_from("<I", data, 0)[0]
        if 4 + count * 28 > len(data):
            raise ValueError("Повреждена таблица записей Addressables")
        entries = [struct.unpack_from("<7i", data, 4 + i * 28) for i in range(count)]

    wanted = tuple(str(x).casefold() for x in terms)
    findings, typed_assets = [], {"scenes": [], "prefabs": [], "scriptable_assets": []}
    for entry_index, entry in enumerate(entries):
        internal_index, provider, dependency_key, dependency_hash, data_index, primary_key_index, resource_type_index = entry
        asset = internal[internal_index] if 0 <= internal_index < len(internal) else "?"
        primary_key = keys[primary_key_index] if 0 <= primary_key_index < len(keys) else "?"
        resource_type = keys[resource_type_index] if 0 <= resource_type_index < len(keys) else "?"
        low_asset = str(asset).casefold()
        if low_asset.endswith((".unity", ".scene")):
            typed_assets["scenes"].append(str(asset))
        elif low_asset.endswith(".prefab"):
            typed_assets["prefabs"].append(str(asset))
        elif low_asset.endswith(".asset"):
            typed_assets["scriptable_assets"].append(str(asset))

        matched = sorted({t for t in wanted if t in (str(asset) + " " + str(primary_key) + " " + str(resource_type)).casefold()})
        bundles = []
        # Buckets are key->entry adjacency lists. Resolve direct dependency entry
        # indexes conservatively and keep only bundle-looking internal IDs.
        if 0 <= dependency_key < len(buckets):
            for dependency_entry_index in buckets[dependency_key][1][:64]:
                if 0 <= dependency_entry_index < len(entries):
                    di = entries[dependency_entry_index][0]
                    dependency_internal = internal[di] if 0 <= di < len(internal) else ""
                    if str(dependency_internal).casefold().endswith(".bundle"):
                        bundles.append(str(dependency_internal).rsplit("/", 1)[-1])
        owner_bundle = bundles[0] if bundles else None
        if matched:
            findings.append({
                "asset": str(asset), "terms": matched, "entry_index": entry_index,
                "primary_key": str(primary_key), "resource_type": str(resource_type),
                "owner_bundle": owner_bundle, "dependency_bundles": sorted(set(bundles)),
                "dependency_bundle_count": len(set(bundles)), "evidence": "addressables_catalog",
            })
    return {
        "locator": catalog.get("m_LocatorId"), "internal_id_count": len(internal),
        "entry_count": len(entries), "findings": findings, "typed_assets": typed_assets,
    }


def _cstring(data: bytes, pos: int) -> tuple[str, int]:
    end = data.find(b"\x00", pos)
    if end < 0:
        raise ValueError("Повреждён заголовок UnityFS")
    return data[pos:end].decode("utf-8", "replace"), end + 1


def _lz4_block(data: bytes, expected: int) -> bytes:
    out = bytearray(); pos = 0
    while pos < len(data):
        token = data[pos]; pos += 1
        literal = token >> 4
        if literal == 15:
            while pos < len(data):
                value = data[pos]; pos += 1; literal += value
                if value != 255: break
        if pos + literal > len(data): raise ValueError("Повреждён LZ4-блок")
        out.extend(data[pos:pos + literal]); pos += literal
        if pos >= len(data): break
        if pos + 2 > len(data): raise ValueError("Повреждён LZ4-блок")
        distance = data[pos] | (data[pos + 1] << 8); pos += 2
        if distance <= 0 or distance > len(out): raise ValueError("Некорректная ссылка LZ4")
        length = token & 0xF
        if length == 15:
            while pos < len(data):
                value = data[pos]; pos += 1; length += value
                if value != 255: break
        length += 4
        for _ in range(length): out.append(out[-distance])
    if len(out) != expected:
        raise ValueError("Размер распакованного LZ4-блока не совпал")
    return bytes(out)


def _decompress(data: bytes, kind: int, expected: int) -> bytes:
    kind &= 63
    if kind == 0: result = data
    elif kind == 1: result = lzma.decompress(data)
    elif kind in (2, 3): result = _lz4_block(data, expected)
    else: raise ValueError("Неподдерживаемое сжатие UnityFS: %d" % kind)
    if len(result) != expected: raise ValueError("Размер блока UnityFS не совпал")
    return result


def scan_unityfs(raw: bytes, terms=DEFAULT_TERMS) -> dict:
    signature, pos = _cstring(raw, 0)
    if signature != "UnityFS": raise ValueError("Bundle не имеет формата UnityFS")
    version = struct.unpack_from(">I", raw, pos)[0]; pos += 4
    unity_version, pos = _cstring(raw, pos)
    revision, pos = _cstring(raw, pos)
    bundle_size, compressed_info, uncompressed_info, flags = struct.unpack_from(">QIII", raw, pos); pos += 20
    # UnityFS v7+ aligns the blocks/directory-info stream to 16 bytes.  Newer
    # writers may additionally request 16-byte padding before the data blocks
    # with ArchiveFlags.BlockInfoNeedPaddingAtStart (0x200).
    header_data_pos = (pos + 15) & ~15 if version >= 7 else pos
    info_at_end = bool(flags & 0x80)
    info_pos = len(raw) - compressed_info if info_at_end else header_data_pos
    packed_info = raw[info_pos:info_pos + compressed_info]
    info = _decompress(packed_info, flags, uncompressed_info)
    ip = 16  # 16-byte hash
    block_count = struct.unpack_from(">I", info, ip)[0]; ip += 4
    blocks = []
    for _ in range(block_count):
        unpacked, packed, block_flags = struct.unpack_from(">IIH", info, ip); ip += 10
        blocks.append((unpacked, packed, block_flags))
    node_count = struct.unpack_from(">I", info, ip)[0]; ip += 4
    nodes = []
    for _ in range(node_count):
        offset, size, node_flags = struct.unpack_from(">QQI", info, ip); ip += 20
        name, ip = _cstring(info, ip)
        nodes.append({"name": name, "offset": offset, "size": size, "flags": node_flags})

    if info_at_end:
        data_pos = header_data_pos
    else:
        data_pos = info_pos + compressed_info
        if flags & 0x200:
            data_pos = (data_pos + 15) & ~15
    strings, searchable = set(), bytearray()
    cursor = data_pos
    for unpacked, packed, block_flags in blocks:
        block = raw[cursor:cursor + packed]; cursor += packed
        searchable.extend(_decompress(block, block_flags, unpacked))
        if len(searchable) > MAX_BUNDLE_BYTES:
            break
    wanted = tuple(str(x).casefold() for x in terms)
    for match in re.finditer(rb"[ -~]{4,180}", bytes(searchable)):
        text = match.group().decode("utf-8", "ignore")
        if any(term in text.casefold() for term in wanted): strings.add(text)
        if len(strings) >= 1000: break
    serialized = [n["name"] for n in nodes if not n["name"].casefold().endswith((".resource", ".ress"))]
    resources = [n["name"] for n in nodes if n["name"].casefold().endswith((".resource", ".ress"))]
    return {
        "format": "UnityFS", "format_version": version, "unity_version": unity_version,
        "revision": revision, "declared_size": bundle_size, "nodes": nodes,
        "serialized_files": serialized, "resource_files": resources,
        "matched_strings": sorted(strings),
    }


def inspect_apk(apk_path, metadata_out=None, library_out=None, report_out=None, cb=None) -> dict:
    result = {"schema": 1, "apk": str(apk_path), "catalogs": [], "bundles": [], "warnings": []}
    with zipfile.ZipFile(apk_path) as apk:
        names = apk.namelist()
        metadata = next((n for n in names if n.endswith("/Managed/Metadata/global-metadata.dat") or n.endswith("global-metadata.dat")), None)
        library = "lib/arm64-v8a/libil2cpp.so" if "lib/arm64-v8a/libil2cpp.so" in names else next((n for n in names if n.endswith("/libil2cpp.so") and "arm64" in n), None)
        if metadata is None: result["warnings"].append("В APK не найден global-metadata.dat")
        if library is None: result["warnings"].append("В APK не найден ARM64 libil2cpp.so")

        for source, destination, label in ((metadata, metadata_out, "метаданных"), (library, library_out, "ARM64-библиотеки")):
            if source and destination:
                _check(cb, "Извлечение " + label + " из APK…")
                temp = str(destination) + ".tmp"
                with apk.open(source) as src, open(temp, "wb") as dst:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk: break
                        _check(cb); dst.write(chunk)
                Path(temp).replace(destination)

        catalogs = [n for n in names if n.casefold().endswith("catalog.json") and "/aa/" in n.casefold()]
        owner_bundles = set()
        for catalog_name in catalogs:
            try:
                _check(cb, "Разбор Addressables: " + catalog_name)
                decoded = decode_catalog(apk.read(catalog_name))
                decoded["apk_entry"] = catalog_name
                result["catalogs"].append(decoded)
                for finding in decoded.get("findings", []):
                    if finding.get("owner_bundle"): owner_bundles.add(finding["owner_bundle"])
            except Exception as exc:
                result["warnings"].append(catalog_name + ": " + str(exc))

        by_basename = {n.rsplit("/", 1)[-1]: n for n in names if n.casefold().endswith(".bundle")}
        for index, bundle in enumerate(sorted(owner_bundles)):
            entry = by_basename.get(bundle)
            if not entry: continue
            try:
                _check(cb, "Проверка Unity bundle %d/%d: %s" % (index + 1, len(owner_bundles), bundle))
                info = apk.getinfo(entry)
                if info.file_size > MAX_BUNDLE_BYTES:
                    result["warnings"].append("%s: пропущен bundle размером %.1f МБ (лимит памяти %.0f МБ)" % (entry, info.file_size / 1048576, MAX_BUNDLE_BYTES / 1048576))
                    continue
                raw = apk.read(entry)
                scanned = scan_unityfs(raw)
                scanned.update({"apk_entry": entry, "sha256": hashlib.sha256(raw).hexdigest()})
                result["bundles"].append(scanned)
            except Exception as exc:
                result["warnings"].append(bundle + ": " + str(exc))

    result["summary"] = {
        "catalogs": len(result["catalogs"]),
        "addressable_findings": sum(len(x.get("findings", [])) for x in result["catalogs"]),
        "owner_bundles_scanned": len(result["bundles"]),
        "bundle_string_hits": sum(len(x.get("matched_strings", [])) for x in result["bundles"]),
        "scenes": sum(len(x.get("typed_assets", {}).get("scenes", [])) for x in result["catalogs"]),
        "prefabs": sum(len(x.get("typed_assets", {}).get("prefabs", [])) for x in result["catalogs"]),
        "scriptable_assets": sum(len(x.get("typed_assets", {}).get("scriptable_assets", [])) for x in result["catalogs"]),
        "serialized_files": sum(len(x.get("serialized_files", [])) for x in result["bundles"]),
    }
    if report_out:
        Path(report_out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
