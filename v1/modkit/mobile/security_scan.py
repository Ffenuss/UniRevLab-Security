"""Passive static discovery of Android network, cryptography and runtime artifact surfaces.

No sockets are opened and no authentication is attempted. The report records API/server
endpoints and locations of crypto/key-handling configuration. It does not extract or use
credential values. Repeated occurrences are aggregated by normalized surface identity so
one CDN/API/config marker does not become hundreds of independent findings.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

from . import artifact_families
from .evidence_quality import normalize_endpoint

SCHEMA = "modkit-security-surfaces-1.4"
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 6000
MAX_LOCATIONS_PER_FINDING = 16
READ_CHUNK_BYTES = 1024 * 1024
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")
URL_RE = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>\\]{4,512}", re.I)
HOSTPORT_RE = re.compile(r"(?<![A-Za-z0-9._-])((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}:\d{2,5})(?!\d)")
API_PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:api|rest|graphql|oauth2?|auth|login|session|v\d+)(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,220})?", re.I)
CERT_PIN_RE = re.compile(r"\bsha256/[A-Za-z0-9+/]{40,88}={0,2}\b")
CRYPTO_MARKERS = ("aes/gcm", "aes/cbc", "chacha20", "blowfish", "xtea", "pbkdf2", "hkdf", "hmacsha", "secretkeyspec")
KEY_MARKERS = ("encryption_key", "aes_key", "crypto_key", "keystore", "keyalias", "secretkeyspec", "keygenerator", "api_key", "apikey", "client_id", "client_secret")
NETWORK_MARKERS = ("retrofit", "okhttp", "websocket", "io.grpc", "grpc", "graphql", "certificatepinner", "trustmanager")
CONNECTION_CONFIG_MARKERS = ("baseurl", "base_url", "api_host", "apihost", "server_url", "serverurl", "server_host", "gateway_url", "socket_url", "websocket_url")
_ENDPOINT_KINDS = {"API_ENDPOINT", "WEBSOCKET_ENDPOINT", "HOST_PORT", "API_PATH"}


class ScanCancelled(RuntimeError):
    """Raised cooperatively so callers never publish a partial security report."""


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
        raise ScanCancelled("security scan cancelled")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _row(kind: str, title: str, apk: str, entry: str, offset: int, value: str | None = None,
         severity: str = "INFO", description: str = "", group: str = "network") -> dict[str, Any]:
    # ID is finalized after normalization/aggregation. Keeping it location-independent
    # prevents one literal repeated in many DEX/splits from looking like many issues.
    row: dict[str, Any] = {
        "kind": kind,
        "title": title,
        "category": "Security/Connection",
        "status": "FOUND_STATIC",
        "severity": severity,
        "description": description,
        "apk": apk,
        "entry": entry,
        "offset": int(offset),
        "trustBoundary": "server",
        "serverAudit": True,
        "evidenceRole": "static-string",
        "group": group,
    }
    if value is not None:
        row["value"] = value[:1024]
    return row


def _normalized_value(row: dict[str, Any]) -> str:
    kind = str(row.get("kind") or "").upper()
    value = str(row.get("value") or "").strip()
    if value:
        if kind in _ENDPOINT_KINDS:
            return normalize_endpoint(value)
        return re.sub(r"\s+", " ", value).strip().casefold()
    # Marker-only evidence is intentionally global: its location list keeps provenance.
    return re.sub(r"\s+", " ", str(row.get("title") or kind)).strip().casefold()


def _finding_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("group") or "network").casefold(),
        str(row.get("kind") or "UNKNOWN").upper(),
        _normalized_value(row),
    )


def _location(row: dict[str, Any]) -> dict[str, Any]:
    return {"apk": row.get("apk"), "entry": row.get("entry"), "offset": int(row.get("offset") or 0)}


def _merge_finding(existing: dict[str, Any] | None, row: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalized_value(row)
    if existing is None:
        out = dict(row)
        identity = "|".join((str(row.get("group") or "network").casefold(), str(row.get("kind") or "UNKNOWN").upper(), normalized))
        out["id"] = "sec:" + str(row.get("kind") or "unknown").lower() + ":" + _sha(identity)[:20]
        out["normalizedValue"] = normalized
        out["occurrenceCount"] = 1
        out["locations"] = [_location(row)]
        out["deduplicated"] = False
        return out
    out = existing
    out["occurrenceCount"] = int(out.get("occurrenceCount", 1) or 1) + 1
    out["deduplicated"] = True
    loc = _location(row)
    locations = out.get("locations") if isinstance(out.get("locations"), list) else []
    if loc not in locations and len(locations) < MAX_LOCATIONS_PER_FINDING:
        locations.append(loc)
    out["locations"] = locations
    return out


def find_network_and_crypto_markers(text: str, apk: str = "", entry: str = "", base_offset: int = 0) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for match in URL_RE.finditer(text):
        value = match.group(0).rstrip(".,);]")
        kind = "WEBSOCKET_ENDPOINT" if value.lower().startswith(("ws://", "wss://")) else "API_ENDPOINT"
        rows.append(_row(kind, "Server/API endpoint", apk, entry, base_offset + match.start(), value, "MEDIUM",
                         "Hardcoded endpoint in the selected local APK/APK-set.", "endpoints"))
    for match in HOSTPORT_RE.finditer(text):
        rows.append(_row("HOST_PORT", "Server host:port", apk, entry, base_offset + match.start(1), match.group(1), "MEDIUM",
                         "Hostname with explicit port.", "endpoints"))
    for match in API_PATH_RE.finditer(text):
        rows.append(_row("API_PATH", "API route/path", apk, entry, base_offset + match.start(), match.group(0), "INFO",
                         "API-like route in client code/resources.", "endpoints"))
    for match in CERT_PIN_RE.finditer(text):
        rows.append(_row("CERT_PIN", "TLS certificate pin", apk, entry, base_offset + match.start(), match.group(0), "MEDIUM",
                         "TLS pinning material. Static presence does not prove the runtime path is active.", "crypto"))
    low = text.lower()
    for marker in CRYPTO_MARKERS:
        pos = low.find(marker)
        if pos >= 0:
            rows.append(_row("CRYPTO_PRIMITIVE", "Crypto primitive: " + marker, apk, entry, base_offset + pos, None, "INFO",
                             "Cryptographic primitive/class marker.", "crypto"))
    for marker in KEY_MARKERS:
        pos = low.find(marker)
        if pos >= 0:
            rows.append(_row("KEY_CONFIG_MARKER", "Key/config marker: " + marker, apk, entry, base_offset + pos, None, "MEDIUM",
                             "Location of key/configuration handling. Credential/key values are not extracted.", "crypto"))
    for marker in NETWORK_MARKERS:
        pos = low.find(marker)
        if pos >= 0:
            rows.append(_row("NETWORK_STACK", "Network stack marker: " + marker, apk, entry, base_offset + pos, None, "INFO",
                             "Networking framework marker.", "network"))
    for marker in CONNECTION_CONFIG_MARKERS:
        pos = low.find(marker)
        if pos >= 0:
            rows.append(_row("CONNECTION_CONFIG", "Connection config marker: " + marker, apk, entry, base_offset + pos, None, "INFO",
                             "Likely base URL/host/gateway configuration location. Inspect locally to determine the actual configured value.", "endpoints"))
    return rows


def _strings(data: bytes, cb: Any | None = None):
    _check(cb)
    for no, match in enumerate(PRINTABLE.finditer(data)):
        if (no & 0xFF) == 0:
            _check(cb)
        yield match.start(), match.group().decode("utf-8", "replace")


def _read_entry(z: zipfile.ZipFile, info: zipfile.ZipInfo, cb: Any | None = None) -> bytes:
    chunks: list[bytes] = []
    with z.open(info, "r") as source:
        while True:
            _check(cb)
            chunk = source.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
    _check(cb)
    return b"".join(chunks)


def _scan_entry(apk: Path, z: zipfile.ZipFile, info: zipfile.ZipInfo,
                cb: Any | None = None) -> list[dict[str, Any]]:
    _check(cb)
    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_ENTRY_BYTES:
        return []
    low = info.filename.lower()
    interesting = low.endswith((".dex", ".so", ".xml", ".json", ".txt", ".properties", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".js", ".jsc", ".lua", ".luac", ".luae", ".proto")) or "assets/" in low or "res/raw/" in low
    if not interesting:
        return []
    try:
        data = _read_entry(z, info, cb)
    except ScanCancelled:
        raise
    except Exception:
        return []
    rows: list[dict[str, Any]] = []
    for offset, text in _strings(data, cb):
        rows.extend(find_network_and_crypto_markers(text, apk.name, info.filename, offset))
        # Bound one pathological entry even when most hits later deduplicate globally.
        if len(rows) >= MAX_FINDINGS:
            break
    _check(cb)
    return rows[:MAX_FINDINGS]


def _group(findings: list[dict[str, Any]], name: str) -> dict[str, Any]:
    rows = [r for r in findings if r.get("group") == name]
    unique_values: dict[tuple[str, str], dict[str, Any]] = {}
    markers: set[str] = set()
    occurrence_count = 0
    for row in rows:
        occurrence_count += int(row.get("occurrenceCount", 1) or 1)
        value = str(row.get("value") or "")
        normalized = str(row.get("normalizedValue") or "")
        if value:
            key = (str(row.get("kind") or ""), normalized or value.casefold())
            item = unique_values.setdefault(key, {"kind": key[0], "value": value, "normalizedValue": normalized, "occurrenceCount": 0, "locations": []})
            item["occurrenceCount"] += int(row.get("occurrenceCount", 1) or 1)
            for loc in row.get("locations", []) if isinstance(row.get("locations"), list) else []:
                if loc not in item["locations"] and len(item["locations"]) < MAX_LOCATIONS_PER_FINDING:
                    item["locations"].append(loc)
        else:
            markers.add(str(row.get("title") or row.get("kind") or ""))
    return {
        "count": len(rows),
        "occurrenceCount": occurrence_count,
        "uniqueValueCount": len(unique_values),
        "values": list(unique_values.values())[:200],
        "markers": sorted(x for x in markers if x)[:200],
    }


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    raw_occurrences = 0
    skipped = 0
    truncated = False
    for raw in paths:
        _check(cb)
        apk = Path(raw)
        if not apk.is_file():
            continue
        try:
            with zipfile.ZipFile(apk) as z:
                for info in z.infolist():
                    _check(cb)
                    if info.file_size > MAX_ENTRY_BYTES:
                        skipped += 1
                        continue
                    for row in _scan_entry(apk, z, info, cb):
                        raw_occurrences += 1
                        key = _finding_key(row)
                        existing = findings_by_key.get(key)
                        if existing is None and len(findings_by_key) >= MAX_FINDINGS:
                            truncated = True
                            continue
                        findings_by_key[key] = _merge_finding(existing, row)
        except ScanCancelled:
            raise
        except Exception:
            continue
    _check(cb)
    findings = list(findings_by_key.values())
    findings.sort(key=lambda row: (str(row.get("group") or ""), str(row.get("kind") or ""), str(row.get("normalizedValue") or "")))
    counts: dict[str, int] = {}
    occurrence_counts: dict[str, int] = {}
    for row in findings:
        kind = str(row.get("kind") or "UNKNOWN")
        counts[kind] = counts.get(kind, 0) + 1
        occurrence_counts[kind] = occurrence_counts.get(kind, 0) + int(row.get("occurrenceCount", 1) or 1)
    groups = {name: _group(findings, name) for name in ("endpoints", "network", "crypto")}
    out = {
        "schema": SCHEMA,
        "passive": True,
        "activeConnectionAttempted": False,
        "credentialValidationAttempted": False,
        "credentialValueExtraction": False,
        "keyValueExtraction": False,
        "findings": findings,
        "counts": counts,
        "occurrenceCounts": occurrence_counts,
        "groups": groups,
        "total": len(findings),
        "rawOccurrenceCount": raw_occurrences,
        "deduplicatedOccurrences": max(0, raw_occurrences - len(findings)),
        "uniqueEndpoints": groups["endpoints"]["uniqueValueCount"],
        "skippedOversizeEntries": skipped,
        "truncated": truncated,
        "dedupPolicy": {
            "normalizedIdentity": True,
            "queryValuesExcludedFromEndpointIdentity": True,
            "maxLocationsPerFinding": MAX_LOCATIONS_PER_FINDING,
            "preservesOccurrenceCount": True,
        },
    }
    _check(cb)
    if output_path:
        destination = Path(output_path)
        temporary = destination.with_name(destination.name + ".part")
        temporary.unlink(missing_ok=True)
        try:
            temporary.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            _check(cb)
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    return out


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


def _artifact_report(root: Path, apk_paths: list[Path]) -> tuple[dict[str, Any], bool]:
    """Reuse the current full-analysis enriched report instead of downgrading it."""
    path = root / "artifact-families.json"
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and existing.get("embeddedEnriched") and isinstance(existing.get("artifacts"), list):
                return existing, True
        except Exception:
            pass
    return artifact_families.scan_apk_paths(apk_paths, path), False


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    _check(cb)
    apk_paths = _workspace_apks(root)
    artifact_output = root / "artifact-families.json"
    artifact_report, reused_enriched = _artifact_report(root, apk_paths)
    _check(cb)
    out = scan_apk_paths(apk_paths, None, cb)
    out["artifactFamilies"] = {
        "schema": artifact_report.get("schema"),
        "total": artifact_report.get("total", 0),
        "familyCounts": artifact_report.get("familyCounts", {}),
        "recoveryCounts": artifact_report.get("recoveryCounts", {}),
        "deepHermes": artifact_report.get("deepHermes", {}),
        "deepNative": artifact_report.get("deepNative", {}),
        "deepFlutter": artifact_report.get("deepFlutter", {}),
        "embeddedEnriched": bool(artifact_report.get("embeddedEnriched")),
        "reusedEnrichedReport": reused_enriched,
        "report": artifact_output.name,
    }
    _check(cb)
    if output_path:
        destination = Path(output_path)
        temporary = destination.with_name(destination.name + ".part")
        temporary.unlink(missing_ok=True)
        try:
            temporary.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            _check(cb)
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    return out
