from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-security-surfaces-1.0"
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 6000
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")
URL_RE = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>\\]{4,512}", re.I)
HOSTPORT_RE = re.compile(r"(?<![A-Za-z0-9._-])((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}:\d{2,5})(?!\d)")
API_PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:api|rest|graphql|oauth2?|auth|login|session|v\d+)(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,220})?", re.I)
CERT_PIN_RE = re.compile(r"\bsha256/[A-Za-z0-9+/]{40,88}={0,2}\b")
CRYPTO_MARKERS = ("aes/gcm", "aes/cbc", "chacha20", "blowfish", "xtea", "pbkdf2", "hkdf", "hmacsha")
KEY_MARKERS = ("encryption_key", "aes_key", "keystore", "keyalias", "secretkeyspec", "keygenerator", "api_key", "client_id")
NETWORK_MARKERS = ("retrofit", "okhttp", "websocket", "io.grpc", "grpc", "graphql", "certificatepinner", "trustmanager")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _row(kind: str, title: str, apk: str, entry: str, offset: int, value: str | None = None, severity: str = "INFO", description: str = "") -> dict[str, Any]:
    stable = _sha(apk + "!" + entry + "!" + str(offset) + "!" + str(value or title))[:20]
    row = {"id": "sec:" + kind.lower() + ":" + stable, "kind": kind, "title": title,
           "category": "Security/Connection", "status": "CONFIRMED", "severity": severity,
           "description": description, "apk": apk, "entry": entry, "offset": int(offset),
           "trustBoundary": "server", "serverAudit": True}
    if value is not None:
        row["value"] = value[:1024]
    return row


def find_network_and_crypto_markers(text: str, apk: str = "", entry: str = "", base_offset: int = 0) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for match in URL_RE.finditer(text):
        value = match.group(0).rstrip(".,);]")
        kind = "WEBSOCKET_ENDPOINT" if value.lower().startswith(("ws://", "wss://")) else "API_ENDPOINT"
        rows.append(_row(kind, "Server/API endpoint", apk, entry, base_offset + match.start(), value, "MEDIUM", "Hardcoded endpoint in the selected local APK/APK-set."))
    for match in HOSTPORT_RE.finditer(text):
        rows.append(_row("HOST_PORT", "Server host:port", apk, entry, base_offset + match.start(1), match.group(1), "MEDIUM", "Hostname with explicit port."))
    for match in API_PATH_RE.finditer(text):
        rows.append(_row("API_PATH", "API route/path", apk, entry, base_offset + match.start(), match.group(0), "INFO", "API-like route in client code/resources."))
    for match in CERT_PIN_RE.finditer(text):
        rows.append(_row("CERT_PIN", "TLS certificate pin", apk, entry, base_offset + match.start(), match.group(0), "MEDIUM", "TLS pinning marker."))
    low = text.lower()
    for marker in CRYPTO_MARKERS:
        pos = low.find(marker)
        if pos >= 0:
            rows.append(_row("CRYPTO_PRIMITIVE", "Crypto primitive: " + marker, apk, entry, base_offset + pos, None, "INFO", "Cryptographic primitive/class marker."))
    for marker in KEY_MARKERS:
        pos = low.find(marker)
        if pos >= 0:
            rows.append(_row("KEY_CONFIG_MARKER", "Key/config marker: " + marker, apk, entry, base_offset + pos, None, "MEDIUM", "Location of key/configuration handling. Value is not extracted."))
    for marker in NETWORK_MARKERS:
        pos = low.find(marker)
        if pos >= 0:
            rows.append(_row("NETWORK_STACK", "Network stack marker: " + marker, apk, entry, base_offset + pos, None, "INFO", "Networking framework marker."))
    return rows


def _strings(data: bytes):
    for match in PRINTABLE.finditer(data):
        yield match.start(), match.group().decode("utf-8", "replace")


def _scan_entry(apk: Path, z: zipfile.ZipFile, info: zipfile.ZipInfo, remaining: int) -> list[dict[str, Any]]:
    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_ENTRY_BYTES:
        return []
    low = info.filename.lower()
    interesting = low.endswith((".dex", ".so", ".xml", ".json", ".txt", ".properties", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".js", ".jsc", ".lua", ".luac", ".luae", ".proto")) or "assets/" in low or "res/raw/" in low
    if not interesting:
        return []
    try:
        data = z.read(info)
    except Exception:
        return []
    rows: list[dict[str, Any]] = []
    for offset, text in _strings(data):
        rows.extend(find_network_and_crypto_markers(text, apk.name, info.filename, offset))
        if len(rows) >= remaining:
            break
    return rows[:remaining]


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int]] = set()
    skipped = 0
    for raw in paths:
        apk = Path(raw)
        if not apk.is_file():
            continue
        try:
            with zipfile.ZipFile(apk) as z:
                for info in z.infolist():
                    if len(findings) >= MAX_FINDINGS:
                        break
                    if info.file_size > MAX_ENTRY_BYTES:
                        skipped += 1
                        continue
                    for row in _scan_entry(apk, z, info, MAX_FINDINGS - len(findings)):
                        key = (row["kind"], row["apk"], row["entry"], row["offset"])
                        if key not in seen:
                            seen.add(key)
                            findings.append(row)
        except Exception:
            continue
    counts: dict[str, int] = {}
    for row in findings:
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
    out = {"schema": SCHEMA, "passive": True, "activeConnectionAttempted": False,
           "credentialValueExtraction": False, "findings": findings, "counts": counts,
           "total": len(findings), "skippedOversizeEntries": skipped,
           "truncated": len(findings) >= MAX_FINDINGS}
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
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


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path)
