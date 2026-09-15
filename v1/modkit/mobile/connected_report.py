from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA = "modkit-connected-report-1.1"


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _norm_hex(value: Any) -> str:
    if value in (None, "", 0, "0"):
        return ""
    if isinstance(value, int):
        return f"0x{value:x}"
    text = str(value).strip().lower()
    try:
        return f"0x{int(text, 0):x}"
    except Exception:
        return text


def _first(obj: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = obj.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _method_index(
    path: Path,
    wanted_ids: set[int] | None = None,
    wanted_rvas: set[str] | None = None,
    wanted_names: set[str] | None = None,
    limit: int = 250000,
) -> tuple[dict[int, dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]], int]:
    """Stream the method catalogue and retain only rows linkable to report findings.

    The historical implementation retained every row in three dictionaries.  On a
    large IL2CPP title that duplicated 100k-250k method dictionaries in RAM.  The
    connected report only ever consumes exact method ids, exact RVAs, or exact method
    names present in current findings, so unrelated rows are counted but not retained.
    RVA/name buckets remain capped at the same 25 rows exposed by `_link_methods`.
    """
    by_id: dict[int, dict[str, Any]] = {}
    by_rva: dict[str, list[dict[str, Any]]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    catalog_rows = 0
    ids = wanted_ids or set()
    rvas = wanted_rvas or set()
    names = wanted_names or set()
    if not path.is_file():
        return by_id, by_rva, by_name, catalog_rows
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for no, line in enumerate(stream):
            if no >= limit:
                break
            try:
                row = json.loads(line)
            except Exception:
                continue
            if not isinstance(row, dict):
                continue
            mid = row.get("id")
            if isinstance(mid, int):
                catalog_rows += 1
                if mid in ids:
                    by_id[mid] = row
            rva = _norm_hex(_first(row, "rva", "RVA", "address", "virtualAddress"))
            if rva and rva in rvas:
                bucket = by_rva.setdefault(rva, [])
                if len(bucket) < 25:
                    bucket.append(row)
            name = str(_first(row, "name", "method", "methodName", "label") or "").strip().casefold()
            if name and name in names:
                bucket = by_name.setdefault(name, [])
                if len(bucket) < 25:
                    bucket.append(row)
    return by_id, by_rva, by_name, catalog_rows


def _locator(card: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for source in (card.get("locator"), card.get("evidence"), card):
        if not isinstance(source, dict):
            continue
        for target, keys in {
            "methodId": ("methodId", "method_id", "id"),
            "class": ("class", "className", "type"),
            "method": ("method", "methodName", "name"),
            "rva": ("rva", "RVA", "address"),
            "entry": ("entry", "path", "file", "artifact"),
            "codeOffset": ("codeOffset", "offset"),
        }.items():
            if target not in out:
                value = _first(source, *keys)
                if value not in (None, ""):
                    out[target] = value
    if "rva" in out:
        out["rva"] = _norm_hex(out["rva"])
    return out


def _wanted_method_links(cards: list[Any]) -> tuple[set[int], set[str], set[str]]:
    ids: set[int] = set()
    rvas: set[str] = set()
    names: set[str] = set()
    for card in cards:
        if not isinstance(card, dict):
            continue
        loc = _locator(card)
        mid = loc.get("methodId")
        if isinstance(mid, int):
            ids.add(mid)
        elif mid not in (None, ""):
            try:
                ids.add(int(str(mid)))
            except Exception:
                pass
        rva = _norm_hex(loc.get("rva"))
        if rva:
            rvas.add(rva)
        name = str(loc.get("method") or "").strip().casefold()
        if name:
            names.add(name)
    return ids, rvas, names


def _link_methods(locator: dict[str, Any], by_id: dict[int, dict[str, Any]], by_rva: dict[str, list[dict[str, Any]]], by_name: dict[str, list[dict[str, Any]]]) -> tuple[str, list[dict[str, Any]]]:
    mid = locator.get("methodId")
    if isinstance(mid, int) and mid in by_id:
        return "EXACT_METHOD_ID", [by_id[mid]]
    try:
        parsed = int(str(mid)) if mid not in (None, "") else None
    except Exception:
        parsed = None
    if parsed is not None and parsed in by_id:
        return "EXACT_METHOD_ID", [by_id[parsed]]
    rva = _norm_hex(locator.get("rva"))
    if rva and rva in by_rva:
        return "EXACT_RVA", by_rva[rva][:25]
    name = str(locator.get("method") or "").strip().casefold()
    if name and name in by_name:
        return "EXACT_NAME", by_name[name][:25]
    return "UNRESOLVED", []


def _file_meta(root: Path, name: str, purpose: str, use: str) -> dict[str, Any]:
    path = root / name
    return {
        "file": name,
        "available": path.exists(),
        "bytes": path.stat().st_size if path.is_file() else None,
        "purpose": purpose,
        "whenToUse": use,
    }


def _engine_row(engine_id: str, report_file: str, report: dict[str, Any], **details: Any) -> dict[str, Any]:
    available = bool(report.get("available", report.get("detected", report.get("analyzedLibraryCount", 0))))
    if report and not any(key in report for key in ("available", "detected", "analyzedLibraryCount")):
        available = True
    row: dict[str, Any] = {
        "engineId": engine_id,
        "report": report_file,
        "available": available,
        "findingCount": int(report.get("findingCount") or 0),
        "manualImportRequired": bool(report.get("manualImportRequired", False)),
        "runtimeTruth": report.get("runtimeTruth") or "not-observed-by-static-analysis",
    }
    for key, value in details.items():
        if value not in (None, ""):
            row[key] = value
    return row


def _engine_coverage(root: Path, embedded: dict[str, Any], artifact_families: dict[str, Any]) -> list[dict[str, Any]]:
    lua = _json(root / "lua-deep.json")
    hermes = _json(root / "hermes-deep.json")
    native = _json(root / "native-deep.json")
    cocos = _json(root / "cocos-deep.json")
    flutter = _json(root / "flutter-deep.json")
    run_status = {
        str(row.get("engineId")): row.get("status")
        for row in embedded.get("runs", []) if isinstance(row, dict) and row.get("engineId")
    }
    rows = [
        _engine_row(
            "lua.bytecode-embedded", "lua-deep.json", lua,
            status=run_status.get("lua.bytecode-embedded"),
            chunkCount=int(lua.get("chunkCount") or 0),
            decodedChunks=sum(1 for row in lua.get("chunks", []) if isinstance(row, dict) and row.get("status") == "BYTECODE_DISASSEMBLED"),
            opaqueChunks=sum(1 for row in lua.get("chunks", []) if isinstance(row, dict) and row.get("recoveryLevel") == "OPAQUE"),
        ),
        _engine_row(
            "hermes.deep-embedded", "hermes-deep.json", hermes,
            status=run_status.get("hermes.deep-embedded"),
            bundleCount=int(hermes.get("bundleCount") or 0),
        ),
        _engine_row(
            "native.deep-embedded", "native-deep.json", native,
            status=run_status.get("native.deep-embedded"),
            libraryCount=int(native.get("analyzedLibraryCount") or 0),
            directCallCount=sum(int(row.get("directCallCount") or 0) for row in native.get("libraries", []) if isinstance(row, dict)),
            tailCallCount=sum(int(row.get("tailCallCount") or 0) for row in native.get("libraries", []) if isinstance(row, dict)),
            indirectSlotCount=sum(int(row.get("indirectSlotCount") or 0) for row in native.get("libraries", []) if isinstance(row, dict)),
        ),
        _engine_row(
            "cocos.deep-embedded", "cocos-deep.json", cocos,
            status=run_status.get("cocos.deep-embedded"),
            detectionConfidence=cocos.get("detectionConfidence"),
            nativeLibraryCount=int(cocos.get("nativeLibraryCount") or 0),
            scriptArtifactCount=int(cocos.get("scriptArtifactCount") or 0),
            bridgeSymbolCount=int(cocos.get("bridgeSymbolCount") or 0),
            correlationCount=int(cocos.get("correlationCount") or 0),
        ),
        _engine_row(
            "flutter.aot-embedded", "flutter-deep.json", flutter,
            status=run_status.get("flutter.aot-embedded"),
            artifactCount=int(flutter.get("artifactCount") or 0),
        ),
    ]
    # Keep the merged artifact-level summaries visible without duplicating the potentially huge reports.
    for row in rows:
        summary_key = {
            "lua.bytecode-embedded": "deepLua",
            "hermes.deep-embedded": "deepHermes",
            "native.deep-embedded": "deepNative",
            "cocos.deep-embedded": "deepCocos",
            "flutter.aot-embedded": "deepFlutter",
        }.get(str(row.get("engineId")))
        summary = artifact_families.get(summary_key) if summary_key else None
        if isinstance(summary, dict):
            row["mergedFindingCount"] = int(summary.get("mergedFindingCount") or 0)
    return rows


def _artifact_guide(root: Path) -> list[dict[str, Any]]:
    specs = [
        ("simple-catalog.json", "Приоритетная сводка findings", "Начинайте отсюда: важные, actionable и buildable находки."),
        ("connected-report.json", "Связанный человеко-читаемый индекс", "Используйте для связи finding → method/class/RVA и общей сводки."),
        ("analysis.methods.jsonl", "Полный каталог методов", "Ищите method id, class/method и RVA; файл большой и построчный."),
        ("analysis.fields.jsonl", "Каталог полей", "Ищите поля/offset evidence и владельца типа."),
        ("analysis.evidence-graph.jsonl", "Evidence Graph", "Используйте для связей между DEX/native/IL2CPP/security/semantic evidence."),
        ("analysis.gameplay-coverage.json", "Игровая семантика", "HP/damage/currency/speed/level и другие gameplay-домены."),
        ("lua-deep.json", "Lua bytecode structural report", "Прототипы, constants, instructions, debug metadata; opaque xLua/SLua отмечены явно."),
        ("hermes-deep.json", "Hermes HBC deep report", "Функции/инструкции/строки для поддерживаемых HBC версий."),
        ("native-deep.json", "ARM64/ELF deep report", "Символы, exact direct/tail edges, thunks, indirect slot evidence и string xrefs."),
        ("cocos-deep.json", "Cocos script↔native correlation", "JS/Lua symbol ↔ native bridge/symbol RVA; static correlation, не runtime proof."),
        ("flutter-deep.json", "Flutter/Dart AOT report", "Snapshot/package/route evidence и корреляция с libapp/native AOT."),
        ("security-surfaces.json", "Security surface report", "TLS/network/auth/crypto/storage/WebView и trust-boundary findings."),
        ("apktool-analysis.json", "Apktool decode summary", "Manifest/resources/smali decode status и workspace coverage."),
        ("full-reconstruction.json", "JADX reconstruction manifest", "Проверяйте полноту Java/Smali/resources reconstruction и cache state."),
        ("modkit-decompiled.zip", "Полный JADX export", "Открывайте исходноподобное Java-представление, Smali и resources."),
    ]
    return [_file_meta(root, *spec) for spec in specs]


def build_connected_report(workdir: str | Path, output_json: str | Path | None = None, output_md: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    catalog = _json(root / "simple-catalog.json")
    analysis = _json(root / "analysis.summary.json")
    security = _json(root / "security-surfaces.json")
    embedded = _json(root / "embedded-analysis.json")
    artifact_families = _json(root / "artifact-families.json")
    apktool = _json(root / "apktool-analysis.json")
    cards = catalog.get("cards") if isinstance(catalog.get("cards"), list) else []
    wanted_ids, wanted_rvas, wanted_names = _wanted_method_links(cards)
    by_id, by_rva, by_name, method_catalog_rows = _method_index(
        root / "analysis.methods.jsonl", wanted_ids, wanted_rvas, wanted_names
    )
    rows: list[dict[str, Any]] = []
    exact = 0
    for card in cards:
        if not isinstance(card, dict):
            continue
        loc = _locator(card)
        link_status, methods = _link_methods(loc, by_id, by_rva, by_name)
        if link_status != "UNRESOLVED":
            exact += 1
        rows.append({
            "id": card.get("id"),
            "title": card.get("title"),
            "status": card.get("status"),
            "verificationStage": card.get("verificationStage"),
            "category": card.get("category"),
            "ownership": card.get("ownership"),
            "buildable": bool(card.get("buildable")),
            "actionable": bool(card.get("actionable")),
            "serverAudit": bool(card.get("serverAudit")),
            "locator": loc,
            "methodLinkStatus": link_status,
            "linkedMethods": methods,
            "description": card.get("description"),
        })
    coverage = _engine_coverage(root, embedded, artifact_families)
    available_engines = sum(1 for row in coverage if row.get("available"))
    evidence_guide = _artifact_guide(root)
    out = {
        "schema": SCHEMA,
        "findingCount": len(rows),
        "exactLinked": exact,
        "unresolvedLinks": len(rows) - exact,
        "methodCatalogRows": method_catalog_rows,
        "methodIndexPolicy": {
            "storage": "STREAMED_RELEVANT_ROWS_ONLY",
            "retainedMethodIds": len(by_id),
            "retainedRvaBuckets": len(by_rva),
            "retainedNameBuckets": len(by_name),
            "maxRowsPerRvaOrName": 25,
            "loadsFullMethodCatalogIntoRam": False,
        },
        "summary": {
            "targetProfile": analysis.get("targetProfile"),
            "total": catalog.get("total", 0),
            "important": catalog.get("important", 0),
            "buildable": catalog.get("buildable", 0),
            "actionable": catalog.get("actionable", 0),
            "serverAudit": catalog.get("serverAudit", 0),
            "deepEnginesAvailable": available_engines,
            "deepEngineCount": len(coverage),
        },
        "embedded": {
            "apktool": {"status": apktool.get("status"), "decoded": apktool.get("decoded"), "failed": apktool.get("failed")},
            "pipelineSchema": embedded.get("schema"),
            "runs": embedded.get("runs") if isinstance(embedded.get("runs"), list) else [],
            "familyCounts": artifact_families.get("familyCounts"),
            "recoveryCounts": artifact_families.get("recoveryCounts"),
            "manualImportRequired": False,
        },
        "engineCoverage": coverage,
        "artifactGuide": evidence_guide,
        "securitySummary": security.get("summary") or security.get("counts"),
        "findings": rows,
        "evidenceSemantics": {
            "EXACT_METHOD_ID": "Finding references an exact method id from the method catalogue.",
            "EXACT_RVA": "Finding RVA equals a catalogue method RVA; this is static address evidence, not runtime execution proof.",
            "EXACT_NAME": "Finding method name exactly matches catalogue rows; overloaded/duplicate names may yield multiple rows.",
            "UNRESOLVED": "No exact method id/RVA/name correlation was proven.",
            "runtimeTruth": "Static reports never claim that a code path executed on-device unless a separate runtime session observed it.",
        },
    }
    if output_json:
        Path(output_json).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    if output_md:
        md = [
            "# ModKit connected report",
            "",
            f"Findings: {len(rows)}",
            f"Exact method/locator links: {exact}",
            f"Unresolved links: {len(rows)-exact}",
            f"Deep engines available: {available_engines}/{len(coverage)}",
            "",
            "## Deep engine coverage",
            "",
        ]
        for engine in coverage:
            state = "available" if engine.get("available") else "not detected / unavailable"
            extras = []
            for key in ("findingCount", "chunkCount", "decodedChunks", "opaqueChunks", "libraryCount", "directCallCount", "tailCallCount", "indirectSlotCount", "correlationCount", "bridgeSymbolCount", "bundleCount", "artifactCount"):
                if key in engine:
                    extras.append(f"{key}={engine.get(key)}")
            md.append(f"- **{engine.get('engineId')}** — {state} · report `{engine.get('report')}`" + (" · " + ", ".join(extras) if extras else ""))
        md += ["", "## Где что смотреть", ""]
        for item in evidence_guide:
            if not item.get("available"):
                continue
            md.append(f"- **`{item.get('file')}`** — {item.get('purpose')}. {item.get('whenToUse')}")
        md += [
            "",
            "## Findings",
            "",
            "> Static exact RVA/method links are evidence of address/identity correlation, not proof that the path executed at runtime.",
            "",
        ]
        for row in rows:
            md.append(f"### {row.get('title') or 'Finding'}")
            md.append(f"- Status: {row.get('status')}")
            md.append(f"- Verification: {row.get('verificationStage')}")
            md.append(f"- Link: {row.get('methodLinkStatus')}")
            loc = row.get("locator") or {}
            if loc:
                md.append("- Locator: " + ", ".join(f"{k}={v}" for k, v in loc.items()))
            for method in row.get("linkedMethods") or []:
                label = _first(method, "label", "name", "method", "methodName")
                rva = _norm_hex(_first(method, "rva", "address"))
                md.append(f"  - Method: {label or '?'}" + (f" @ {rva}" if rva else ""))
            if row.get("description"):
                md.append(f"- {row['description']}")
            md.append("")
        Path(output_md).write_text("\n".join(md), encoding="utf-8")
    return out