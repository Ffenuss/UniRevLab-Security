"""Cross-artifact correlation for APK/DEX/Unity/IL2CPP/native evidence.

This module does not claim that a string match is a working modification.  It
keeps provenance and promotes a finding only when independent evidence agrees.
"""
from __future__ import annotations

from collections import defaultdict
from bisect import bisect_right
from dataclasses import dataclass, asdict
import hashlib
import os
import math
import mmap
from pathlib import Path
import re
import shutil
import tempfile
import zipfile

from modkit.elf.reader import ElfFile
from modkit.reworkspace.native import direct_bl_calls
from modkit.reworkspace.trust import SURFACE_NAMES
from modkit.reworkspace.schema import ensure_report_contract
from modkit.reworkspace.artifact_scan import Evidence, scan_artifact, matches

@dataclass(slots=True)
class Finding:
    id: str
    title: str
    category: str
    status: str
    confidence: float
    evidence: list[Evidence]
    rationale: str

    def json(self) -> dict:
        d = asdict(self)
        return d


def _normalized_words(value: str) -> tuple[set[str], str, str]:
    text = str(value or "").replace("\\", "/")
    camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    words = re.findall(r"[a-z0-9]+", camel.casefold())
    return set(words), "".join(words), text.casefold()


def _is_high_signal_surface_evidence(category: str, e: Evidence) -> bool:
    """Whether evidence is specific enough to promote control/hook surfaces.

    Generic words such as ``debug``, ``speed`` or ``overlay`` are common in
    Unity and Android frameworks. They remain inventory evidence, but cannot by
    themselves promote an actionable developer/gameplay surface.
    """
    words, compact, low = _normalized_words(e.value)
    if category == "menu_overlay":
        if any(x in compact for x in ("modmenu", "cheatmenu", "debugmenu", "canvascheat", "developermenu")):
            return True
        return "overlay" in words and bool(words & {"developer", "debug", "cheat"})
    if category == "debug_console":
        return any(x in compact for x in (
            "debugconsole", "developerconsole", "toggleconsole", "consolewindow", "debugonkey", "cheatconsole",
        ))
    if category == "gameplay_controls":
        if "unityengine.rendering" in low or "rendering/debug" in low:
            return False
        if any(x in compact for x in ("godmode", "invincible", "noclip", "cheatmode", "levelup")):
            return True
        # Ordinary health/speed/damage names are ubiquitous. Require explicit
        # developer/cheat context before promoting them.
        return "cheat" in words and bool(words & {"health", "damage", "stamina", "mana", "money", "gold", "level", "weather", "speed", "crit", "critical"})
    if category == "hook_framework":
        if e.kind not in {"native-string", "native-symbol", "DT_NEEDED"}:
            return False
        return any(x in compact for x in ("dobbyhook", "mshookfunction", "a64hookfunction", "inlinehook", "hookfunction"))
    return True


def _is_category_noise(category: str, value: str, kind: str) -> bool:
    words, compact, low = _normalized_words(value)
    if category == "menu_overlay" and any(x in low for x in ("floatingactionbutton", "com/google/android/material", "androidx/", "androidx.", "mode_menu")):
        return True
    if category == "debug_console" and any(x in low for x in (
        "unityengine.rendering.debug", "rendering/debug", "debugprobes", "debugmetadata", ".debug_info", ".debug_line", ".debug_str",
    )):
        return True
    if category == "gameplay_controls":
        if "noclipping" in compact:
            return True
        if "render" in words and ("unityengine.rendering" in low or "rendering/debug" in low):
            return True
    if category == "hook_framework" and "shadowhook" in compact and kind in {"dex-string", "dex-class"}:
        # Presence of the Java wrapper is dependency evidence, not proof that an
        # app-specific native hook is actually configured.
        return True
    return False


def _scan_items_bounded(items):
    """Scan small immutable members concurrently without overlapping large ELF.

    mmap-backed members and every native library are scanned synchronously while
    their source is guaranteed alive. Only small byte-backed DEX/config artifacts
    are queued, with a tiny pending window, so parallelism cannot recreate the
    pre-dev33 peak-memory behaviour.
    """
    from concurrent.futures import ThreadPoolExecutor

    try:
        configured = int(os.environ.get("MODKIT_RE_WORKERS", "2") or "2")
    except ValueError:
        configured = 2
    workers = max(1, min(2, configured))
    max_parallel_bytes = 8 * 1024 * 1024
    max_pending = workers * 2
    results = []
    pending = []
    diag = {
        "schema": "modkit-artifact-scan-1",
        "workers": workers,
        "parallelEligible": 0,
        "parallelSubmitted": 0,
        "synchronous": 0,
        "nativeSynchronous": 0,
        "mmapSynchronous": 0,
        "maxPending": 0,
        "parallelByteCap": max_parallel_bytes,
    }

    def harvest_one():
        seq, future = pending.pop(0)
        results.append((seq, future.result()))

    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="modkit-re") if workers > 1 else None
    try:
        for seq, (name, blob) in enumerate(items):
            size = len(blob)
            low = str(name).lower()
            is_mapped = isinstance(blob, mmap.mmap)
            synchronous = is_mapped or low.endswith(".so") or size > max_parallel_bytes or executor is None
            if synchronous:
                diag["synchronous"] += 1
                if low.endswith(".so"):
                    diag["nativeSynchronous"] += 1
                if is_mapped:
                    diag["mmapSynchronous"] += 1
                results.append((seq, scan_artifact(name, blob)))
                continue
            diag["parallelEligible"] += 1
            pending.append((seq, executor.submit(scan_artifact, name, blob)))
            diag["parallelSubmitted"] += 1
            diag["maxPending"] = max(diag["maxPending"], len(pending))
            if len(pending) >= max_pending:
                harvest_one()
        while pending:
            harvest_one()
    finally:
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=False)
    results.sort(key=lambda x: x[0])
    return [item for _seq, item in results], diag


def analyze_artifacts(artifacts) -> dict:
    inventories = {"dex": [], "native": [], "other": []}
    by_category: dict[str, list[Evidence]] = defaultdict(list)
    category_artifacts: dict[str, set[str]] = defaultdict(set)
    promotion_by_category: dict[str, list[Evidence]] = defaultdict(list)
    dex_classes: dict[str, list[str]] = {}
    dex_strings: dict[str, set[str]] = {}
    dex_trust_rows: list[dict] = []
    dex_trust_errors: list[dict] = []

    items = artifacts.items() if hasattr(artifacts, "items") else artifacts
    scanned, scan_diag = _scan_items_bounded(items)
    for item in scanned:
        name = item.name
        if item.kind == "dex":
            dex_classes[name] = list(item.classes or [])
            dex_strings[name] = set(item.strings or set())
            inventories["dex"].append(item.inventory)
            if len(dex_trust_rows) < 2400:
                remaining = 2400 - len(dex_trust_rows)
                dex_trust_rows.extend((item.trust_rows or [])[:remaining])
            dex_trust_errors.extend(item.trust_errors or [])
        elif item.kind == "native":
            inventories["native"].append(item.inventory)
        else:
            inventories["other"].append(item.inventory)

        for e in item.evidence:
            # Per-artifact scanning carries an artifact-wide category set;
            # match the individual evidence value before applying centralized
            # noise/promotion policy.
            for cat in item.categories:
                # Only attach evidence to categories it actually matches. Some
                # artifacts have several independent categories.
                if cat not in matches(e.value):
                    continue
                if _is_category_noise(cat, e.value, e.kind):
                    continue
                by_category[cat].append(e)
                category_artifacts[cat].add(name)
                if _is_high_signal_surface_evidence(cat, e):
                    promotion_by_category[cat].append(e)

    # Cross-artifact promotion.  A single string remains a candidate; two
    # independent files/kinds can establish a correlated/confirmed surface.
    findings: list[Finding] = []
    titles = {
        "menu_overlay": "Embedded Android overlay/menu framework",
        "debug_console": "Developer/debug control surface",
        "gameplay_controls": "Gameplay control surface",
        "monetization_surface": "Purchase/entitlement trust surface",
        "hook_framework": "Native hook framework",
        "il2cpp_surface": "IL2CPP native/metadata surface",
        "anti_cheat_surface": "Anti-cheat / defensive data surface",
    }
    high_signal_categories = {"gameplay_controls", "menu_overlay", "hook_framework", "debug_console"}
    for cat, evs in by_category.items():
        promotion_evs = promotion_by_category.get(cat, []) if cat in high_signal_categories else evs
        artifacts_n = len({e.artifact for e in promotion_evs})
        kinds = {e.kind for e in promotion_evs}
        if cat in high_signal_categories and not promotion_evs:
            # Generic words remain inventory evidence but are not promoted into
            # an actionable developer/gameplay/hook surface.
            status, confidence = "candidate", 0.38
        elif artifacts_n >= 2 and len(kinds) >= 2:
            status, confidence = "confirmed", min(0.98, 0.80 + 0.02 * min(len(promotion_evs), 9))
        elif artifacts_n >= 2 or len(kinds) >= 2:
            status, confidence = "correlated", 0.72
        else:
            status, confidence = "candidate", 0.48
        # Keep the report bounded but retain the strongest heterogeneous evidence.
        selected = []
        used = set()
        for e in evs:
            key = (e.artifact, e.kind, e.value)
            if key in used:
                continue
            used.add(key); selected.append(e)
            if len(selected) >= 40:
                break
        findings.append(Finding(
            f"re.{cat}", titles.get(cat, cat), cat, status, confidence, selected,
            f"{artifacts_n} high-signal artifact(s), {len(kinds)} promotion evidence kind(s); status is evidence-strength, not proof of runtime behavior.",
        ))

    # Strong composition finding: menu + hooks + IL2CPP across the same pack.
    if (promotion_by_category.get("menu_overlay") and promotion_by_category.get("hook_framework")
            and by_category.get("il2cpp_surface")):
        evs = []
        for cat in ("menu_overlay", "hook_framework", "il2cpp_surface"):
            evs.extend(by_category[cat][:12])
        findings.append(Finding(
            "re.native_menu_il2cpp", "Native menu/hook stack connected to IL2CPP",
            "cross_artifact", "confirmed", 0.94, evs,
            "Independent DEX/native menu, hook-framework and IL2CPP evidence are present in the analyzed artifact set.",
        ))

    if all(promotion_by_category.get(x) for x in ("menu_overlay", "debug_console", "gameplay_controls")):
        evs = []
        for cat in ("menu_overlay", "debug_console", "gameplay_controls"):
            evs.extend(by_category[cat][:12])
        findings.append(Finding(
            "re.developer_gameplay_surface", "Developer/debug/gameplay control surface",
            "cross_artifact", "confirmed", 0.93, evs,
            "Overlay/menu evidence is correlated with explicit debug-console and gameplay-control markers. Review provenance to determine whether it is developer tooling, a bundled test menu, or a third-party overlay.",
        ))

    native_by_base: dict[str, list[dict]] = defaultdict(list)
    native_by_name: dict[str, dict] = {}
    for row in inventories["native"]:
        row_name = str(row.get("name", ""))
        native_by_name[row_name] = row
        native_by_base[Path(row_name).name].append(row)
    dependency_edges = []
    external_dependencies = []
    jni_surfaces = []
    dynamic_loaders = []
    render_surfaces = []
    native_string_edges = []
    native_symbol_edges = []
    dynamic_symbol_edges = []
    jni_direct_calls = []
    jni_call_chains = []
    dex_native_links = []
    for row in inventories["native"]:
        host = str(row.get("name", ""))
        for dep in row.get("needed", []) or []:
            targets = native_by_base.get(str(dep), [])
            if targets:
                for target in targets[:4]:
                    dependency_edges.append({"from": host, "to": str(target.get("name", dep)), "kind": "DT_NEEDED"})
            else:
                external_dependencies.append({"from": host, "dependency": str(dep)})
        for ref in row.get("libraryStringRefs", []) or []:
            targets = native_by_base.get(str(ref), [])
            for target in targets[:4]:
                target_name = str(target.get("name", ref))
                if target_name != host:
                    native_string_edges.append({"from": host, "to": target_name, "kind": "embedded-library-string", "value": ref})
        jni = row.get("jni") or {}
        if jni.get("hasJniOnLoad") or jni.get("exports") or jni.get("importsRegisterNatives"):
            jni_surfaces.append({"artifact": host, **jni})
        markers = set(row.get("nativeApiMarkers") or [])
        if markers & {"dlopen", "android_dlopen_ext", "dlsym"}:
            dynamic_loaders.append({"artifact": host, "apis": sorted(markers & {"dlopen", "android_dlopen_ext", "dlsym"})})
        if markers & {"eglSwapBuffers", "AMotionEvent_getAction"}:
            render_surfaces.append({"artifact": host, "apis": sorted(markers & {"eglSwapBuffers", "AMotionEvent_getAction"})})
        calls = row.get("directFunctionCalls", []) or []
        for call in calls:
            src = str(call.get("sourceFunction") or "")
            if src == "JNI_OnLoad" or src.startswith("Java_"):
                jni_direct_calls.append({"artifact": host, **call})
        # Follow only already-resolved named direct BL edges, max depth 4.
        by_source: dict[int, list[dict]] = defaultdict(list)
        roots = []
        for call in calls:
            sr = call.get("sourceRva")
            if isinstance(sr, int):
                by_source[sr].append(call)
            src = str(call.get("sourceFunction") or "")
            if (src == "JNI_OnLoad" or src.startswith("Java_")) and isinstance(sr, int):
                roots.append((sr, src))
        for root_rva, root_name in list(dict.fromkeys(roots))[:32]:
            queue = [(root_rva, root_name, [{"name": root_name, "rva": root_rva}], [], 0)]
            seen_paths = 0
            while queue and seen_paths < 80:
                current_rva, current_name, funcs_path, calls_path, depth = queue.pop(0)
                if depth >= 4:
                    continue
                for edge in by_source.get(current_rva, [])[:24]:
                    tr = edge.get("targetRva")
                    tn = str(edge.get("targetFunction") or "")
                    if not isinstance(tr, int) or not tn:
                        continue
                    if any(x.get("rva") == tr for x in funcs_path):
                        continue
                    new_funcs = funcs_path + [{"name": tn, "rva": tr}]
                    new_calls = calls_path + [int(edge.get("callRva") or 0)]
                    jni_call_chains.append({"artifact": host, "root": root_name, "functions": new_funcs, "callRvas": new_calls, "depth": depth + 1})
                    seen_paths += 1
                    if depth + 1 < 4:
                        queue.append((tr, tn, new_funcs, new_calls, depth + 1))
                    if seen_paths >= 80:
                        break

    # Function-level SO↔SO linkage from exact imported/exported dynamic symbols.
    export_index: dict[str, list[str]] = defaultdict(list)
    for row in inventories["native"]:
        host = str(row.get("name", ""))
        for symbol in (row.get("linkingSymbols") or {}).get("exports", []) or []:
            export_index[str(symbol)].append(host)
    for row in inventories["native"]:
        host = str(row.get("name", ""))
        for symbol in (row.get("linkingSymbols") or {}).get("imports", []) or []:
            for target in export_index.get(str(symbol), [])[:8]:
                if target == host:
                    continue
                target_row = native_by_name.get(target)
                target_rva = ((target_row or {}).get("linkingSymbols") or {}).get("exportRvas", {}).get(str(symbol))
                native_symbol_edges.append({
                    "from": host, "to": target, "kind": "import-export-symbol",
                    "symbol": str(symbol), "targetRva": target_rva, "confidence": 0.96,
                    "rationale": "Source ELF imports an exact dynamic symbol exported by the target ELF.",
                })

    # dlsym-based links are weaker: require both a packaged downstream-library
    # relation and a string equal to an exported target symbol. This does not claim
    # that the string reaches dlsym at runtime.
    string_edge_pairs = {(str(x.get("from", "")), str(x.get("to", ""))) for x in native_string_edges}
    for row in inventories["native"]:
        host = str(row.get("name", ""))
        if "dlsym" not in set(row.get("nativeApiMarkers") or []):
            continue
        refs = set(row.get("symbolStringRefs") or [])
        own = set((row.get("linkingSymbols") or {}).get("imports", []) or []) | set((row.get("linkingSymbols") or {}).get("exports", []) or [])
        refs -= own
        refs = {x for x in refs if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,79}", x) and not x.startswith("_Z") and x not in {"JNI_OnLoad", "JNIEnv", "JavaVM"}}
        if not refs:
            continue
        for target_row in inventories["native"]:
            target = str(target_row.get("name", ""))
            if target == host or (host, target) not in string_edge_pairs:
                continue
            target_exports = set((target_row.get("linkingSymbols") or {}).get("exports", []) or [])
            for symbol in sorted(refs & target_exports)[:80]:
                target_rva = ((target_row.get("linkingSymbols") or {}).get("exportRvas") or {}).get(symbol)
                dynamic_symbol_edges.append({
                    "from": host, "to": target, "kind": "dlsym-string-export",
                    "symbol": symbol, "targetRva": target_rva, "confidence": 0.78,
                    "rationale": "Source contains dlsym, references the target library and embeds an exact exported symbol name; runtime data flow is not claimed.",
                })

    for edge in dynamic_symbol_edges:
        row = native_by_name.get(str(edge.get("from", "")))
        if not row:
            continue
        loc = next((x for x in row.get("symbolStringLocations", []) or [] if str(x.get("value", "")) == str(edge.get("symbol", ""))), None)
        if loc:
            edge["stringRva"] = loc.get("rva")
            edge["stringFileOffset"] = loc.get("fileOffset")
            edge["stringSection"] = loc.get("section")
            xrefs = [x for x in row.get("stringAddressXrefs", []) or [] if x.get("targetRva") == loc.get("rva")]
            if xrefs:
                edge["staticStringXrefs"] = xrefs[:16]
                edge["confidence"] = max(float(edge.get("confidence", 0.0)), 0.88)
                edge["rationale"] = (str(edge.get("rationale", "")) + " ARM64 ADRP+ADD also materializes this exact string address in code; runtime dlsym data flow is still not claimed.")

    for dex_name, strings in dex_strings.items():
        lower = {x.casefold() for x in strings}
        has_loader = "loadlibrary" in lower or "system.loadlibrary" in lower
        for base, targets in native_by_base.items():
            if not (base.startswith("lib") and base.endswith(".so")):
                continue
            stem = base[3:-3]
            if base.casefold() not in lower and stem.casefold() not in lower:
                continue
            for target in targets[:4]:
                jni = target.get("jni") or {}
                dex_native_links.append({
                    "from": dex_name, "to": str(target.get("name", base)),
                    "kind": "dex-library-name", "library": base, "stem": stem,
                    "loadLibraryMarker": has_loader, "jniOnLoad": bool(jni.get("hasJniOnLoad")),
                    "confidence": 0.92 if has_loader and jni.get("hasJniOnLoad") else (0.84 if has_loader else 0.66),
                    "rationale": ("DEX contains a matching library-name string and loadLibrary marker; target ELF exports JNI_OnLoad."
                                  if has_loader and jni.get("hasJniOnLoad") else
                                  "Static name correlation only; call-site association is not claimed."),
                })

    native_relations = {
        "schema": "modkit-native-relations-1.2",
        "libraries": len(inventories["native"]),
        "dependencyEdges": dependency_edges[:400],
        "embeddedLibraryStringEdges": native_string_edges[:400],
        "symbolEdges": native_symbol_edges[:800],
        "dynamicSymbolEdges": dynamic_symbol_edges[:400],
        "dexNativeLinks": dex_native_links[:200],
        "externalDependencies": external_dependencies[:400],
        "jniSurfaces": jni_surfaces[:80],
        "jniDirectCallRefs": jni_direct_calls[:400],
        "jniCallChains": jni_call_chains[:800],
        "dynamicLoadingSurfaces": dynamic_loaders[:80],
        "renderInputSurfaces": render_surfaces[:80],
    }

    if native_symbol_edges:
        evs = [Evidence(str(x.get("from", "")), "native-import-export", str(x.get("symbol", "")), str(x.get("to", "")))
               for x in native_symbol_edges[:40]]
        findings.append(Finding(
            "re.native_import_export_bridge", "Cross-library native function linkage", "native_function_bridge",
            "confirmed", 0.96, evs,
            "One packaged ELF imports exact dynamic symbol names exported by another packaged ELF. This is static linker evidence, not runtime execution proof.",
        ))

    scoped_dynamic = [x for x in dynamic_symbol_edges if x.get("staticStringXrefs")]
    if scoped_dynamic:
        evs = []
        for edge in scoped_dynamic[:20]:
            for xref in (edge.get("staticStringXrefs") or [])[:2]:
                src = str(xref.get("sourceFunction") or f"sub_{int(xref.get('xrefRva') or 0):x}")
                evs.append(Evidence(str(edge.get("from", "")), "native-dlsym-string-xref",
                                    f"{src} -> {edge.get('symbol', '')}",
                                    f"{edge.get('to', '')}; string RVA 0x{int(edge.get('stringRva') or 0):x}"))
        findings.append(Finding(
            "re.native_dynamic_symbol_bridge", "Function-scoped dynamic native symbol bridge", "native_function_bridge",
            "correlated", 0.90, evs[:40],
            "A function statically materializes an exact symbol-name string while its ELF exposes dlsym and references a packaged library exporting that symbol. This narrows the loader path but does not prove the string is passed to dlsym at runtime.",
        ))

    strong_dex_native = [x for x in dex_native_links if x.get("loadLibraryMarker") and x.get("jniOnLoad")]
    if strong_dex_native:
        chain_evidence: list[Evidence] = []
        for link in strong_dex_native[:8]:
            chain_evidence.append(Evidence(str(link.get("from", "DEX")), "dex-native-link",
                                           str(link.get("library", "")), str(link.get("to", ""))))
        strong_targets = {str(x.get("to", "")) for x in strong_dex_native}
        for edge in native_string_edges[:24]:
            if str(edge.get("from", "")) in strong_targets:
                chain_evidence.append(Evidence(str(edge.get("from", "")), "embedded-library-reference",
                                               str(edge.get("value", "")), str(edge.get("to", ""))))
        for row in dynamic_loaders[:16]:
            if str(row.get("artifact", "")) in strong_targets:
                chain_evidence.append(Evidence(str(row.get("artifact", "")), "dynamic-loader-api",
                                               ", ".join(row.get("apis") or []), ""))
        extended = len(chain_evidence) > len(strong_dex_native)
        findings.append(Finding(
            "re.dex_native_loader_bridge", "DEX-to-native loader bridge", "dex_native_bridge",
            "confirmed" if extended else "correlated", 0.97 if extended else 0.91, chain_evidence[:40],
            ("DEX contains a matching library-name plus loadLibrary marker and the target ELF exports JNI_OnLoad; "
             + ("the native library also exposes a static downstream library/dynamic-loader link. " if extended else "")
             + "This confirms a packaged loader relationship, not execution of any specific native function."),
        ))

    def dex_surface(surface: str) -> dict:
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
        local_authority = ("possible-local" if any(x.get("localAuthority") == "possible-local" for x in app) else
                           "not-confirmed" if boundary in {"server-backed", "platform-backed"} and app else "unknown")
        return {
            "methods": rows[:120], "totalMatches": len(rows), "applicationMatches": len(app),
            "trustBoundaries": sorted({str(x.get("trustBoundary", "unknown")) for x in rows}),
            "presenceConfidence": round(max((float(x.get("presenceConfidence", 0.0)) for x in rows), default=0.0), 2),
            "behaviorConfidence": round(max((float(x.get("behaviorConfidence", 0.0)) for x in rows), default=0.0), 2),
            "trustBoundary": boundary, "localAuthority": local_authority,
        }

    return ensure_report_contract({
        "inventory": inventories,
        "nativeRelations": native_relations,
        "dexClasses": dex_classes,
        "dexTrust": {
            "schema": "modkit-dex-trust-2", "methodsScanned": len(dex_trust_rows),
            "errors": dex_trust_errors[:80],
            "surfaceNames": SURFACE_NAMES,
            "surfaces": {surface: dex_surface(surface) for surface in SURFACE_NAMES},
        },
        "findings": [f.json() for f in sorted(findings, key=lambda x: (-x.confidence, x.id))],
        "artifactScanDiagnostics": scan_diag,
    })


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def correlate_apk(apk_path: str | Path, extra_paths: list[str | Path] | None = None,
                  *, apk_sha256: str | None = None) -> dict:
    """Correlate a plain APK or APK-set/XAPK with bounded peak memory.

    Dev33 streams nested APK members into a spooled file instead of materialising
    the entire nested APK as ``bytes``. Large ELF members are extracted to a
    temporary file and exposed to the scanner through a read-only mmap for the
    duration of exactly one artifact.  This keeps the existing sequential
    evidence semantics while removing the largest avoidable APK-set/ELF copies.
    """
    apk_path = Path(apk_path)
    skipped: list[dict] = []
    nested_apks: list[dict] = []
    duplicates: list[dict] = []
    seen_apk_hashes: set[str] = set()
    deduplicated_artifacts = 0
    stream_diag = {
        "schema": "modkit-streaming-diagnostics-1",
        "nestedApksStreamed": 0,
        "nestedBytesStreamed": 0,
        "nestedApksRolledToDisk": 0,
        "mappedElfArtifacts": 0,
        "mappedElfBytes": 0,
        "largeElfThresholdBytes": 8 * 1024 * 1024,
        "spoolMemoryThresholdBytes": 8 * 1024 * 1024,
    }

    def interesting(name: str) -> bool:
        low = name.lower()
        return (low.endswith(".dex") or low.endswith(".so") or "global-metadata" in low
                or low.endswith((".json", ".txt", ".xml")))

    def retain(name: str, size: int) -> tuple[bool, int]:
        low = name.lower()
        cap = 512 * 1024 * 1024 if low.endswith(".so") else 128 * 1024 * 1024
        return size <= cap, cap

    def scan_zip(z: zipfile.ZipFile, prefix: str = ""):
        nonlocal deduplicated_artifacts
        for info in z.infolist():
            if not interesting(info.filename):
                continue
            ok, cap = retain(info.filename, info.file_size)
            shown = f"{prefix}{info.filename}" if prefix else info.filename
            if not ok:
                skipped.append({"artifact": shown, "size": info.file_size,
                                "reason": f"bounded scanner cap {cap} bytes"})
                continue
            deduplicated_artifacts += 1
            low = info.filename.lower()
            if low.endswith(".so") and info.file_size >= stream_diag["largeElfThresholdBytes"]:
                with tempfile.TemporaryFile(prefix="modkit-elf-") as tmp:
                    with z.open(info, "r") as src:
                        shutil.copyfileobj(src, tmp, length=1024 * 1024)
                    tmp.flush(); tmp.seek(0)
                    with mmap.mmap(tmp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        stream_diag["mappedElfArtifacts"] += 1
                        stream_diag["mappedElfBytes"] += info.file_size
                        yield shown, mm
            else:
                yield shown, z.read(info)

    def iter_artifacts():
        with zipfile.ZipFile(apk_path) as outer:
            names = [x.filename for x in outer.infolist()]
            is_plain_apk = any(x == "AndroidManifest.xml" for x in names) and any(
                x.endswith(".dex") or x.startswith("lib/") for x in names)
            if is_plain_apk:
                seen_apk_hashes.add(apk_sha256 or _sha256_file(apk_path))
                yield from scan_zip(outer)
            else:
                for info in outer.infolist():
                    if not info.filename.lower().endswith(".apk"):
                        continue
                    if info.file_size > 768 * 1024 * 1024:
                        skipped.append({"artifact": info.filename, "size": info.file_size,
                                        "reason": "nested APK cap 805306368 bytes"})
                        continue
                    h = hashlib.sha256()
                    with tempfile.SpooledTemporaryFile(
                            max_size=stream_diag["spoolMemoryThresholdBytes"],
                            mode="w+b", prefix="modkit-nested-apk-") as payload:
                        with outer.open(info, "r") as src:
                            while True:
                                chunk = src.read(1024 * 1024)
                                if not chunk:
                                    break
                                h.update(chunk); payload.write(chunk)
                        digest = h.hexdigest()
                        stream_diag["nestedApksStreamed"] += 1
                        stream_diag["nestedBytesStreamed"] += info.file_size
                        if bool(getattr(payload, "_rolled", False)):
                            stream_diag["nestedApksRolledToDisk"] += 1
                        if digest in seen_apk_hashes:
                            duplicates.append({"apk": info.filename, "sha256": digest})
                            continue
                        seen_apk_hashes.add(digest)
                        nested_apks.append({"apk": info.filename, "sha256": digest, "size": info.file_size})
                        payload.seek(0)
                        try:
                            with zipfile.ZipFile(payload) as nested:
                                yield from scan_zip(nested, f"{info.filename}!")
                        except zipfile.BadZipFile as exc:
                            skipped.append({"artifact": info.filename, "size": info.file_size,
                                            "reason": f"invalid nested APK: {exc}"})
        for path in extra_paths or []:
            p = Path(path)
            if not p.is_file():
                continue
            cap = 512 * 1024 * 1024 if p.suffix.lower() == ".so" else 256 * 1024 * 1024
            size = p.stat().st_size
            if size > cap:
                skipped.append({"artifact": str(p), "size": size,
                                "reason": f"bounded scanner cap {cap} bytes"})
                continue
            if p.suffix.lower() == ".so" and size >= stream_diag["largeElfThresholdBytes"]:
                with p.open("rb") as fh:
                    with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        stream_diag["mappedElfArtifacts"] += 1
                        stream_diag["mappedElfBytes"] += size
                        yield f"extra/{p.name}", mm
            else:
                yield f"extra/{p.name}", p.read_bytes()

    result = analyze_artifacts(iter_artifacts())
    result["apk"] = {"path": str(apk_path), "sha256": apk_sha256 or _sha256_file(apk_path),
                     "kind": "apk-set" if nested_apks else "apk"}
    result["nestedApks"] = nested_apks
    result["duplicates"] = duplicates
    result["deduplicatedArtifacts"] = deduplicated_artifacts
    result["memoryModel"] = "sequential-artifact-scan+spooled-nested-apk+mmap-large-elf"
    result["streamingDiagnostics"] = stream_diag
    result["skippedArtifacts"] = skipped
    return ensure_report_contract(result)


_CONTROL_MARKER = re.compile(
    r"(?i)(cheat|debug|console|god|invic|noclip|health|damage|stamina|mana|money|gold|level|xp|experience|unlock|quest|weather|speed|state|mode|status|freeze|frozen|pause|crit|rva[_ -]|developer)"
)


def _candidate_title(value: str) -> str:
    text = str(value).strip().replace("\\", "/")
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    text = re.sub(r"\.(png|jpg|jpeg|asset|prefab|unity)$", "", text, flags=re.I)
    text = re.sub(r"^PPtr<\$|>$", "", text)
    text = re.sub(r"[_-]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip(" +:-")
    return text[:120]


def _suggested_control(value: str) -> str:
    text = str(value)
    low = text.casefold()
    if re.search(r"(?i)::(?:\.ctor|\.cctor|update|lateupdate|awake|start|reset|onenable|ondisable|ondestroy|movenext|setstatemachine)\(", text):
        return "review"
    # A method-shaped action is safer to present as a button suggestion than as a
    # bool setter: Toggle*/Activate*/Enable* does not imply a bool parameter.
    if re.search(r"(?i)::(?:toggle|activate|deactivate|enable|disable|show|hide|spawn|give|teleport|port)[A-Za-z0-9_]*\(", text):
        return "button"
    if re.search(r"(?i)::(?:get_|get|is|has)[A-Za-z0-9_]*\(", text):
        return "review"
    if any(x in low for x in ("noclip", "invic", "god", "cheat mode", "infinite")):
        return "toggle"
    if any(x in low for x in ("action", "levelup", "weather", "equip", "console")):
        return "button"
    if any(x in low for x in ("damage", "health", "money", "mana", "stamina", "speed", "crit")):
        return "slider_or_toggle"
    return "review"


def derive_control_candidates(report: dict, limit: int = 200) -> list[dict]:
    """Extract reviewable menu/control candidates with provenance.

    This deliberately does *not* bind or call an address.  Even native symbols
    named like RVA_* may be configuration/storage symbols rather than the target
    function itself, so their address is retained only as evidenceRva.
    """
    out: list[dict] = []
    seen: dict[str, int] = {}

    def add(value: str, source: str, kind: str, location: str = "", confidence: float = 0.55,
            contract: dict | None = None, resolver: dict | None = None, verification: dict | None = None):
        from modkit.reworkspace.method_evidence import structurally_actionable
        if not value:
            return
        verification = dict(verification or {})
        generic_structural = bool(
            verification.get("addressConfirmed")
            and structurally_actionable(value, contract or {})
        )
        # Legacy/string evidence still needs semantic control markers. Address-
        # confirmed metadata callables may enter by generic API morphology alone.
        if not _CONTROL_MARKER.search(value) and not generic_structural:
            return
        # Keep collection bounded, but do not use the user-visible limit as an
        # early cutoff: stronger evidence sources are merged and globally ranked
        # before the final slice.
        if len(out) >= max(800, int(limit) * 8):
            return
        title = _candidate_title(value)
        if len(title) < 3:
            return
        key = re.sub(r"[^a-z0-9]+", "", title.casefold())
        if not key:
            return
        # Avoid ordinary game UI art unless it explicitly belongs to debug/cheat tooling.
        low = value.casefold()
        if low.startswith(".debug") or low in {"debug_abbrev", "debug_info", "debug_line", "debug_loc", "debug_ranges", "debug_str"}:
            return
        if (low.endswith((".png", ".jpg", ".jpeg")) or "/gui/" in low) and not any(x in low for x in ("cheat", "debug", "console")):
            return
        evidence_rva = None
        m = re.fullmatch(r"RVA\s+0x([0-9a-fA-F]+)", location.strip())
        if m:
            evidence_rva = int(m.group(1), 16)
        score = float(confidence)
        if verification:
            score = max(score, float(verification.get("structuralConfidence") or 0.0))
            if verification.get("addressConfirmed"):
                score += 0.03
            if verification.get("relationStatus") == "confirmed-static-xref":
                score += 0.04
            if verification.get("contextStatus") == "corroborated-static-context":
                score += 0.03
        low_compact = re.sub(r"[^a-z0-9]+", "", low)
        if any(x in low for x in ("cheat_", "canvas_cheat", "rva_")):
            score += 0.24
        elif "cheat " in low or "cheatgamehandler" in low:
            score += 0.15
        elif "debug_" in low or "debugonkey" in low:
            score += 0.10
        elif "debug " in low:
            score += 0.05
        if any(x in low_compact for x in ("noclip", "invic", "godmode", "levelup", "weather", "cheatmode")):
            score += 0.10
        if not any(x in low for x in ("cheat", "debug", "console", "rva_")) and any(x in low for x in ("health", "damage", "money", "mana", "stamina")):
            score -= 0.12
        actionish = bool(re.search(r"(?i)::(?:toggle|activate|deactivate|enable|disable|show|hide|spawn|give|teleport|port|set)[A-Za-z0-9_]*\(", value))
        getterish = bool(re.search(r"(?i)::(?:get_|get|is|has)[A-Za-z0-9_]*\(", value))
        explicit_surface = any(x in low for x in ("cheatgamehandler", "cheat_", "cheat ", "noclip", "invic", "godmode", "consolewindow", "debugonkey"))
        if explicit_surface and actionish:
            score += 0.18
        elif getterish and ("debug" in low or "cheat" in low):
            score -= 0.16
        lifecycle_or_generated = bool(re.search(r"(?i)::(?:\.ctor|\.cctor|update|lateupdate|awake|start|reset|onenable|ondisable|ondestroy|movenext|setstatemachine)\(", value))
        if lifecycle_or_generated:
            score -= 0.24
        if "checkchunkperf" in low and not re.search(r"(?i)::(?:toggle|enable|disable|activate|deactivate)", value):
            score -= 0.22
        score = max(0.20, min(0.99, score))
        if verification and resolver and resolver.get("verified") and verification.get("resolverRequired"):
            verification["resolverVerified"] = True
            verification["bindingBlocker"] = None
            if verification.get("addressConfirmed") and verification.get("abiConfirmed"):
                verification["executableReady"] = True
                verification["confirmationLevel"] = "executable-ready-static"
            ve = list(verification.get("evidence") or [])
            ve.append({"kind": "instance-resolver", "rva": resolver.get("rva"),
                       "match": resolver.get("match"), "targetClass": resolver.get("targetClass")})
            verification["evidence"] = ve[:32]
        evidence_item = {"source": source, "kind": kind, "value": value[:240], "location": location,
                         "evidenceRva": evidence_rva, "signatureContract": contract,
                         "methodVerification": verification or None}
        if key in seen:
            item = out[seen[key]]
            evs = item.setdefault("corroboratingEvidence", [])
            sig = (source, kind, value[:240], location)
            existing = {(e.get("source"), e.get("kind"), e.get("value"), e.get("location")) for e in evs}
            primary = (item.get("source"), item.get("kind"), item.get("value"), item.get("location"))
            if sig != primary and sig not in existing:
                evs.append(evidence_item)
                item["status"] = "correlated"
                item["confidence"] = round(min(0.99, max(float(item.get("confidence", 0.0)), score) + 0.06), 2)
            if contract and not item.get("signatureContract"):
                item["signatureContract"] = contract
                item["bindingSuggestion"] = contract.get("bindingSuggestion")
                item["bindingBlocker"] = contract.get("bindingBlocker")
                item["isStatic"] = contract.get("isStatic")
                item["suggestedType"] = contract.get("suggestedControlType") or {
                    "action": "button", "bool_setter": "toggle",
                    "number_setter": "slider_or_toggle",
                }.get(contract.get("bindingSuggestion"), item.get("suggestedType"))
            if verification:
                current = item.get("methodVerification") or {}
                if float(verification.get("structuralConfidence") or 0.0) >= float(current.get("structuralConfidence") or 0.0):
                    item["methodVerification"] = verification
            if resolver and not item.get("instanceResolver"):
                item["instanceResolver"] = resolver
                item["resolverRva"] = resolver.get("rva")
                item["resolverKind"] = resolver.get("kind")
                item["resolverVerified"] = bool(resolver.get("verified"))
                item["resolverMatch"] = resolver.get("match")
                item["bindingBlocker"] = (None if resolver.get("verified")
                                          else "instance-resolver-review-required")
            if item.get("evidenceRva") is None and evidence_rva is not None:
                # Prefer the address-bearing evidence as primary, but preserve the
                # previous primary source in corroboratingEvidence so provenance
                # is never lost during promotion.
                old_primary = {"source": item.get("source", ""), "kind": item.get("kind", ""),
                               "value": item.get("value", ""), "location": item.get("location", ""),
                               "evidenceRva": item.get("evidenceRva")}
                old_sig = (old_primary["source"], old_primary["kind"], old_primary["value"], old_primary["location"])
                # The new address-bearing evidence becomes primary, so remove its
                # duplicate from corroboratingEvidence if it was appended above.
                evs[:] = [e for e in evs if (e.get("source"), e.get("kind"), e.get("value"), e.get("location")) != sig]
                existing = {(e.get("source"), e.get("kind"), e.get("value"), e.get("location")) for e in evs}
                if old_sig != sig and old_sig not in existing:
                    evs.append(old_primary)
                item["evidenceRva"] = evidence_rva
                item["source"], item["kind"], item["value"], item["location"] = source, kind, value[:240], location
            item["evidenceCount"] = 1 + len(evs)
            return
        suggested_visual = _suggested_control(value)
        if contract:
            suggested_visual = contract.get("suggestedControlType") or {
                "action": "button",
                "bool_setter": "toggle",
                "number_setter": "slider_or_toggle",
            }.get(contract.get("bindingSuggestion"), suggested_visual)
        seen[key] = len(out)
        out.append({
            "id": "candidate." + key[:56],
            "title": title,
            "suggestedType": suggested_visual,
            "status": ("structural-confirmed" if verification.get("addressConfirmed") else "review"),
            "confidence": round(score, 2),
            "source": source,
            "kind": kind,
            "value": value[:240],
            "location": location,
            "evidenceRva": evidence_rva,
            "evidenceCount": 1,
            "corroboratingEvidence": [],
            "signatureContract": contract,
            "methodVerification": verification or None,
            "bindingSuggestion": contract.get("bindingSuggestion") if contract else None,
            "bindingBlocker": ((None if resolver.get("verified") else "instance-resolver-review-required")
                               if resolver else (contract.get("bindingBlocker") if contract else None)),
            "isStatic": contract.get("isStatic") if contract else None,
            "instanceResolver": resolver,
            "resolverRva": resolver.get("rva") if resolver else None,
            "resolverKind": resolver.get("kind") if resolver else None,
            "resolverVerified": bool(resolver.get("verified")) if resolver else False,
            "resolverMatch": resolver.get("match") if resolver else None,
            "binding": None,
            "rationale": (("Instance method with metadata-verified target type and unique static resolver candidate."
                           if resolver.get("verified") else
                           "Instance method with same-owner resolver candidate; resolver type identity is not proven and requires review.")
                          if resolver else "Candidate extracted from static evidence; review signature/calling convention before binding."),
        })

    for finding in report.get("findings", []):
        conf = float(finding.get("confidence", 0.5))
        for ev in finding.get("evidence", []):
            add(str(ev.get("value", "")), str(ev.get("artifact", "")), str(ev.get("kind", "")),
                str(ev.get("location", "")), conf)

    unity = report.get("unity") or {}
    for catalog in unity.get("catalogs", []) or []:
        for f in catalog.get("findings", []) or []:
            value = str(f.get("primary_key") or f.get("asset") or "")
            add(value, str(catalog.get("apk_entry", "Addressables catalog")), "addressables", "", 0.65)
    for bundle in unity.get("bundles", []) or []:
        source = str(bundle.get("apk_entry") or bundle.get("sha256") or "UnityFS bundle")
        for value in bundle.get("matched_strings", []) or []:
            add(str(value), source, "unity-string", "", 0.58)

    il2cpp = report.get("il2cpp") or {}
    structured_rows = []
    for key in ("metadata_callable_methods", "metadata_resolved_methods", "discoveries", "candidates"):
        structured_rows.extend(il2cpp.get(key, []) or [])
    resolver_candidates_exact: dict[tuple[str, str], list[dict]] = defaultdict(list)
    resolver_candidates_fallback: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in structured_rows:
        contract = row.get("signature_contract") or {}
        rva = row.get("rva")
        label = str(row.get("label", ""))
        resolver_kind = contract.get("resolverSuggestion")
        if resolver_kind not in {"out_ptr_bool", "return_ptr"} or not isinstance(rva, int) or rva <= 0 or "::" not in label:
            continue
        owner, method = label.rsplit("::", 1)
        image = str(row.get("image", ""))
        priority = 0
        ml = method.casefold()
        if ml.startswith("tryget"): priority += 4
        if ml in {"get_instance", "getinstance", "instance"}: priority += 6
        if "instance" in ml: priority += 3
        if ml.startswith("get"): priority += 1
        candidate = {
            "rva": rva, "kind": resolver_kind, "label": label,
            "source": image or "Rodroid", "contract": contract, "priority": priority,
            "verified": False, "match": "same-owner-name-only",
            "targetClass": contract.get("resolverTargetClass"),
            "targetImage": contract.get("resolverTargetImage"),
            "contractSource": contract.get("contractSource"),
        }
        target_class = str(contract.get("resolverTargetClass") or "")
        target_image = str(contract.get("resolverTargetImage") or image or "")
        if contract.get("resolverTargetVerified") and target_class:
            exact = dict(candidate)
            exact.update({"verified": True, "match": "metadata-target-type-exact"})
            resolver_candidates_exact[(target_image, target_class)].append(exact)
        else:
            # Legacy Rodroid signatures do not carry a proven metadata type
            # identity. Preserve them for analyst review, but never treat a
            # same-owner name coincidence as an automatic instance proof.
            resolver_candidates_fallback[(image, owner)].append(candidate)

    verified_resolvers = {}
    for target, rows in resolver_candidates_exact.items():
        rows.sort(key=lambda x: (-x["priority"], x["rva"]))
        if len(rows) == 1 or rows[0]["priority"] > rows[1]["priority"]:
            verified_resolvers[target] = rows[0]
    review_resolvers = {}
    for target, rows in resolver_candidates_fallback.items():
        rows.sort(key=lambda x: (-x["priority"], x["rva"]))
        if len(rows) == 1 or rows[0]["priority"] > rows[1]["priority"]:
            review_resolvers[target] = rows[0]

    def resolver_for(row: dict, contract: dict) -> dict | None:
        if contract.get("isStatic") is not False:
            return None
        label = str(row.get("label", ""))
        owner = label.rsplit("::", 1)[0] if "::" in label else ""
        image = str(row.get("image", ""))
        return (verified_resolvers.get((image, owner))
                or review_resolvers.get((image, owner)))

    # Confirmed metadata callable mappings are processed first. These are the
    # dev12 method-resolver rows: exact metadata key + unique CodeRegistration
    # address + managed signature contract.
    for row in il2cpp.get("metadata_callable_methods", []) or []:
        label = str(row.get("label", ""))
        rva = row.get("rva")
        loc = f"RVA 0x{int(rva):x}" if isinstance(rva, int) and rva > 0 else ""
        contract = row.get("signature_contract") or {}
        resolver = resolver_for(row, contract)
        confirmed = str(row.get("resolution", "")).startswith("confirmed-unique")
        app_surface = row.get("application_owned") is not False
        confidence = (0.98 if app_surface else 0.70) if confirmed else (0.82 if app_surface else 0.62)
        add(label, str(row.get("image", "IL2CPP metadata")), "il2cpp-metadata-callable",
            loc, confidence, contract, resolver, row.get("method_verification"))

    # Confirmed metadata fallback mappings and semantic discoveries are processed
    # before the large generic getter list, so high-signal developer controls
    # cannot be displaced by thousands of ordinary gameplay properties.
    for row in il2cpp.get("metadata_resolved_methods", []) or []:
        label = str(row.get("label", ""))
        rva = row.get("rva")
        loc = f"RVA 0x{int(rva):x}" if isinstance(rva, int) and rva > 0 else ""
        conf = 0.94 if str(row.get("resolution", "")).startswith("confirmed-unique") else 0.78
        contract = row.get("signature_contract") or {}
        resolver = resolver_for(row, contract)
        add(label, str(row.get("image", "IL2CPP metadata")), "il2cpp-metadata-method", loc, conf, contract, resolver,
            row.get("method_verification"))
    for row in il2cpp.get("discoveries", []) or []:
        label = str(row.get("label", ""))
        rva = row.get("rva")
        loc = f"RVA 0x{int(rva):x}" if isinstance(rva, int) and rva > 0 else ""
        kind = "rodroid-field" if row.get("item_type") == "field" else "rodroid-discovery"
        contract = row.get("signature_contract") or {}
        resolver = resolver_for(row, contract)
        add(label, str(row.get("image", "Rodroid")), kind, loc, 0.78 if rva else 0.64, contract, resolver,
            row.get("method_verification"))
    for row in il2cpp.get("candidates", []) or []:
        label = str(row.get("label", ""))
        rva = row.get("rva")
        loc = f"RVA 0x{int(rva):x}" if isinstance(rva, int) and rva > 0 else ""
        contract = row.get("signature_contract") or {}
        resolver = resolver_for(row, contract)
        add(label, str(row.get("image", "Rodroid")), "rodroid-method", loc, 0.72, contract, resolver,
            row.get("method_verification"))

    out.sort(key=lambda x: (-x["confidence"], x["title"].casefold()))
    return out[:limit]


def augment_function_correlations(report: dict, apk_path: str | Path | None = None, library_path: str | Path | None = None, metadata_path: str | Path | None = None, *, max_targets: int = 192) -> dict:
    """Add bounded static function/xref evidence after IL2CPP data is loaded.

    The scanner only decodes direct ARM64 ``BL`` instructions.  Results are static
    references inside the ELF image, not runtime traces, and indirect calls are
    deliberately not guessed.
    """
    il2cpp = report.get("il2cpp") or {}
    rows = []
    for key in ("metadata_callable_methods", "metadata_resolved_methods", "discoveries", "candidates"):
        rows.extend(il2cpp.get(key, []) or [])

    method_rows_by_rva: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        rva = row.get("rva")
        if isinstance(rva, int) and rva > 0 and row.get("label"):
            method_rows_by_rva[rva].append(row)
    method_starts = sorted(method_rows_by_rva)

    # dev16: rank the whole high-signal pool before applying max_targets.  Large
    # games otherwise let compiler glue and middleware which happen to appear
    # early in metadata crowd Assembly-CSharp methods out of xref coverage.
    ranked_rows = []
    from modkit.reworkspace.method_evidence import method_role, structurally_actionable
    for row in rows:
        rva = row.get("rva")
        label = str(row.get("label") or "")
        contract = row.get("signature_contract") or {}
        # Dev21: xref coverage is no longer gated by gameplay/debug vocabulary.
        # Generic callable API morphology is enough to enter the bounded target
        # pool; semantic names only influence ranking after structural admission.
        observed_direct_bl = int(row.get("static_incoming_direct_bl_count") or 0)
        if (not isinstance(rva, int) or rva <= 0 or not label
                or (not observed_direct_bl and not _CONTROL_MARKER.search(label)
                    and not structurally_actionable(label, contract)
                    and method_role(label, contract) != "instance_resolver")):
            continue
        image = str(row.get("image") or "")
        provenance = str(row.get("provenance") or "")
        if not provenance:
            if image in {"Assembly-CSharp", "Assembly-CSharp.dll"} or image.startswith("Assembly-CSharp."):
                provenance = "game-primary"
            elif "firstpass" in image.casefold():
                provenance = "mixed-firstpass"
            elif image.startswith(("Unity", "System", "Microsoft", "Mono", "mscorlib", "netstandard")):
                provenance = "framework"
            elif any(x in (image + " " + label).casefold() for x in ("dotween", "criware", "crimana", "cinemachine", "fmod", "spine", "newtonsoft", "firebase", "unitask")):
                provenance = "third-party-known"
            else:
                provenance = "custom-unknown"
        low = label.casefold()
        method = label.rsplit("::", 1)[-1].split("(", 1)[0].casefold()
        score = {"game-primary": 100, "mixed-firstpass": 30, "custom-unknown": 15,
                 "third-party-known": -45, "framework": -70}.get(provenance, 0)
        if contract.get("bindingSuggestion"):
            score += 20
        if observed_direct_bl:
            # Name-independent structural discovery from the full metadata RVA
            # scan gets first-class xref follow-up even when the symbol is "a".
            score += 38 + min(18, int(math.log2(observed_direct_bl + 1) * 4))
        score += {
            "instance_resolver": 22, "toggle_action": 16, "setter": 14,
            "action": 8, "query": 0, "unknown": -4,
            "lifecycle": -80, "generated": -70,
        }.get(method_role(label, contract), 0)
        if any(x in low for x in ("godmode", "noclip", "invincible", "cheat", "trainer")):
            score += 25
        elif any(x in low for x in ("health", "damage", "money", "mana", "speed", "level", "state")):
            score += 8
        if method in {"setstatemachine", "movenext", "begininvoke", "endinvoke", "invoke"}:
            score -= 90
        if "<" in label or ">" in label:
            score -= 25
        ranked_rows.append((score, rva, label.casefold(), provenance, row))

    ranked_rows.sort(key=lambda x: (-x[0], x[2], x[1]))
    targets: dict[int, list[dict]] = defaultdict(list)
    for _score, rva, _label_sort, provenance, row in ranked_rows:
        label = str(row.get("label") or "")
        bucket = targets[rva]
        if not any(x.get("label") == label for x in bucket):
            bucket.append({"label": label, "image": str(row.get("image") or ""),
                           "provenance": provenance,
                           "signature": str((row.get("signature_contract") or {}).get("signature") or row.get("signature") or "")})
        if len(targets) >= max_targets:
            break
    if not targets:
        return report

    blob = None
    elf = None
    mmap_owned = False
    artifact_name = "libil2cpp.so"
    source = None
    if library_path:
        lp = Path(library_path)
        if lp.is_file() and lp.stat().st_size <= 512 * 1024 * 1024:
            try:
                elf = ElfFile.open_mmap(lp); mmap_owned = True; source = str(lp)
            except (OSError, ValueError):
                elf = None
    if elf is None and apk_path:
        ap = Path(apk_path)
        if ap.is_file():
            with zipfile.ZipFile(ap) as z:
                choices = [i for i in z.infolist() if i.filename.lower().endswith("/libil2cpp.so") and i.file_size <= 512 * 1024 * 1024]
                choices.sort(key=lambda i: (0 if "arm64-v8a" in i.filename.lower() else 1, i.filename))
                if choices:
                    info = choices[0]
                    blob = z.read(info); source = info.filename; artifact_name = info.filename
                    try:
                        elf = ElfFile(blob)
                    except ValueError:
                        elf = None
    if elf is None:
        return report

    try:
        calls = direct_bl_calls(elf, set(targets), limit=5000, max_scan_bytes=256 * 1024 * 1024)
        exact_sources = {}
        method_context = {}
        if metadata_path and library_path and Path(metadata_path).is_file() and Path(library_path).is_file() and (calls or targets):
            try:
                from modkit.mobile.engine import _metadata_callsite_sources
                context_targets = list(targets)[:64]
                exact_sources, method_context = _metadata_callsite_sources(
                    metadata_path, library_path, [x.get("callRva") for x in calls],
                    selected_method_rvas=context_targets, return_context=True,
                    max_context_methods=64, max_method_bytes=16 * 1024,
                    max_total_context_bytes=256 * 1024)
            except Exception as source_exc:
                report.setdefault("nativeRelations", {}).setdefault("functionCorrelationErrors", []).append({
                    "artifact": artifact_name, "stage": "metadata-callsite-attribution", "error": str(source_exc)
                })
    except Exception as exc:
        report.setdefault("nativeRelations", {}).setdefault("functionCorrelationErrors", []).append({
            "artifact": artifact_name, "error": str(exc)
        })
        return report
    finally:
        if mmap_owned:
            elf.close()

    refs = []
    for call in calls:
        labels = targets.get(int(call.get("targetRva") or 0), [])
        ref = {
            "artifact": artifact_name,
            "source": source,
            **call,
            "targetMethods": labels[:8],
            "confidence": 0.96,
            "rationale": "ARM64 direct BL resolves exactly to an address-bearing Rodroid/IL2CPP method RVA.",
        }
        call_rva = int(call.get("callRva") or 0)
        exact = exact_sources.get(call_rva) if call_rva > 0 else None
        if exact:
            ref.update(exact)
        elif method_starts and call_rva > 0:
            idx = bisect_right(method_starts, call_rva) - 1
            if idx >= 0:
                start = method_starts[idx]
                next_start = method_starts[idx + 1] if idx + 1 < len(method_starts) else None
                span = call_rva - start
                if 0 <= span <= 0x40000 and (next_start is None or call_rva < next_start):
                    candidates = method_rows_by_rva[start]
                    source_rows = [{
                        "label": str(x.get("label") or ""),
                        "image": str(x.get("image") or ""),
                        "rva": start,
                        "signature": str((x.get("signature_contract") or {}).get("signature") or x.get("signature") or ""),
                    } for x in candidates[:8]]
                    ref["sourceMethodCandidates"] = source_rows
                    ref["sourceInterval"] = {"startRva": start, "nextMethodRva": next_start, "callOffset": span}
                    # If only one managed method starts at this RVA, attribution is
                    # strong static interval evidence; duplicate/generic starts stay ambiguous.
                    ref["sourceAttribution"] = "unique-managed-interval" if len(candidates) == 1 else "ambiguous-shared-rva"
        refs.append(ref)
    relations = report.setdefault("nativeRelations", {})
    relations["il2cppDirectCallRefs"] = refs[:5000]
    relations["il2cppDirectCallTargets"] = len({x["targetRva"] for x in refs})
    if method_context:
        # Persist only selected high-signal method context.  The full metadata
        # address map used to prove these relationships remains transient.
        relations["il2cppMethodContext"] = [method_context[k] for k in sorted(method_context)][:max_targets]
        relations["il2cppMethodContextSummary"] = {
            "schema": "modkit-il2cpp-method-context-1.0",
            "methods": len(method_context),
            "outgoingManagedCalls": sum(len(x.get("outgoingManagedCalls") or []) for x in method_context.values()),
            "stringRefs": sum(len(x.get("stringRefs") or []) for x in method_context.values()),
            "thisOffsetCandidates": sum(len(x.get("thisOffsetCandidates") or []) for x in method_context.values()),
            "semantics": "Static method-local evidence only; field offsets remain candidates until independently corroborated.",
        }

    if refs:
        evidence = []
        for ref in refs[:40]:
            target = (ref.get("targetMethods") or [{}])[0]
            src_methods = ref.get("sourceMethodCandidates") or []
            src_fn = str((src_methods[0].get("label") if src_methods else None) or ref.get("sourceFunction") or f"sub_{int(ref.get('callRva') or 0):x}")
            evidence.append({
                "artifact": artifact_name,
                "kind": "arm64-direct-bl-xref",
                "value": f"{src_fn} -> {target.get('label', 'IL2CPP method')}",
                "location": f"call RVA 0x{int(ref.get('callRva') or 0):x} -> 0x{int(ref.get('targetRva') or 0):x}",
            })
        finding = {
            "id": "re.il2cpp_static_call_references",
            "title": "Static call references to address-bearing IL2CPP controls",
            "category": "il2cpp_function_xrefs",
            "status": "correlated",
            "confidence": 0.96,
            "evidence": evidence,
            "rationale": (f"{len(refs)} ARM64 direct BL reference(s) resolve exactly to {relations['il2cppDirectCallTargets']} "
                          "address-bearing IL2CPP target(s). This is static xref evidence, not runtime execution proof."),
        }
        findings = report.setdefault("findings", [])
        findings[:] = [x for x in findings if x.get("id") != finding["id"]]
        findings.append(finding)
        findings.sort(key=lambda f: (-float(f.get("confidence", 0.0)), str(f.get("id", ""))))
    return report



def augment_method_verification(report: dict) -> dict:
    """Attach universal structural/xref/context evidence to IL2CPP method rows.

    This pass is intentionally semantic-neutral.  It can confirm an address,
    typed ABI and exact managed-call relationships, but never claims that a
    method produced a runtime effect merely because its name looked interesting.
    """
    from modkit.reworkspace.method_evidence import build_method_verification, enrich_method_verification

    il2cpp = report.get("il2cpp") or {}
    rows: list[dict] = []
    for key in ("metadata_callable_methods", "metadata_resolved_methods", "discoveries", "candidates"):
        rows.extend(il2cpp.get(key, []) or [])

    incoming: dict[int, list[dict]] = defaultdict(list)
    outgoing: dict[int, list[dict]] = defaultdict(list)
    relations = report.get("nativeRelations") or {}
    for ref in relations.get("il2cppDirectCallRefs", []) or []:
        trva = ref.get("targetRva")
        if isinstance(trva, int) and trva > 0:
            incoming[trva].append(ref)
        if ref.get("sourceAttribution") in {"unique-managed-interval", "unique-metadata-method-interval"}:
            for src in ref.get("sourceMethodCandidates") or []:
                srva = src.get("rva")
                if isinstance(srva, int) and srva > 0:
                    outgoing[srva].append(ref)

    context_by_rva: dict[int, dict] = {}
    for ctx in relations.get("il2cppMethodContext", []) or []:
        rva = ((ctx.get("method") or {}).get("rva"))
        if isinstance(rva, int) and rva > 0:
            context_by_rva[rva] = ctx

    seen = set()
    verified_rows = []
    for row in rows:
        rva = row.get("rva")
        label = str(row.get("label") or "")
        if not isinstance(rva, int) or rva <= 0 or not label:
            continue
        key = (label, rva, str(row.get("image") or ""))
        if key in seen:
            continue
        seen.add(key)
        base = row.get("method_verification") or build_method_verification(row)
        enriched = enrich_method_verification(
            base, incoming_refs=incoming.get(rva), outgoing_refs=outgoing.get(rva),
            method_context=context_by_rva.get(rva))
        row["method_verification"] = enriched
        verified_rows.append(enriched)

    summary = {
        "schema": "modkit-universal-method-resolver-1.0",
        "rows": len(verified_rows),
        "addressConfirmed": sum(1 for x in verified_rows if x.get("addressConfirmed")),
        "abiConfirmed": sum(1 for x in verified_rows if x.get("abiConfirmed")),
        "executableReadyStatic": sum(1 for x in verified_rows if x.get("executableReady")),
        "xrefCorroborated": sum(1 for x in verified_rows if x.get("relationStatus") == "confirmed-static-xref"),
        "contextCorroborated": sum(1 for x in verified_rows if x.get("contextStatus") == "corroborated-static-context"),
        "runtimeConfirmed": 0,
        "semantics": ("Application-agnostic static verification. Address/ABI/xref/context are separate evidence layers; "
                      "runtime behaviour remains unobserved until a future dynamic verifier records it."),
    }
    report["methodVerification"] = summary
    return report


def build_static_relationship_graph(report: dict, *, max_chains: int = 80) -> dict:
    """Build a bounded cross-artifact graph from already-collected static evidence.

    Edges deliberately preserve their evidence class.  A DEX library-name match,
    JNI direct BL, embedded-library string, dlsym string xref and IL2CPP direct BL
    are *not* treated as interchangeable execution proof.  Complete chains are
    emitted only when directed evidence connects a DEX loader root to a reviewable
    control candidate.  Otherwise the graph records partial chains and explicit
    gaps instead of inventing a missing hop.
    """
    relations = report.get("nativeRelations") or {}
    controls = report.get("controlCandidates") or []

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_keys: set[tuple] = set()

    def nid(kind: str, artifact: str = "", label: str = "", rva=None) -> str:
        # Native dynamic/exported function names are unique enough inside one ELF
        # and often appear first without an RVA (JNI surface) and later with one
        # (direct-call/xref evidence). Keep one node and enrich it with the RVA.
        rva_part = "" if (rva is None or kind == "native-function") else f"{int(rva):x}"
        raw = f"{kind}|{artifact}|{label}|{rva_part}".encode("utf-8", "replace")
        return f"{kind}." + hashlib.sha1(raw).hexdigest()[:14]

    def add_node(kind: str, artifact: str = "", label: str = "", rva=None, **extra) -> str:
        node_id = nid(kind, artifact, label, rva)
        row = {"id": node_id, "type": kind, "artifact": artifact, "label": label or artifact}
        if isinstance(rva, int):
            row["rva"] = rva
        for k, v in extra.items():
            if v is not None and v != "":
                row[k] = v
        existing = nodes.get(node_id)
        if existing:
            for k, v in row.items():
                existing.setdefault(k, v)
        else:
            nodes[node_id] = row
        return node_id

    def add_edge(src: str, dst: str, kind: str, confidence: float, *, evidence_class: str,
                 rationale: str = "", structural: bool = False, **extra):
        key = (src, dst, kind, evidence_class)
        if src == dst or key in edge_keys:
            return
        edge_keys.add(key)
        row = {
            "from": src, "to": dst, "kind": kind,
            "confidence": round(float(confidence), 2),
            "evidenceClass": evidence_class,
            "structural": bool(structural),
        }
        if rationale:
            row["rationale"] = rationale
        for k, v in extra.items():
            if v is not None and v != "":
                row[k] = v
        edges.append(row)

    so_nodes: dict[str, str] = {}
    dex_nodes: dict[str, str] = {}

    def so_node(name: str) -> str:
        name = str(name or "")
        if name not in so_nodes:
            so_nodes[name] = add_node("native-library", name, Path(name).name)
        return so_nodes[name]

    def dex_node(name: str) -> str:
        name = str(name or "")
        if name not in dex_nodes:
            dex_nodes[name] = add_node("dex", name, Path(name).name)
        return dex_nodes[name]

    # DEX -> packaged native loader relation.
    for x in relations.get("dexNativeLinks", []) or []:
        d = dex_node(str(x.get("from", "")))
        s = so_node(str(x.get("to", "")))
        add_edge(d, s, "loads-library", float(x.get("confidence", 0.6)),
                 evidence_class="dex-library-name",
                 rationale=str(x.get("rationale", "")),
                 library=x.get("library"), loadLibraryMarker=bool(x.get("loadLibraryMarker")),
                 jniOnLoad=bool(x.get("jniOnLoad")))

    # Library-to-library static relations.  Keep DT_NEEDED distinct from weaker
    # embedded string evidence.
    for key, kind, conf, evc in (
        ("dependencyEdges", "depends-on", 0.99, "DT_NEEDED"),
        ("embeddedLibraryStringEdges", "references-library", 0.68, "embedded-library-string"),
    ):
        for x in relations.get(key, []) or []:
            src = so_node(str(x.get("from", "")))
            dst = so_node(str(x.get("to", "")))
            add_edge(src, dst, kind, conf, evidence_class=evc, rationale=str(x.get("rationale", "")), value=x.get("value"))

    # JNI entrypoints and direct native calls inside the same ELF.
    for x in relations.get("jniSurfaces", []) or []:
        art = str(x.get("artifact", ""))
        if not art:
            continue
        lib = so_node(art)
        for name in x.get("exports", []) or []:
            if name != "JNI_OnLoad" and not str(name).startswith("Java_"):
                continue
            fn = add_node("native-function", art, str(name))
            add_edge(lib, fn, "exports-jni-entry", 0.99, evidence_class="ELF-export", structural=True)
    for x in relations.get("jniDirectCallRefs", []) or []:
        art = str(x.get("artifact", ""))
        src_label = str(x.get("sourceFunction") or f"sub_{int(x.get('sourceRva') or x.get('callRva') or 0):x}")
        dst_label = str(x.get("targetFunction") or f"sub_{int(x.get('targetRva') or 0):x}")
        src = add_node("native-function", art, src_label, x.get("sourceRva"))
        dst = add_node("native-function", art, dst_label, x.get("targetRva"))
        add_edge(src, dst, "direct-call", 0.98, evidence_class="arm64-direct-bl",
                 callRva=x.get("callRva"), rationale="ARM64 BL resolves directly to the target RVA.")

    # Exact import/export linkage is linker evidence.  A caller function is not
    # known, so source is the importing ELF rather than an invented function.
    for x in relations.get("symbolEdges", []) or []:
        src = so_node(str(x.get("from", "")))
        target_art = str(x.get("to", ""))
        symbol = str(x.get("symbol", ""))
        dst = add_node("native-function", target_art, symbol, x.get("targetRva"))
        add_edge(src, dst, "imports-export", float(x.get("confidence", 0.96)),
                 evidence_class="ELF-import-export", rationale=str(x.get("rationale", "")), structural=True)

    # dlsym correlation can sometimes be function-scoped through ADRP+ADD xrefs.
    for x in relations.get("dynamicSymbolEdges", []) or []:
        target_art = str(x.get("to", ""))
        symbol = str(x.get("symbol", ""))
        dst = add_node("native-function", target_art, symbol, x.get("targetRva"))
        xrefs = x.get("staticStringXrefs") or []
        if xrefs:
            for xr in xrefs[:12]:
                host = str(x.get("from", ""))
                label = str(xr.get("sourceFunction") or f"sub_{int(xr.get('xrefRva') or 0):x}")
                src = add_node("native-function", host, label, xr.get("sourceRva"))
                add_edge(src, dst, "dynamic-symbol-candidate", float(x.get("confidence", 0.88)),
                         evidence_class="dlsym-string-address-xref",
                         rationale=str(x.get("rationale", "")), stringRva=x.get("stringRva"), xrefRva=xr.get("xrefRva"))
        else:
            src = so_node(str(x.get("from", "")))
            add_edge(src, dst, "dynamic-symbol-candidate", float(x.get("confidence", 0.78)),
                     evidence_class="dlsym-string-export", rationale=str(x.get("rationale", "")), structural=True)

    # Address-bearing IL2CPP method graph.  Source attribution remains explicit
    # about whether the managed interval is unique or ambiguous.
    managed_by_rva: dict[int, list[str]] = defaultdict(list)
    for ref in relations.get("il2cppDirectCallRefs", []) or []:
        art = str(ref.get("artifact", "libil2cpp.so"))
        target_rva = ref.get("targetRva")
        targets = ref.get("targetMethods") or []
        if not targets:
            targets = [{"label": f"IL2CPP RVA 0x{int(target_rva or 0):x}"}]
        target_ids = []
        for m in targets[:8]:
            label = str(m.get("label") or f"IL2CPP RVA 0x{int(target_rva or 0):x}")
            mid = add_node("managed-method", art, label, target_rva,
                           image=m.get("image"), signature=m.get("signature"))
            target_ids.append(mid)
            if isinstance(target_rva, int):
                managed_by_rva[target_rva].append(mid)
        sources = ref.get("sourceMethodCandidates") or []
        if sources:
            for m in sources[:8]:
                src_rva = m.get("rva")
                src = add_node("managed-method", art, str(m.get("label") or "managed source"), src_rva,
                               image=m.get("image"), signature=m.get("signature"),
                               attribution=ref.get("sourceAttribution"))
                for dst in target_ids:
                    add_edge(src, dst, "managed-direct-call", float(ref.get("confidence", 0.96)),
                             evidence_class="arm64-direct-bl+rodroid-interval",
                             rationale=str(ref.get("rationale", "")), callRva=ref.get("callRva"),
                             attribution=ref.get("sourceAttribution"))
        else:
            src_label = str(ref.get("sourceFunction") or f"sub_{int(ref.get('callRva') or 0):x}")
            src = add_node("native-function", art, src_label, ref.get("sourceRva"))
            for dst in target_ids:
                add_edge(src, dst, "direct-call-to-managed-rva", float(ref.get("confidence", 0.96)),
                         evidence_class="arm64-direct-bl", rationale=str(ref.get("rationale", "")), callRva=ref.get("callRva"))

    # Link reviewable controls to the exact address-bearing evidence that created
    # them.  This is an evidence edge, not execution proof.
    control_nodes = []
    for c in controls[:400]:
        cid = add_node("control-candidate", str(c.get("source", "")), str(c.get("title") or c.get("id") or "control"),
                       c.get("evidenceRva"), candidateId=c.get("id"), status=c.get("status"),
                       confidence=c.get("confidence"), suggestedType=c.get("suggestedType"), binding=c.get("binding"))
        control_nodes.append(cid)
        rva = c.get("evidenceRva")
        linked = False
        if isinstance(rva, int):
            for mid in managed_by_rva.get(rva, [])[:8]:
                add_edge(mid, cid, "evidence-for-control", float(c.get("confidence", 0.6)),
                         evidence_class="candidate-provenance", structural=True)
                linked = True
            if not linked and str(c.get("source", "")).replace("\\", "/").endswith(".so"):
                src = add_node("native-function", str(c.get("source", "")), str(c.get("value") or c.get("title") or "native evidence"), rva)
                add_edge(src, cid, "evidence-for-control", float(c.get("confidence", 0.6)),
                         evidence_class="candidate-provenance", structural=True)
        if not linked and str(c.get("source", "")).lower().endswith(".dex"):
            add_edge(dex_node(str(c.get("source", ""))), cid, "evidence-for-control", float(c.get("confidence", 0.5)),
                     evidence_class="candidate-provenance", structural=True)

    # Directed reachability.  Only actual directed edges are traversed; there is
    # no synthetic bridge between disconnected components.
    adjacency: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    reverse: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for edge_index, e in enumerate(edges):
        adjacency[e["from"]].append((edge_index, e))
        reverse[e["to"]].append((edge_index, e))

    roots = [n for n in nodes.values() if n["type"] == "dex" and adjacency.get(n["id"])]
    control_set = {n["id"] for n in nodes.values() if n["type"] == "control-candidate"}
    complete = []
    partial = []
    reached_controls = set()

    for root in roots[:32]:
        queue = [(root["id"], [root["id"]], [])]
        seen_depth: dict[str, int] = {root["id"]: 0}
        emitted_partial = 0
        while queue and len(complete) < max_chains:
            current, path_nodes, path_edges = queue.pop(0)
            if current in control_set and len(path_nodes) > 1:
                reached_controls.add(current)
                complete.append({"root": root["id"], "target": current, "nodes": path_nodes, "edges": path_edges,
                                 "confidence": round(min((float(edges[i]["confidence"]) for i in path_edges), default=0.0), 2)})
                continue
            if len(path_edges) >= 8:
                continue
            outs = adjacency.get(current, [])[:32]
            if not outs and len(path_edges) >= 2 and emitted_partial < 6:
                partial.append({"root": root["id"], "leaf": current, "nodes": path_nodes, "edges": path_edges,
                                "reason": "static-evidence-chain-ends-here"})
                emitted_partial += 1
            for edge_index, e in outs:
                nxt = e["to"]
                if nxt in path_nodes:
                    continue
                depth = len(path_edges) + 1
                if seen_depth.get(nxt, 99) < depth:
                    continue
                seen_depth[nxt] = depth
                queue.append((nxt, path_nodes + [nxt], path_edges + [edge_index]))

    native_only = []
    native_reached = set()
    callable_edge_kinds = {"managed-direct-call", "direct-call-to-managed-rva", "direct-call"}
    for cid in sorted(control_set):
        queue = [(cid, [cid], [])]
        seen = {cid}
        while queue and len(native_only) < max_chains:
            current, rev_nodes, rev_edges = queue.pop(0)
            if len(rev_edges) >= 5:
                continue
            for edge_index, e in reverse.get(current, [])[:24]:
                prev = e["from"]
                if prev in seen:
                    continue
                path_edges = [edge_index] + rev_edges
                path_nodes = [prev] + rev_nodes
                has_direct = any(edges[i].get("kind") in callable_edge_kinds for i in path_edges)
                prev_node = nodes.get(prev) or {}
                if has_direct and prev_node.get("type") in {"managed-method", "native-function"}:
                    native_reached.add(cid)
                    native_only.append({
                        "root": prev, "target": cid, "nodes": path_nodes, "edges": path_edges,
                        "confidence": round(min((float(edges[i]["confidence"]) for i in path_edges), default=0.0), 2),
                        "scope": "native-only",
                    })
                    queue = []
                    break
                seen.add(prev)
                queue.append((prev, path_nodes, path_edges))

    # Unlinked controls keep the legacy DEX-root meaning for backwards-compatible diagnostics.
    unlinked_controls = sorted(control_set - reached_controls)
    gaps = []
    if roots and unlinked_controls:
        for cid in unlinked_controls[:80]:
            c = nodes[cid]
            incoming = reverse.get(cid, [])
            gaps.append({
                "control": cid,
                "label": c.get("label"),
                "reason": "no-directed-static-path-from-dex-loader",
                "nearestEvidence": [e["from"] for _idx, e in incoming[:4]],
            })

    graph = {
        "schema": "modkit-static-relationship-graph-1.0",
        "nodes": list(nodes.values())[:3000],
        "edges": edges[:6000],
        "completeChains": complete[:max_chains],
        "nativeOnlyChains": native_only[:max_chains],
        "partialLoaderChains": partial[:max_chains],
        "gaps": gaps,
        "summary": {
            "nodes": len(nodes), "edges": len(edges), "dexRoots": len(roots),
            "controls": len(control_set), "completeChains": len(complete),
            "nativeOnlyChains": len(native_only), "controlsReachedFromNative": len(native_reached),
            "controlsReachedFromDex": len(reached_controls), "unlinkedControls": len(unlinked_controls),
        },
        "semantics": "Static evidence graph only; DEX-root and native-only chains are reported separately. No missing DEX/JNI hop is synthesized, and no chain is a runtime execution trace.",
    }
    report["relationshipGraph"] = graph
    return graph


def augment_control_semantics(report: dict, *, min_verified_score: float = 0.68) -> dict:
    """Correlate reviewable control candidates with static managed call context.

    This is a conservative *semantic* layer on top of address/ABI verification.
    It never executes target code and never treats a method name as behavior proof.
    A candidate is marked ``semanticVerified`` only when an application-owned,
    address-bearing IL2CPP method participates in at least one uniquely attributed
    ARM64 direct-call relationship whose managed peer has a meaningful semantic
    affinity (same owner or shared gameplay/debug tags).  Ambiguous intervals,
    framework-only methods and name-only matches remain review-only.
    """
    candidates = report.get("controlCandidates") or []
    il2cpp = report.get("il2cpp") or {}
    relations = report.get("nativeRelations") or {}
    method_context_by_rva = {}
    for ctx in relations.get("il2cppMethodContext", []) or []:
        mrva = ((ctx.get("method") or {}).get("rva"))
        if isinstance(mrva, int) and mrva > 0:
            method_context_by_rva[mrva] = ctx

    # Optional dump.cs field offsets are independent corroboration only.  A raw
    # x0+imm access is never named as a field without exact owner+offset match.
    fields_by_owner_offset: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in il2cpp.get("discoveries", []) or []:
        if row.get("item_type") != "field/property":
            continue
        off = row.get("field_offset")
        label = str(row.get("label") or "")
        if not isinstance(off, int) or off < 0 or "." not in label:
            continue
        fields_by_owner_offset[(label.rsplit(".", 1)[0], off)].append(row)

    rows: list[dict] = []
    for key in ("metadata_callable_methods", "metadata_resolved_methods", "discoveries", "candidates"):
        rows.extend(il2cpp.get(key, []) or [])

    by_rva: dict[int, list[dict]] = defaultdict(list)
    by_label: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        rva = row.get("rva")
        label = str(row.get("label") or "")
        if isinstance(rva, int) and rva > 0:
            by_rva[rva].append(row)
        if label:
            by_label[label].append(row)

    framework_prefixes = (
        "UnityEngine.", "Unity.", "System.", "Microsoft.", "Mono.", "mscorlib",
        "netstandard", "Android.", "JetBrains.",
    )
    third_party_prefixes = (
        "Newtonsoft.", "Google.", "Firebase.", "DG.Tweening", "DOTween", "CriWare",
        "CriMana", "Cinemachine", "FMOD", "Spine", "TMPro", "Cysharp.", "UniTask",
        "MessagePack.", "BestHTTP", "LitJson", "Google.Protobuf", "Adjust.", "AppsFlyer",
    )
    semantic_groups = {
        "debug": {"debug", "developer", "console", "devmenu", "diagnostic", "logging", "logger"},
        "cheat": {"cheat", "godmode", "noclip", "invincible", "trainer"},
        "health": {"health", "hp", "invincible", "invulnerability", "godmode"},
        "damage": {"damage", "dmg", "critical", "crit"},
        "movement": {"speed", "movespeed", "movement", "jump", "stamina", "noclip"},
        "state": {"state", "mode", "status", "freeze", "frozen", "pause", "paused"},
        "progression": {"level", "xp", "experience", "unlock", "unlocked", "quest"},
        "economy": {"money", "gold", "coin", "coins", "currency", "gems"},
        "resource": {"mana", "stamina", "energy"},
        "world": {"weather", "time", "day", "night"},
    }
    # Dev15 negative semantic context.  These words commonly cause false
    # positives for generic "state/speed" names but usually describe rendering,
    # quality or presentation plumbing rather than gameplay state.  A technical
    # surface can still be inspected, but it is never auto-promoted from this
    # static semantic layer alone.
    technical_surface_words = {
        "quality", "render", "renderer", "rendering", "texture", "shadow",
        "antialiasing", "resolution", "mipmap", "mipmaps", "streaming",
        "graphics", "visual", "vfx", "fx", "particle", "particles", "camera",
        "postprocess", "postprocessing", "lod", "shader", "memoryquality",
        "lifetime", "lifecycle", "animation", "animator", "timeline", "cinematic",
        "dialogue", "preview", "culling", "fog", "audio", "video", "movie",
        "typewriter", "luaopen", "luabinder", "wrapper", "binding", "rendererstate",
    }

    def words(text: str) -> set[str]:
        camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text or ""))
        return set(re.findall(r"[a-z0-9]+", camel.casefold()))

    def tags(text: str) -> set[str]:
        ws = words(text)
        return {name for name, vocab in semantic_groups.items() if ws & vocab}

    def owner(label: str) -> str:
        return label.rsplit("::", 1)[0] if "::" in label else ""

    def provenance_for(image: str, label: str = "", row: dict | None = None) -> str:
        if row and row.get("provenance"):
            return str(row.get("provenance"))
        image = str(image or "")
        cls = owner(label)
        if image in {"Assembly-CSharp", "Assembly-CSharp.dll"} or image.startswith("Assembly-CSharp."):
            return "game-primary"
        if "firstpass" in image.casefold():
            return "mixed-firstpass"
        if any(image.startswith(x) or cls.startswith(x) for x in framework_prefixes):
            return "framework"
        if any(image.startswith(x) or cls.startswith(x) for x in third_party_prefixes):
            return "third-party-known"
        low = (image + " " + cls).casefold()
        if any(x in low for x in ("dotween", "criware", "crimana", "cinemachine", "fmod", "spine", "unitask", "newtonsoft", "firebase", "google.protobuf")):
            return "third-party-known"
        return "custom-unknown"

    def app_owned(image: str, label: str = "", row: dict | None = None) -> bool:
        return provenance_for(image, label, row) in {"game-primary", "mixed-firstpass", "custom-unknown"}

    def row_for_candidate(c: dict) -> dict | None:
        rva = c.get("evidenceRva")
        value = str(c.get("value") or "")
        source = str(c.get("source") or "")
        options = by_rva.get(rva, []) if isinstance(rva, int) else []
        if value:
            exact = [r for r in options if str(r.get("label") or "") == value]
            if exact:
                return exact[0]
        if source:
            same_image = [r for r in options if str(r.get("image") or "") == source]
            if same_image:
                return same_image[0]
        return options[0] if options else None

    incoming: dict[int, list[dict]] = defaultdict(list)
    outgoing: dict[int, list[dict]] = defaultdict(list)
    for ref in relations.get("il2cppDirectCallRefs", []) or []:
        target_rva = ref.get("targetRva")
        if isinstance(target_rva, int) and target_rva > 0:
            incoming[target_rva].append(ref)
        for src in ref.get("sourceMethodCandidates") or []:
            srva = src.get("rva")
            if isinstance(srva, int) and srva > 0:
                outgoing[srva].append(ref)

    structured_pairs = set()
    for finding in report.get("findings", []) or []:
        if finding.get("id") != "re.structured_developer_control_api":
            continue
        for ev in finding.get("evidence", []) or []:
            loc = str(ev.get("location") or "")
            m = re.search(r"RVA\s+0x([0-9a-fA-F]+)", loc)
            if m:
                structured_pairs.add((str(ev.get("value") or ""), int(m.group(1), 16)))

    verified_count = correlated_count = review_count = 0
    verified_evidence: list[dict] = []

    for c in candidates:
        rva = c.get("evidenceRva")
        row = row_for_candidate(c)
        label = str((row or {}).get("label") or c.get("value") or "")
        image = str((row or {}).get("image") or c.get("source") or "")
        ctags = set((row or {}).get("semantic") or []) or tags(label)
        semantic_sources: dict[str, set[str]] = defaultdict(set)
        for semantic_tag in ctags:
            semantic_sources[semantic_tag].add('candidate-label')
        label_words = words(label)
        technical_hits = sorted(label_words & technical_surface_words)
        compact_label = re.sub(r"[^a-z0-9]+", "", label.casefold())
        for marker in ("lifetime", "luaopen", "luabinder", "battlefx", "particle", "renderquality"):
            if marker in compact_label and marker not in technical_hits:
                technical_hits.append(marker)
        technical_surface = bool(technical_hits)
        provenance = provenance_for(image, label, row)
        owned = provenance in {"game-primary", "mixed-firstpass", "custom-unknown"}
        diagnostic_only = bool("debug" in ctags and "cheat" not in ctags and
                               label_words & {"log", "logging", "logger", "trace", "diagnostic", "diagnostics"})
        c["provenance"] = provenance
        c["applicationOwned"] = owned
        contract = (row or {}).get("signature_contract") or {}
        # Dev23: semantic verification must not depend on a human-readable
        # setter/action name.  Exact address + typed ABI is enough to establish
        # a callable static-analysis subject; automatic Menu binding remains a
        # separate decision.  This is essential for obfuscated a()/b()/xqv().
        exact_callable = bool(
            row and isinstance(rva, int) and rva > 0
            and str(row.get("resolution") or "").startswith("confirmed-unique")
            and contract.get("shapeSupported")
            and contract.get("staticnessVerified") is not False
        )

        score = 0.0
        evidence: list[dict] = []
        relational = 0
        context_relational = 0
        context_string_hits = 0
        context_field_hits = 0
        context_exact_field_hits = 0
        context_engine_sink_hits = 0
        context_score = 0.0
        if exact_callable:
            score += 0.22
            evidence.append({"kind": "metadata-callable", "label": label, "image": image, "rva": rva,
                             "rationale": "unique CodeRegistration RVA with managed call contract"})
        score += {
            "game-primary": 0.18, "mixed-firstpass": 0.04, "custom-unknown": 0.02,
            "third-party-known": -0.34, "framework": -0.42,
        }.get(provenance, -0.08)
        if diagnostic_only:
            score -= 0.28
            context_score -= 0.24
            evidence.append({
                "kind": "diagnostic-only-penalty",
                "rationale": "debug/logging naming is diagnostic evidence, not a gameplay-control proof",
            })
        if technical_surface:
            score -= 0.34
            context_score -= 0.34
            evidence.append({
                "kind": "technical-surface-penalty", "terms": technical_hits,
                "rationale": "rendering/quality/presentation terminology is not gameplay proof",
            })

        def assess_ref(ref: dict, direction: str) -> None:
            nonlocal score, relational
            if ref.get("sourceAttribution") not in {"unique-managed-interval", "unique-metadata-method-interval"}:
                return
            srcs = ref.get("sourceMethodCandidates") or []
            tgts = ref.get("targetMethods") or []
            peers = srcs if direction == "incoming" else tgts
            if not peers:
                return
            peer = peers[0]
            peer_label = str(peer.get("label") or "")
            peer_image = str(peer.get("image") or "")
            if not peer_label or not app_owned(peer_image, peer_label, peer):
                return
            peer_tags = tags(peer_label)
            for semantic_tag in peer_tags:
                semantic_sources[semantic_tag].add(f'managed-{direction}-peer:{peer_label}@{peer.get("rva")}')
            same_owner = bool(owner(peer_label) and owner(peer_label) == owner(label))
            shared_tags = sorted(ctags & peer_tags)
            same_image = bool(image and peer_image and image == peer_image)
            # A raw call alone is structural evidence.  Semantic promotion needs
            # a managed peer which is meaningfully related to the candidate.
            if not (same_owner or shared_tags):
                return
            relational += 1
            bonus = 0.28
            if same_owner:
                bonus += 0.10
            if shared_tags:
                bonus += min(0.12, 0.06 * len(shared_tags))
            if same_image:
                bonus += 0.04
            score += bonus
            evidence.append({
                "kind": f"managed-{direction}-direct-call",
                "peer": peer_label, "peerImage": peer_image,
                "callRva": ref.get("callRva"), "targetRva": ref.get("targetRva"),
                "sameOwner": same_owner, "sharedTags": shared_tags,
                "rationale": "unique managed interval + exact ARM64 direct BL",
            })

        if isinstance(rva, int) and rva > 0:
            for ref in incoming.get(rva, [])[:12]:
                assess_ref(ref, "incoming")
            for ref in outgoing.get(rva, [])[:12]:
                assess_ref(ref, "outgoing")

        # Dev15 method-local context.  Unlike the dev14 incoming-xref layer,
        # these relations are decoded strictly inside the candidate's own exact
        # metadata interval.
        ctx = method_context_by_rva.get(rva) if isinstance(rva, int) else None
        if ctx:
            for call in (ctx.get("outgoingManagedCalls") or [])[:12]:
                peer = call.get("targetMethod") or {}
                peer_label = str(peer.get("label") or "")
                peer_image = str(peer.get("image") or "")
                if not peer_label:
                    continue
                peer_tags = set(peer.get("semantic") or []) or tags(peer_label)
                for semantic_tag in peer_tags:
                    semantic_sources[semantic_tag].add(f'method-local-callee:{peer_label}@{call.get("targetRva")}')
                same_owner = bool(owner(peer_label) and owner(peer_label) == owner(label))
                shared_tags = sorted(ctags & peer_tags)
                peer_provenance = provenance_for(peer_image, peer_label, peer)
                # Exact calls into narrowly-scoped engine state APIs are strong
                # method-local context even though the callee is framework-owned.
                # This is intentionally subsystem-based, not title/app-specific.
                engine_owner = owner(peer_label)
                engine_sink = bool(
                    peer_provenance == "framework" and shared_tags and
                    engine_owner.startswith(("UnityEngine.Time", "UnityEngine.Camera",
                                             "UnityEngine.Physics", "UnityEngine.RenderSettings"))
                )
                if engine_sink:
                    context_engine_sink_hits += 1
                    context_score += 0.52
                    score += 0.12
                    evidence.append({
                        "kind": "method-local-engine-state-sink", "peer": peer_label,
                        "peerImage": peer_image, "callRva": call.get("callRva"),
                        "targetRva": call.get("targetRva"), "sharedTags": shared_tags,
                        "rationale": "exact managed call from candidate interval into a matching Unity engine state sink",
                    })
                    continue
                if not bool(peer.get("applicationOwned", app_owned(peer_image, peer_label, peer))):
                    continue
                if not (same_owner or shared_tags):
                    continue
                relational += 1
                context_relational += 1
                same_image = bool(image and peer_image and image == peer_image)
                bonus = (0.28 + (0.10 if same_owner else 0.0)
                         + min(0.12, 0.06 * len(shared_tags))
                         + (0.04 if same_image else 0.0))
                score += bonus
                context_score += (0.36 + (0.10 if same_owner else 0.0)
                                  + min(0.10, 0.05 * len(shared_tags))
                                  + (0.04 if same_image else 0.0))
                evidence.append({
                    "kind": "method-local-managed-callee", "peer": peer_label, "peerImage": peer_image,
                    "callRva": call.get("callRva"), "targetRva": call.get("targetRva"),
                    "sameOwner": same_owner, "sharedTags": shared_tags,
                    "rationale": "exact candidate interval + ARM64 direct BL + unique metadata target",
                })

            # dev27 Evidence Graph provides a stronger field proof than the
            # older dump.cs + raw this+offset correlation: the base register is
            # typed, propagated through the CFG, and the offset comes directly
            # from MetadataRegistration.fieldOffsets.  A matching store/read is
            # therefore a first-class method-local context anchor.
            for access in (ctx.get("typedFieldAccesses") or [])[:16]:
                field_label = '.'.join(filter(None, (str(access.get("declaringType") or ''),
                                                     str(access.get("field") or ''))))
                field_tags = tags(field_label)
                shared = sorted(ctags & field_tags)
                if not shared:
                    continue
                if str(access.get("proof") or '') != "typed-register+MetadataRegistration-fieldOffsets":
                    continue
                context_exact_field_hits += 1
                bonus = 0.58 if access.get("access") == "store" else 0.44
                context_score += bonus
                score += 0.14 if access.get("access") == "store" else 0.10
                for semantic_tag in field_tags:
                    semantic_sources[semantic_tag].add(
                        f'exact-runtime-field:{field_label}@{access.get("fieldOffset")}')
                evidence.append({
                    "kind": "method-local-exact-runtime-field", "field": field_label,
                    "offset": access.get("fieldOffset"), "access": access.get("access"),
                    "instructionRva": access.get("instructionRva"), "base": access.get("baseProvenance"),
                    "sharedTags": shared,
                    "rationale": "CFG-typed object register + exact MetadataRegistration field offset",
                })
                if context_exact_field_hits >= 3:
                    break

            for ref in (ctx.get("stringRefs") or [])[:12]:
                value = str(ref.get("value") or "")
                ref_tags = tags(value)
                for semantic_tag in ref_tags:
                    semantic_sources[semantic_tag].add(f'method-local-string:{ref.get("xrefRva")}:{value[:80]}')
                shared = sorted(ctags & ref_tags)
                if not shared:
                    continue
                context_string_hits += 1
                score += 0.07
                context_score += 0.16
                evidence.append({
                    "kind": "method-local-string-xref", "value": value[:180],
                    "xrefRva": ref.get("xrefRva"), "targetRva": ref.get("targetRva"),
                    "sharedTags": shared,
                    "rationale": "ADRP+ADD resolves to printable data inside the candidate method interval",
                })
                if context_string_hits >= 3:
                    break

            candidate_owner = owner(label)
            if candidate_owner:
                for access in (ctx.get("thisOffsetCandidates") or [])[:16]:
                    off = access.get("offset")
                    if not isinstance(off, int):
                        continue
                    matches = fields_by_owner_offset.get((candidate_owner, off), [])
                    if not matches:
                        continue
                    # Exact class+offset match is required before a memory access
                    # can inherit a dump.cs field name.  Semantic overlap further
                    # protects against unrelated bookkeeping fields.
                    for fld in matches[:2]:
                        fld_label = str(fld.get("label") or "")
                        field_tags = set(fld.get("semantic") or []) or tags(fld_label)
                        for semantic_tag in field_tags:
                            semantic_sources[semantic_tag].add(f'field-offset:{fld_label}@{off}')
                        shared = sorted(ctags & field_tags)
                        if not shared:
                            continue
                        context_field_hits += 1
                        score += 0.10
                        context_score += 0.22
                        evidence.append({
                            "kind": "method-local-field-offset-match", "field": fld_label,
                            "offset": off, "access": access.get("access"),
                            "instructionRva": access.get("instructionRva"), "sharedTags": shared,
                            "rationale": "early this-relative load/store + exact dump.cs owner/offset corroboration",
                        })
                        break
                    if context_field_hits >= 3:
                        break

        if (label, rva) in structured_pairs:
            score += 0.08
            evidence.append({"kind": "structured-developer-api", "label": label, "rva": rva,
                             "rationale": "independent structured developer/debug API finding"})

        # Corroboration from a different artifact can raise correlation confidence,
        # but it cannot substitute for a uniquely attributed managed call relation.
        independent = 0
        for ev in c.get("corroboratingEvidence") or []:
            kind = str(ev.get("kind") or "")
            value = str(ev.get("value") or "")
            if kind not in {"unity-string", "addressables", "native-string", "artifact-string"}:
                continue
            ev_tags = tags(value)
            for semantic_tag in ev_tags:
                semantic_sources[semantic_tag].add(f'cross-artifact:{kind}:{ev.get("source")}:{value[:80]}')
            shared = sorted(ctags & ev_tags)
            if not shared:
                continue
            independent += 1
            score += 0.05
            evidence.append({"kind": "cross-artifact-semantic", "source": ev.get("source"),
                             "evidenceKind": kind, "value": value[:160], "sharedTags": shared})
            if independent >= 2:
                break

        corroborated_tags = {tag for tag, sources in semantic_sources.items() if len(sources) >= 2}
        effective_tags = set(ctags) | corroborated_tags
        semantic_anchor = bool(corroborated_tags)
        if semantic_anchor:
            score += min(0.14, 0.05 + 0.03 * len(corroborated_tags))
            evidence.append({
                "kind": "semantic-signal-corroboration",
                "tags": sorted(corroborated_tags),
                "sources": {tag: sorted(semantic_sources[tag])[:6] for tag in sorted(corroborated_tags)},
                "rationale": "at least two independent static semantic sources agree",
            })

        gameplay_tags = effective_tags & {"health", "damage", "movement", "state", "progression", "economy", "resource", "world", "cheat"}
        relevance = 8
        relevance += {"game-primary": 26, "custom-unknown": 12, "mixed-firstpass": 4,
                      "third-party-known": -24, "framework": -32}.get(provenance, -8)
        relevance += min(28, 8 * len(gameplay_tags))
        if exact_callable:
            relevance += 10
        if relational:
            relevance += min(16, 8 * relational)
        if context_relational:
            relevance += min(16, 8 * context_relational)
        if "debug" in ctags and not gameplay_tags:
            relevance += 2
        if diagnostic_only:
            relevance -= 22
        if technical_surface:
            relevance -= 38
        if (label_words & {"wrapper", "binding"}) or any(x in compact_label for x in ("luaopen", "luabinder")):
            relevance -= 22
        relevance = max(0, min(100, int(round(relevance))))
        c["gameplayRelevance"] = relevance
        c["gameplayRelevanceTier"] = ("high" if relevance >= 70 else
                                      "medium" if relevance >= 45 else
                                      "low" if relevance >= 20 else "technical")

        score = max(0.0, min(0.99, score))
        context_score = max(0.0, min(0.99, context_score + (0.22 if exact_callable else 0.0)
                                                + (0.10 if owned else 0.0)))
        promotable_provenance = provenance in {"game-primary", "custom-unknown"}
        verified = bool(promotable_provenance and not diagnostic_only and not technical_surface
                        and exact_callable and relational > 0 and semantic_anchor
                        and score >= float(min_verified_score))
        context_anchor = bool(context_relational > 0 or context_exact_field_hits > 0 or context_engine_sink_hits > 0)
        context_verified = bool(promotable_provenance and not diagnostic_only and not technical_surface
                                and exact_callable and context_anchor and semantic_anchor
                                and context_score >= 0.68)
        if verified:
            status = "verified-static-xref"
            blocker = None
            verified_count += 1
            verified_evidence.append({
                "artifact": image or "libil2cpp.so", "kind": "semantic-control-xref",
                "value": label[:240], "location": f"RVA 0x{int(rva):x}" if isinstance(rva, int) else "",
            })
        elif technical_surface:
            status = "review"
            blocker = "technical-rendering-or-quality-surface"
            review_count += 1
        elif provenance in {"framework", "third-party-known"}:
            status = "review"
            blocker = "non-game-primary-provenance"
            review_count += 1
        elif diagnostic_only:
            status = "review"
            blocker = "diagnostic-debug-surface-only"
            review_count += 1
        elif not semantic_anchor and score >= 0.48:
            status = "correlated-review"
            blocker = "semantic-signal-corroboration-required"
            correlated_count += 1
        elif score >= 0.48:
            status = "correlated-review"
            blocker = "semantic-direct-call-verification-required"
            correlated_count += 1
        else:
            status = "review"
            blocker = "semantic-context-insufficient"
            review_count += 1

        c["semanticStatus"] = status
        c["semanticVerified"] = verified
        c["semanticConfidence"] = round(score, 2)
        c["semanticTags"] = sorted(effective_tags)
        c["semanticCorroboratedTags"] = sorted(corroborated_tags)
        c["semanticSignalSources"] = {tag: sorted(sources)[:8] for tag, sources in semantic_sources.items() if sources}
        if c.get("methodVerification"):
            from modkit.reworkspace.method_evidence import apply_semantic_result
            c["methodVerification"] = apply_semantic_result(
                c.get("methodVerification") or {}, status=status,
                confidence=round(score, 2), verified=verified, tags=effective_tags)
        c["semanticEvidence"] = evidence[:24]
        c["semanticBlocker"] = blocker
        c["contextVerified"] = context_verified
        c["contextStatus"] = ("verified-method-context" if context_verified else
                              ("correlated-review" if context_score >= 0.48 else "review"))
        c["contextConfidence"] = round(context_score, 2)
        c["contextEvidence"] = [e for e in evidence if str(e.get("kind", "")).startswith("method-local-")][:24]
        c["contextBlocker"] = (None if context_verified else
                               ("technical-rendering-or-quality-surface" if technical_surface else
                                "non-game-primary-provenance" if provenance in {"framework", "third-party-known"} else
                                "diagnostic-debug-surface-only" if diagnostic_only else
                                "method-local-context-verification-required"))
        if c["contextBlocker"] and c.get("bindingBlocker") is None and c.get("bindingSuggestion"):
            c["bindingBlocker"] = c["contextBlocker"]
        if blocker and c.get("bindingBlocker") is None and c.get("bindingSuggestion"):
            c["bindingBlocker"] = blocker

    context_verified_count = sum(1 for c in candidates if c.get("contextVerified") is True)
    context_correlated_count = sum(1 for c in candidates if c.get("contextStatus") == "correlated-review")
    provenance_counts = defaultdict(int)
    for c in candidates:
        provenance_counts[str(c.get("provenance") or "unknown")] += 1
    candidates.sort(key=lambda c: (
        0 if c.get("contextVerified") else 1 if c.get("semanticVerified") else 2,
        -int(c.get("gameplayRelevance") or 0),
        -float(c.get("semanticConfidence") or 0.0),
        -float(c.get("confidence") or 0.0),
        str(c.get("title") or "").casefold(),
    ))

    report["controlProvenance"] = {
        "schema": "modkit-control-provenance-1.0",
        "counts": dict(sorted(provenance_counts.items())),
        "semantics": "Static assembly/namespace provenance for ranking only; it is not ownership proof.",
    }
    report["methodContextVerification"] = {
        "schema": "modkit-method-context-verification-1.0",
        "method": "exact metadata interval + outgoing managed BL + method-local string/field corroboration",
        "candidates": len(candidates), "verified": context_verified_count,
        "correlatedReview": context_correlated_count,
        "review": max(0, len(candidates) - context_verified_count - context_correlated_count),
        "semantics": "Static method-local context only; this does not prove runtime behavior or gameplay effect.",
    }

    summary = {
        "schema": "modkit-semantic-control-verification-1.2",
        "method": "metadata-callable + uniquely-attributed ARM64 direct-BL managed context",
        "threshold": float(min_verified_score),
        "candidates": len(candidates), "verified": verified_count,
        "correlatedReview": correlated_count, "review": review_count,
        "semantics": "Static semantic correlation only; it does not prove runtime behavior or game effect.",
    }
    report["semanticVerification"] = summary

    findings = report.setdefault("findings", [])
    findings[:] = [f for f in findings if f.get("id") != "re.semantic_control_xrefs"]
    if verified_evidence:
        findings.append({
            "id": "re.semantic_control_xrefs",
            "title": "Semantically correlated IL2CPP control methods",
            "category": "il2cpp_semantic_xrefs",
            "status": "correlated",
            "confidence": 0.97,
            "evidence": verified_evidence[:40],
            "rationale": (f"{verified_count} control candidate(s) have unique managed direct-call context "
                          "with same-owner or shared gameplay/debug semantics. This remains static evidence."),
        })
        findings.sort(key=lambda f: (-float(f.get("confidence", 0.0)), str(f.get("id", ""))))
    return report

def augment_structured_findings(report: dict) -> dict:
    """Add high-signal findings from address-bearing Rodroid calling contracts.

    This confirms the presence of a structured developer/debug API surface, not
    that any specific behavior has been exercised at runtime.
    """
    from modkit.reworkspace.signature import rodroid_signature_contract

    il2cpp = report.get("il2cpp") or {}
    rows = []
    for key in ("metadata_callable_methods", "metadata_resolved_methods", "discoveries", "candidates"):
        rows.extend(il2cpp.get(key, []) or [])
    evidence = []
    seen = set()
    for row in rows:
        label = str(row.get("label", ""))
        low = label.casefold()
        rva = row.get("rva")
        if not isinstance(rva, int) or rva <= 0:
            continue
        if not any(x in low for x in (".cheat.", "cheatgamehandler", "cheat_", "debug", "console", "noclip", "invic")):
            continue
        contract = row.get("signature_contract") or {}
        signature = str(contract.get("signature") or row.get("signature") or "")
        verified = rodroid_signature_contract(signature) if signature else contract
        if not verified.get("autoBindingSafe") or not verified.get("bindingSuggestion"):
            continue
        key = (label, rva)
        if key in seen:
            continue
        seen.add(key)
        evidence.append({
            "artifact": str(row.get("image") or "Rodroid"),
            "kind": "rodroid-call-contract",
            "value": label[:240],
            "location": f"RVA 0x{rva:x}",
            "signatureContract": verified,
        })
        if len(evidence) >= 40:
            break

    if len(evidence) < 2:
        return report

    unity_evidence = []
    for bundle in (report.get("unity") or {}).get("bundles", []) or []:
        source = str(bundle.get("apk_entry") or bundle.get("sha256") or "UnityFS bundle")
        for value in bundle.get("matched_strings", []) or []:
            text = str(value)
            if any(x in text.casefold() for x in ("cheat", "debug", "console", "noclip", "invic")):
                unity_evidence.append({
                    "artifact": source, "kind": "unity-control-marker", "value": text[:240], "location": ""
                })
                if len(unity_evidence) >= 12:
                    break
        if len(unity_evidence) >= 12:
            break

    finding = {
        "id": "re.structured_developer_control_api",
        "title": "Structured developer cheat/debug control API",
        "category": "developer_control_api",
        "status": "confirmed",
        "confidence": 0.98 if unity_evidence else 0.95,
        "evidence": evidence + unity_evidence,
        "rationale": (
            f"{len(evidence)} unique address-bearing Rodroid methods have conservative callable signatures"
            + (" and Unity assets independently expose cheat/debug control markers." if unity_evidence
               else ". This confirms an addressable developer/debug API surface; runtime behavior is not claimed until exercised.")
        ),
    }
    findings = report.setdefault("findings", [])
    findings[:] = [f for f in findings if f.get("id") != finding["id"]]
    findings.append(finding)
    findings.sort(key=lambda f: (-float(f.get("confidence", 0.0)), str(f.get("id", ""))))
    return report
