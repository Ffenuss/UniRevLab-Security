"""Fail-closed AutoMod planner over the unified Evidence Graph catalog.

Runtime layout and metadata identity are corroboration only. A no-RVA native recovery
may supply a preflight-eligible locator only after exact MethodDef identity, exact
CodeGenModule method-count proof, a file-backed executable pointer and global pointer
uniqueness. Even that recovery never makes a finding buildable by itself.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "modkit-automod-plan-1.4"
_IL2CPP_CROSSCHECK_SCHEMA = "modkit-il2cpp-crosscheck-1.0"
_METADATA_IDENTITY_SCHEMA = "modkit-il2cpp-metadata-identity-1.1"
_NATIVE_RECOVERY_SCHEMA = "modkit-il2cpp-no-rva-native-1.0"

_BUILD = "READY_TO_BUILD"
_PREFLIGHT = "READY_FOR_PREFLIGHT"
_RUNTIME = "RUNTIME_NEEDED"
_REVIEW = "REVIEW"
_AUDIT = "AUDIT_ONLY"
_EXCLUDED = "EXCLUDED"

_EXCLUDED_OWNERSHIP = {"FRAMEWORK", "FRAMEWORK_NOISE", "BUNDLED_SDK", "SDK_NOISE", "ENGINE"}
_APP_OWNERSHIP = {"APP", "APP_OR_GAME"}
_AUDIT_WORDS = (
    "server", "backend", "network", "endpoint", "authentication", "oauth", "session",
    "billing", "purchase", "payment", "entitlement", "subscription", "license",
    "certificate", "pinning", "crypto", "credential", "access token", "refresh token",
)


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                text = line.strip()
                if not text:
                    continue
                try:
                    value = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    rows.append(value)
    except Exception:
        return []
    return rows


def _fresh(outputs: list[Path], inputs: list[Path]) -> bool:
    if not outputs or not inputs:
        return False
    try:
        if any(not path.is_file() for path in outputs) or any(not path.is_file() for path in inputs):
            return False
        newest_input = max(path.stat().st_mtime_ns for path in inputs)
        oldest_output = min(path.stat().st_mtime_ns for path in outputs)
        return oldest_output >= newest_input
    except OSError:
        return False


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


def _norm_name(value: Any) -> str:
    text = str(value or "").strip()
    if "::" in text:
        text = text.rsplit("::", 1)[1]
    if "(" in text:
        text = text.split("(", 1)[0]
    return text.strip().casefold()


def _norm_class(value: Any) -> str:
    return str(value or "").strip().replace("/", ".").casefold()


def _audit_like(card: dict[str, Any]) -> bool:
    if card.get("serverAudit"):
        return True
    category = str(card.get("category") or "").casefold()
    title = str(card.get("title") or "").casefold()
    stage = str(card.get("verificationStage") or "").upper()
    status = str(card.get("status") or "").upper()
    if stage == "SERVER_AUDIT" or status == "SERVER_AUDIT":
        return True
    text = f"{category} {title}"
    return any(word in text for word in _AUDIT_WORDS)


def _locator_is_exact(card: dict[str, Any]) -> bool:
    locator = card.get("locator")
    if not isinstance(locator, dict) or not locator:
        return False
    if locator.get("rva") not in (None, "", 0, "0", "0x0"):
        return True
    if locator.get("codeOffset") is not None and (locator.get("class") or locator.get("signature")):
        return True
    if locator.get("entry") and (locator.get("symbol") or locator.get("offset") is not None):
        return True
    return False


def _runtime_index(runtime_correlation: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(runtime_correlation, dict):
        return {}
    rows = runtime_correlation.get("correlations")
    if not isinstance(rows, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        card_id = row.get("id")
        if card_id in (None, ""):
            continue
        if str(row.get("runtimeEvidence") or "") != "PROCFS_MODULE_LAYOUT" or bool(row.get("promotesBuildability")):
            continue
        out[str(card_id)] = row
    return out


def _runtime_view(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    return {
        "evidence": "PROCFS_MODULE_LAYOUT", "modulePath": row.get("modulePath"),
        "moduleBasename": row.get("moduleBasename"), "loadBaseHex": row.get("loadBaseHex"),
        "rvaHex": row.get("rvaHex"), "runtimeVaHex": row.get("runtimeVaHex"),
        "mapped": bool(row.get("mapped")), "mappingPerms": row.get("mappingPerms"),
        "matchMode": row.get("matchMode"), "promotesBuildability": False,
    }


def _ensure_il2cpp_crosscheck(root: Path) -> dict[str, Any]:
    metadata, library, methods = root / "metadata.bin", root / "library.so", root / "analysis.methods.jsonl"
    output, rows = root / "il2cpp-crosscheck.json", root / "il2cpp-crosscheck.methods.jsonl"
    inputs = [metadata, library, methods]
    if not all(path.is_file() for path in inputs): return {}
    existing = _load(output)
    if existing.get("schema") == _IL2CPP_CROSSCHECK_SCHEMA and not existing.get("error") and _fresh([output, rows], inputs): return existing
    if existing.get("error") and _fresh([output], inputs): return existing
    try:
        output.unlink(missing_ok=True);rows.unlink(missing_ok=True)
        from modkit.mobile.il2cpp_crosscheck import run_crosscheck
        return run_crosscheck(metadata, library, methods, output, rows)
    except Exception as exc:
        error = {"schema":"modkit-il2cpp-crosscheck-error-1.0","engine":"il2cpp.structural-crosscheck-embedded","error":str(exc),"promotesBuildability":False,"confirmsMethodToRvaAssociation":False}
        try: output.write_text(json.dumps(error,ensure_ascii=False,indent=2),encoding="utf-8")
        except Exception: pass
        return error


def _ensure_metadata_identity(root: Path) -> dict[str, Any]:
    metadata, methods = root / "metadata.bin", root / "analysis.methods.jsonl"
    output, rows = root / "il2cpp-metadata-identity.json", root / "il2cpp-metadata-identity.methods.jsonl"
    inputs = [metadata, methods]
    if not all(path.is_file() for path in inputs): return {}
    existing = _load(output)
    if existing.get("schema") == _METADATA_IDENTITY_SCHEMA and not existing.get("error") and _fresh([output, rows], inputs): return existing
    if existing.get("error") and _fresh([output], inputs): return existing
    try:
        output.unlink(missing_ok=True);rows.unlink(missing_ok=True)
        from modkit.mobile.il2cpp_metadata_identity import build_workspace_identity
        return build_workspace_identity(root, output)
    except Exception as exc:
        error = {"schema":"modkit-il2cpp-metadata-identity-error-1.1","engine":"il2cpp.metadata-identity-embedded","error":str(exc),"addressResolver":False,"actionable":False,"promotesBuildability":False}
        try: output.write_text(json.dumps(error,ensure_ascii=False,indent=2),encoding="utf-8")
        except Exception: pass
        return error


def _ensure_native_recovery(root: Path) -> dict[str, Any]:
    metadata, library, methods = root / "metadata.bin", root / "library.so", root / "analysis.methods.jsonl"
    output, rows = root / "il2cpp-no-rva-native.json", root / "il2cpp-no-rva-native.methods.jsonl"
    inputs = [metadata, library, methods]
    if not all(path.is_file() for path in inputs): return {}
    existing = _load(output)
    if existing.get("schema") == _NATIVE_RECOVERY_SCHEMA and not existing.get("error") and _fresh([output, rows], inputs): return existing
    if existing.get("error") and _fresh([output], inputs): return existing
    try:
        output.unlink(missing_ok=True);rows.unlink(missing_ok=True)
        from modkit.mobile.il2cpp_no_rva_native import recover_workspace
        return recover_workspace(root, output)
    except Exception as exc:
        error = {"schema":"modkit-il2cpp-no-rva-native-error-1.0","engine":"il2cpp.codegenmodule-native-recovery","error":str(exc),"addressResolver":True,"actionable":False,"buildable":False,"promotesBuildability":False}
        try: output.write_text(json.dumps(error,ensure_ascii=False,indent=2),encoding="utf-8")
        except Exception: pass
        return error


def _il2cpp_index(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    rank={"STRUCTURAL_BOTH_PRESENT":3,"ELF_EXECUTABLE_RVA_CONFIRMED":2,"METADATA_METHOD_NAME_CONFIRMED":1,"UNRESOLVED":0};out={}
    for row in rows:
        if not isinstance(row,dict) or bool(row.get("promotesBuildability")): continue
        rva=_number(row.get("rva"));rva=_number(row.get("rvaHex")) if rva is None else rva
        if rva is None or rva<0: continue
        current=out.get(rva)
        if current is None or rank.get(str(row.get("status")),-1)>rank.get(str(current.get("status")),-1): out[rva]=row
    return out


def _il2cpp_view(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(row,dict): return None
    return {"engine":"il2cpp.structural-crosscheck-embedded","status":row.get("status"),"methodName":row.get("methodName"),"rvaHex":row.get("rvaHex"),"metadataMethodNamePresent":bool(row.get("metadataMethodNamePresent")),"executableElfRangePresent":bool(row.get("executableElfRangePresent")),"elfRangeMode":row.get("elfRangeMode"),"segmentIndex":row.get("segmentIndex"),"associationConfirmed":False,"promotesBuildability":False}


def _identity_indexes(rows: list[dict[str, Any]]):
    by_id={};by_pair={};by_name={}
    for row in rows:
        if not isinstance(row,dict) or bool(row.get("promotesBuildability")) or bool(row.get("addressConfirmed")) or bool(row.get("actionable")) or bool(row.get("buildable")): continue
        status=str(row.get("status") or "UNRESOLVED_NO_RVA")
        if status in {"UNRESOLVED_NO_RVA","METADATA_TOKEN_CONFLICT_NO_RVA"}: continue
        row_id=row.get("id")
        if row_id not in (None,""): by_id[str(row_id)]=row
        method=_norm_name(row.get("methodName"));cls=_norm_class(row.get("class"))
        if method: by_name.setdefault(method,[]).append(row)
        if method and cls:
            by_pair.setdefault((cls,method),[]).append(row);short=cls.rsplit(".",1)[-1]
            if short!=cls: by_pair.setdefault((short,method),[]).append(row)
    return by_id,by_pair,by_name


def _card_method_id(card: dict[str, Any]) -> str:
    locator=card.get("locator") if isinstance(card.get("locator"),dict) else {}
    for key in ("methodId","metadataMethodId","methodIndex"):
        if locator.get(key) not in (None,""): return str(locator.get(key))
    return ""


def _identity_for_card(card: dict[str, Any], indexes):
    by_id,by_pair,by_name=indexes;locator=card.get("locator") if isinstance(card.get("locator"),dict) else {};method_id=_card_method_id(card)
    if method_id and method_id in by_id: return by_id[method_id]
    method=_norm_name(locator.get("method") or locator.get("methodName"));cls=_norm_class(locator.get("class") or locator.get("className"))
    if method and cls:
        matches=by_pair.get((cls,method),[])
        if len(matches)==1:return matches[0]
        short=cls.rsplit(".",1)[-1]
        if short!=cls:
            matches=by_pair.get((short,method),[])
            if len(matches)==1:return matches[0]
    if method and len(by_name.get(method,[]))==1:return by_name[method][0]
    return None


def _identity_view(row):
    if not isinstance(row,dict): return None
    status=str(row.get("status") or "UNRESOLVED_NO_RVA")
    if status in {"UNRESOLVED_NO_RVA","METADATA_TOKEN_CONFLICT_NO_RVA"}: return None
    return {"engine":"il2cpp.metadata-identity-embedded","status":status,"class":row.get("class"),"methodName":row.get("methodName"),"metadataMethodNamePresent":bool(row.get("metadataMethodNamePresent")),"metadataQualifiedMethodPresent":bool(row.get("metadataQualifiedMethodPresent")),"metadataToken":row.get("metadataToken"),"metadataTokenConfirmed":bool(row.get("metadataTokenConfirmed")),"metadataResolvedClass":row.get("metadataResolvedClass"),"metadataResolvedMethodName":row.get("metadataResolvedMethodName"),"addressConfirmed":False,"rva":None,"actionable":False,"buildable":False,"promotesBuildability":False}


def _native_recovery_indexes(rows: list[dict[str, Any]]):
    by_id={};by_pair={}
    for row in rows:
        if not isinstance(row,dict): continue
        rva=_number(row.get("rva"))
        if str(row.get("status") or "")!="NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE" or rva is None or rva<=0: continue
        if not row.get("addressConfirmed") or not row.get("associationConfirmed") or not row.get("uniqueExecutablePointer") or row.get("promotesBuildability"): continue
        safe={"engine":"il2cpp.codegenmodule-native-recovery","status":row.get("status"),"metadataMethodId":row.get("metadataMethodId"),"metadataToken":row.get("metadataToken"),"image":row.get("image"),"class":row.get("class"),"methodName":row.get("methodName"),"rva":rva,"rvaHex":row.get("rvaHex") or f"0x{rva:x}","addressConfirmed":True,"associationConfirmed":True,"uniqueExecutablePointer":True,"moduleResolution":row.get("moduleResolution"),"identityProof":row.get("identityProof"),"actionable":False,"buildable":False,"promotesBuildability":False}
        mid=row.get("metadataMethodId") if row.get("metadataMethodId") not in (None,"") else row.get("id")
        if mid not in (None,""): by_id[str(mid)]=safe
        method=_norm_name(row.get("methodName"));cls=_norm_class(row.get("class"))
        if method and cls:
            by_pair.setdefault((cls,method),[]).append(safe);short=cls.rsplit(".",1)[-1]
            if short!=cls: by_pair.setdefault((short,method),[]).append(safe)
    return by_id,by_pair


def _native_for_card(card: dict[str, Any], indexes):
    by_id,by_pair=indexes;mid=_card_method_id(card)
    if mid and mid in by_id:return by_id[mid]
    locator=card.get("locator") if isinstance(card.get("locator"),dict) else {};method=_norm_name(locator.get("method") or locator.get("methodName"));cls=_norm_class(locator.get("class") or locator.get("className"))
    if method and cls:
        matches=by_pair.get((cls,method),[])
        if len(matches)==1:return matches[0]
        short=cls.rsplit(".",1)[-1]
        if short!=cls:
            matches=by_pair.get((short,method),[])
            if len(matches)==1:return matches[0]
    return None


def _classify(card: dict[str, Any], native_recovery: dict[str, Any] | None = None) -> tuple[str,str]:
    ownership=str(card.get("ownership") or "UNKNOWN").upper();stage=str(card.get("verificationStage") or "FOUND_STATIC").upper();status=str(card.get("status") or "").upper()
    if card.get("externalCorroborating"): return _EXCLUDED,"Внешняя corroboration-находка не становится patch-point без локального подтверждения."
    if ownership in _EXCLUDED_OWNERSHIP:return _EXCLUDED,"SDK/framework/runtime marker исключён из автоматической модификации."
    if _audit_like(card):return _AUDIT,"Server/payment/auth/network/trust evidence сохраняется только для аудита."
    app_owned=ownership in _APP_OWNERSHIP;native_exact=bool(native_recovery and native_recovery.get("addressConfirmed") and native_recovery.get("associationConfirmed") and native_recovery.get("uniqueExecutablePointer"));exact_locator=_locator_is_exact(card) or bool(card.get("actionable")) or native_exact;patch_ready=bool(card.get("buildable")) and stage=="PATCH_READY" and app_owned
    if patch_ready:return _BUILD,"Есть проверенный локальный executable binding; допустим signed build после обязательного preflight."
    if app_owned and native_exact:return _PREFLIGHT,"Exact CodeGenModule recovery восстановил уникальный executable RVA; нужен обычный binding/preflight, buildability не повышена."
    if app_owned and exact_locator:return _PREFLIGHT,"Есть локальный точный locator; нужен smart prepare/preflight для validated executable binding."
    if app_owned and stage in {"RUNTIME_CONFIRMED","FLOW_CONFIRMED","LOCATOR_CONFIRMED"}:return _RUNTIME,"Evidence сильное, но ещё не доказан безопасный executable binding для автосборки."
    if app_owned and stage in {"APP_OWNED","FOUND_STATIC"}:return _REVIEW,"App-owned статическая находка; требуется flow/runtime/locator подтверждение."
    if status.startswith("READY") and exact_locator:return _PREFLIGHT,"Есть точный локатор; перед сборкой требуется fail-closed preflight."
    return _REVIEW,"Находка полезна для ручной проверки, но её недостаточно для автоматической модификации."


def _candidate(card,runtime_by_id,il2cpp_by_rva,identity_indexes,native_indexes):
    locator=card.get("locator") if isinstance(card.get("locator"),dict) else None;rva=_number(locator.get("rva")) if locator else None;native=_native_for_card(card,native_indexes) if rva is None else None;stage,reason=_classify(card,native);runtime=_runtime_view(runtime_by_id.get(str(card.get("id"))));il2cpp=_il2cpp_view(il2cpp_by_rva.get(rva)) if rva is not None else None;identity=_identity_view(_identity_for_card(card,identity_indexes)) if rva is None else None
    if runtime and runtime.get("mapped"):reason+=" Runtime VA наблюдался в procfs layout; это corroboration и не заменяет executable binding/preflight."
    if il2cpp and il2cpp.get("status")=="STRUCTURAL_BOTH_PRESENT":reason+=" IL2CPP cross-check отдельно подтвердил metadata method name и executable ELF range; их ассоциация этим backend'ом не считается доказанной."
    if native:reason+=" Native recovery подтвердил точную MethodDef→CodeGenModule→unique executable pointer ассоциацию; recovered RVA допускается только к preflight."
    if identity:
        if identity.get("metadataTokenConfirmed"):reason+=" Global metadata подтверждает method token и identity."
        elif identity.get("metadataQualifiedMethodPresent"):reason+=" Global metadata независимо подтверждает точный Class::Method."
        else:reason+=" Global metadata подтверждает имя метода без уникального Class::Method."
    resolved_locator=None
    if native:resolved_locator={"rva":native.get("rva"),"rvaHex":native.get("rvaHex"),"source":"EXACT_CODEGENMODULE_RECOVERY","addressConfirmed":True,"associationConfirmed":True}
    return {"id":card.get("id"),"title":card.get("title"),"category":card.get("category"),"source":card.get("source"),"stage":stage,"reason":reason,"sourceStatus":card.get("status"),"verificationStage":card.get("verificationStage"),"ownership":card.get("ownership"),"gameplayDomain":card.get("gameplayDomain"),"priority":int(card.get("priority") or 0),"buildable":bool(card.get("buildable")),"actionable":bool(card.get("actionable")),"serverAudit":bool(card.get("serverAudit")),"externalCorroborating":bool(card.get("externalCorroborating")),"locator":locator,"resolvedLocator":resolved_locator,"nativeRvaRecovered":bool(native),"nativeRvaRecovery":native,"runtimeObserved":bool(runtime and runtime.get("mapped")),"runtimeObservation":runtime,"il2cppStructuralObserved":bool(il2cpp and (il2cpp.get("metadataMethodNamePresent") or il2cpp.get("executableElfRangePresent"))),"il2cppStructural":il2cpp,"metadataIdentityObserved":bool(identity),"metadataIdentity":identity,"readyReason":card.get("readyReason"),"notReadyReason":card.get("notReadyReason")}


def build_plan(catalog: dict[str,Any],runtime_correlation: dict[str,Any]|None=None,il2cpp_crosscheck_rows: list[dict[str,Any]]|None=None,metadata_identity_rows: list[dict[str,Any]]|None=None,native_recovery_rows: list[dict[str,Any]]|None=None)->dict[str,Any]:
    cards=catalog.get("cards") if isinstance(catalog.get("cards"),list) else [];runtime_by_id=_runtime_index(runtime_correlation);il2cpp_by_rva=_il2cpp_index(il2cpp_crosscheck_rows or []);identity_indexes=_identity_indexes(metadata_identity_rows or []);native_indexes=_native_recovery_indexes(native_recovery_rows or []);candidates=[_candidate(card,runtime_by_id,il2cpp_by_rva,identity_indexes,native_indexes) for card in cards if isinstance(card,dict)];order={_BUILD:0,_PREFLIGHT:1,_RUNTIME:2,_REVIEW:3,_AUDIT:4,_EXCLUDED:5};candidates.sort(key=lambda row:(order.get(str(row.get("stage")),99),-int(row.get("priority") or 0),str(row.get("title") or "").casefold()));counts=Counter(str(row.get("stage") or _REVIEW) for row in candidates);gameplay=Counter(str(row.get("gameplayDomain")) for row in candidates if row.get("gameplayDomain") and row.get("stage") not in {_AUDIT,_EXCLUDED});exact=sum(1 for card in cards if isinstance(card,dict) and _locator_is_exact(card));runtime_observed=sum(1 for row in candidates if row.get("runtimeObserved"));il2cpp_observed=sum(1 for row in candidates if row.get("il2cppStructuralObserved"));il2cpp_both=sum(1 for row in candidates if isinstance(row.get("il2cppStructural"),dict) and row["il2cppStructural"].get("status")=="STRUCTURAL_BOTH_PRESENT");metadata_observed=sum(1 for row in candidates if row.get("metadataIdentityObserved"));metadata_qualified=sum(1 for row in candidates if isinstance(row.get("metadataIdentity"),dict) and row["metadataIdentity"].get("metadataQualifiedMethodPresent"));metadata_token=sum(1 for row in candidates if isinstance(row.get("metadataIdentity"),dict) and row["metadataIdentity"].get("metadataTokenConfirmed"));native_recovered=sum(1 for row in candidates if row.get("nativeRvaRecovered"))
    return {"schema":SCHEMA,"source":"simple-catalog.json","runtimeSource":"runtime-correlation.json" if runtime_by_id else None,"il2cppCrosscheckSource":"il2cpp-crosscheck.methods.jsonl" if il2cpp_by_rva else None,"il2cppMetadataIdentitySource":"il2cpp-metadata-identity.methods.jsonl" if metadata_observed else None,"il2cppNativeRecoverySource":"il2cpp-no-rva-native.methods.jsonl" if native_recovered else None,"failClosed":True,"modifiesTarget":False,"runtimeEvidencePromotesBuildability":False,"il2cppCrosscheckPromotesBuildability":False,"metadataIdentityPromotesBuildability":False,"nativeRecoveryPromotesBuildability":False,"nativeRecoveryMayEnterPreflight":True,"autoBuildRequiresValidatedExecutableBinding":True,"serverBypassGenerated":False,"counts":{stage:int(counts.get(stage,0)) for stage in (_BUILD,_PREFLIGHT,_RUNTIME,_REVIEW,_AUDIT,_EXCLUDED)},"gameplayCounts":dict(sorted(gameplay.items())),"exactLocatorCount":exact,"nativeRecoveredLocatorCount":native_recovered,"runtimeObservedCount":runtime_observed,"il2cppStructuralObservedCount":il2cpp_observed,"il2cppStructuralBothCount":il2cpp_both,"metadataIdentityObservedCount":metadata_observed,"metadataQualifiedNoRvaCount":metadata_qualified,"metadataTokenNoRvaCount":metadata_token,"readyToBuildCount":int(counts.get(_BUILD,0)),"readyForPreflightCount":int(counts.get(_PREFLIGHT,0)),"runtimeNeededCount":int(counts.get(_RUNTIME,0)),"reviewCount":int(counts.get(_REVIEW,0)),"auditOnlyCount":int(counts.get(_AUDIT,0)),"excludedCount":int(counts.get(_EXCLUDED,0)),"candidateCount":len(candidates),"candidates":candidates}


def build_workspace_plan(workdir: str|Path,output_path: str|Path|None=None)->dict[str,Any]:
    root=Path(workdir);catalog_path=root/"simple-catalog.json";catalog=_load(catalog_path)
    if not catalog:
        from modkit.mobile.simple_mode import build_catalog
        catalog=build_catalog(root,catalog_path)
    runtime_correlation=_load(root/"runtime-correlation.json");il2cpp_summary=_ensure_il2cpp_crosscheck(root);il2cpp_rows=_load_jsonl(root/"il2cpp-crosscheck.methods.jsonl") if il2cpp_summary and not il2cpp_summary.get("error") else [];identity_summary=_ensure_metadata_identity(root);identity_rows=_load_jsonl(root/"il2cpp-metadata-identity.methods.jsonl") if identity_summary and not identity_summary.get("error") else [];native_summary=_ensure_native_recovery(root);native_rows=_load_jsonl(root/"il2cpp-no-rva-native.methods.jsonl") if native_summary and not native_summary.get("error") else []
    out=build_plan(catalog,runtime_correlation if runtime_correlation else None,il2cpp_rows,identity_rows,native_rows)
    if il2cpp_summary:out["il2cppCrosscheck"]={"schema":il2cpp_summary.get("schema"),"engine":il2cpp_summary.get("engine"),"error":il2cpp_summary.get("error"),"counts":il2cpp_summary.get("counts"),"confirmsMethodToRvaAssociation":bool(il2cpp_summary.get("confirmsMethodToRvaAssociation")),"promotesBuildability":False}
    if identity_summary:out["il2cppMetadataIdentity"]={"schema":identity_summary.get("schema"),"engine":identity_summary.get("engine"),"error":identity_summary.get("error"),"typeLayout":identity_summary.get("typeLayout"),"uniqueMethodTokenCount":int(identity_summary.get("uniqueMethodTokenCount") or 0),"counts":identity_summary.get("counts"),"addressResolver":False,"actionable":False,"promotesBuildability":False}
    if native_summary:out["il2cppNativeRecovery"]={"schema":native_summary.get("schema"),"engine":native_summary.get("engine"),"error":native_summary.get("error"),"resolvedModuleCount":int(native_summary.get("resolvedModuleCount") or 0),"counts":native_summary.get("counts"),"addressResolver":bool(native_summary.get("addressResolver")),"requiresUniqueExecutablePointer":bool(native_summary.get("requiresUniqueExecutablePointer")),"actionable":False,"buildable":False,"promotesBuildability":False,"mayEnterPreflight":True}
    destination=Path(output_path) if output_path else root/"automod-plan.json";destination.write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding="utf-8");return out
