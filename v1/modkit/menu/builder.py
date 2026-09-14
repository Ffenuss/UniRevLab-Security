"""Declarative menu-spec builder.

The builder intentionally separates UI description from binary integration.  Each
control can reference a *confirmed* analysis finding/RVA and the generated project
contains an auditable mapping instead of hard-coded opaque offsets in UI code.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
import hashlib
import json
from pathlib import Path
import re
import zipfile

_ALLOWED = {"toggle", "button", "slider_int", "slider_float", "label"}
_BINDINGS = {None, "action", "bool_setter", "number_setter"}
_CALL_ABIS = {"native", "il2cpp"}
_RESOLVERS = {None, "out_ptr_bool", "return_ptr"}


@dataclass(slots=True)
class MenuControl:
    id: str
    title: str
    type: str
    category: str = "General"
    finding_id: str | None = None
    rva: int | None = None
    min_value: float | None = None
    max_value: float | None = None
    default: float | bool | None = None
    note: str = ""
    # Calling convention is intentionally separate from the visual control type.
    # Auto-discovered RVAs keep binding=None until an analyst explicitly confirms
    # how the function is safe to call.
    binding: str | None = None
    target_so: str = "libil2cpp.so"
    is_static: bool = True
    value_type: str = "auto"
    # Static-analysis provenance. These fields never make a control executable by
    # themselves; they only preserve why the candidate was suggested.
    suggested_type: str | None = None
    evidence_rva: int | None = None
    evidence_source: str = ""
    evidence_kind: str = ""
    evidence_location: str = ""
    evidence_confidence: float | None = None
    evidence_status: str = ""
    evidence_count: int = 0
    corroborating_evidence: list[dict] = field(default_factory=list)
    suggested_target_so: str | None = None
    suggested_binding: str | None = None
    evidence_is_static: bool | None = None
    binding_blocker: str | None = None
    evidence_signature: str = ""
    call_abi: str = "native"
    resolver_rva: int | None = None
    resolver_kind: str | None = None
    resolver_label: str = ""
    resolver_source: str = ""
    resolver_verified: bool = False
    resolver_match: str = ""
    resolver_target_class: str = ""
    resolver_contract_source: str = ""
    resolver_signature: str = ""
    # Dev14 semantic/xref provenance. None means a legacy/manual control which
    # predates semantic verification; False is an explicit verifier result.
    semantic_verified: bool | None = None
    semantic_status: str = ""
    semantic_confidence: float | None = None
    semantic_tags: list[str] = field(default_factory=list)
    semantic_evidence: list[dict] = field(default_factory=list)
    semantic_blocker: str | None = None
    # Dev15 bounded method-local context. None preserves compatibility with
    # legacy/manual MenuSpecs; False is an explicit dev15 verifier result.
    context_verified: bool | None = None
    context_status: str = ""
    context_confidence: float | None = None
    context_evidence: list[dict] = field(default_factory=list)
    context_blocker: str | None = None
    gameplay_relevance: int | None = None
    gameplay_relevance_tier: str = ""
    # Dev21 universal evidence model.  Kept as a nested record so future
    # evidence layers can evolve without expanding MenuControl every release.
    method_verification: dict = field(default_factory=dict)
    # Dev29 read-only runtime probe metadata. Probe controls are never executable
    # bindings: they resolve a live IL2CPP object by exact class identity and read
    # one exact runtime field offset for observation/correlation only.
    probe_kind: str | None = None
    probe_owner: str = ""
    probe_field: str = ""
    probe_offset: int | None = None
    probe_primitive: str = ""
    probe_status: str = ""

    def __post_init__(self) -> None:
        if self.value_type == "auto":
            if self.type == "slider_float":
                self.value_type = "System.Single"
            elif self.type == "toggle":
                self.value_type = "System.Boolean"
            else:
                self.value_type = "System.Int32"

    def validate(self) -> None:
        if self.type not in _ALLOWED:
            raise ValueError(f"unsupported control type: {self.type}")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", self.id):
            raise ValueError("control id must be a stable ASCII identifier")
        if self.type.startswith("slider"):
            if self.min_value is None or self.max_value is None or self.min_value >= self.max_value:
                raise ValueError("slider requires min_value < max_value")
        if self.binding not in _BINDINGS:
            raise ValueError(f"unsupported binding: {self.binding}")
        if self.probe_kind not in {None, "watch"}:
            raise ValueError(f"unsupported probe kind: {self.probe_kind}")
        if self.probe_kind is not None:
            if self.binding is not None:
                raise ValueError("read-only probe controls cannot have executable bindings")
            if not self.probe_owner or not self.probe_field:
                raise ValueError("probe controls require exact owner and field identity")
            if self.probe_offset is None or int(self.probe_offset) < 0:
                raise ValueError("probe controls require a non-negative exact runtime field offset")
            if self.probe_primitive not in {"bool", "int32", "uint32", "float"}:
                raise ValueError(f"unsupported probe primitive: {self.probe_primitive}")
        if self.call_abi not in _CALL_ABIS:
            raise ValueError(f"unsupported call ABI: {self.call_abi}")
        if self.resolver_kind not in _RESOLVERS:
            raise ValueError(f"unsupported instance resolver: {self.resolver_kind}")
        if self.binding is not None and self.rva is None:
            raise ValueError("an executable binding requires an RVA")
        if self.binding is not None and not self.is_static:
            if self.call_abi != "il2cpp":
                raise ValueError("instance bindings currently require il2cpp call ABI")
            if not self.resolver_rva or self.resolver_rva <= 0 or self.resolver_kind not in {"out_ptr_bool", "return_ptr"}:
                raise ValueError("instance binding requires a confirmed instance resolver RVA")
            if not self.resolver_verified:
                raise ValueError("instance binding requires a type-verified instance resolver")
        if self.binding == "action" and self.type != "button":
            raise ValueError("action binding requires button control")
        if self.binding == "bool_setter" and self.type != "toggle":
            raise ValueError("bool_setter binding requires toggle control")
        if self.binding == "number_setter" and not self.type.startswith("slider"):
            raise ValueError("number_setter binding requires slider control")
        if self.binding == "number_setter":
            expected = "System.Int32" if self.type == "slider_int" else "System.Single"
            if self.value_type != expected:
                raise ValueError(f"generic runtime {self.type} requires {expected}, got {self.value_type}")


@dataclass(slots=True)
class MenuSpec:
    title: str = "ModKit Menu"
    icon_text: str = "MK"
    controls: list[MenuControl] = field(default_factory=list)
    target_sha256: str = ""
    source_apk_sha256: str = ""

    def validate(self) -> None:
        for name, value in (("target_sha256", self.target_sha256), ("source_apk_sha256", self.source_apk_sha256)):
            if value and not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                raise ValueError(f"{name} must be a 64-character SHA-256 hex digest")
        ids = set()
        for c in self.controls:
            c.validate()
            if c.id in ids:
                raise ValueError(f"duplicate control id: {c.id}")
            ids.add(c.id)

    def json(self) -> dict:
        self.validate()
        return {"schema": "modkit-menu-1.1", "title": self.title, "iconText": self.icon_text,
                "targetSha256": self.target_sha256, "sourceApkSha256": self.source_apk_sha256,
                "controls": [asdict(c) for c in self.controls]}


def spec_from_analysis(analysis: dict, title: str = "ModKit Menu") -> MenuSpec:
    """Seed reviewable controls from RE candidates and stronger findings.

    Control candidates are still labels: suggested visual type and evidence RVA
    are advisory only.  Executable binding remains None until analyst review.
    """
    controls: list[MenuControl] = []
    used = set()

    for candidate in analysis.get("controlCandidates", [])[:120]:
        evidence_kind = str(candidate.get("kind") or "")
        verification = candidate.get("methodVerification") or {}
        # DEX strings/classes are useful application-discovery evidence, but the
        # native Menu runtime cannot execute them. Do not turn a string such as
        # `enableDeveloperModeWhenDebuggable=false` into a fake toggle/number
        # control. It may enter Menu Builder only after a future/explicit DEX
        # patch contract proves the owning method and mutation semantics.
        if evidence_kind.startswith("dex-") and not verification.get("executableDexPatchReady"):
            continue
        base = re.sub(r"[^A-Za-z0-9]+", "_", candidate.get("id", "candidate")).strip("_")[:40] or "candidate"
        cid = base; n = 2
        while cid in used:
            cid = f"{base}_{n}"; n += 1
        used.add(cid)
        suggested = str(candidate.get("suggestedType", "review"))
        # A visual suggestion is harmless and useful in the review UI, but it is
        # not a calling-convention claim. Slider-or-toggle remains a label until
        # the analyst chooses the exact control semantics.
        visual = suggested if suggested in {"toggle", "button"} else "label"
        source = str(candidate.get("source", ""))
        suggested_so = None
        source_name = source.replace("\\", "/").rsplit("/", 1)[-1]
        if re.fullmatch(r"lib[^/\\\x00]+\.so", source_name):
            suggested_so = source_name
        note = (f"Suggested control: {suggested}. {candidate.get('rationale','')} "
                f"Source: {source} · {candidate.get('kind','')} · {candidate.get('location','')}").strip()
        contract = candidate.get("signatureContract") or {}
        resolver = candidate.get("instanceResolver") or {}
        evidence_value_type = str(contract.get("managedValueType") or "System.Int32")
        controls.append(MenuControl(
            cid, candidate.get("title", cid), visual, str(candidate.get("category") or "Detected controls"),
            finding_id=candidate.get("id"), rva=None, note=note, binding=None,
            suggested_type=suggested, evidence_rva=candidate.get("evidenceRva"),
            evidence_source=source, evidence_kind=str(candidate.get("kind", "")),
            is_static=bool(candidate.get("isStatic")) if candidate.get("isStatic") is not None else True,
            evidence_location=str(candidate.get("location", "")),
            evidence_confidence=float(candidate.get("confidence", 0.0)) if candidate.get("confidence") is not None else None,
            evidence_status=str(candidate.get("status", "review")), evidence_count=int(candidate.get("evidenceCount", 1) or 1),
            corroborating_evidence=list(candidate.get("corroboratingEvidence") or [])[:24],
            suggested_target_so=suggested_so, suggested_binding=candidate.get("bindingSuggestion"),
            evidence_is_static=candidate.get("isStatic"), binding_blocker=candidate.get("bindingBlocker"),
            value_type=evidence_value_type,
            evidence_signature=str((candidate.get("signatureContract") or {}).get("signature", "")),
            call_abi="il2cpp" if candidate.get("signatureContract") else "native",
            resolver_rva=candidate.get("resolverRva"), resolver_kind=candidate.get("resolverKind"),
            resolver_label=str(resolver.get("label", "")),
            resolver_source=str(resolver.get("source", "")),
            resolver_verified=bool(candidate.get("resolverVerified") or resolver.get("verified")),
            resolver_match=str(candidate.get("resolverMatch") or resolver.get("match") or ""),
            resolver_target_class=str(resolver.get("targetClass") or ""),
            resolver_contract_source=str(resolver.get("contractSource") or ""),
            resolver_signature=str((resolver.get("contract") or {}).get("signature", "")),
            semantic_verified=(bool(candidate.get("semanticVerified"))
                               if "semanticVerified" in candidate else None),
            semantic_status=str(candidate.get("semanticStatus") or ""),
            semantic_confidence=(float(candidate.get("semanticConfidence"))
                                 if candidate.get("semanticConfidence") is not None else None),
            semantic_tags=list(candidate.get("semanticTags") or [])[:24],
            semantic_evidence=list(candidate.get("semanticEvidence") or [])[:24],
            semantic_blocker=candidate.get("semanticBlocker"),
            context_verified=(bool(candidate.get("contextVerified"))
                              if "contextVerified" in candidate else None),
            context_status=str(candidate.get("contextStatus") or ""),
            context_confidence=(float(candidate.get("contextConfidence"))
                                if candidate.get("contextConfidence") is not None else None),
            context_evidence=list(candidate.get("contextEvidence") or [])[:24],
            context_blocker=candidate.get("contextBlocker"),
            gameplay_relevance=(int(candidate.get("gameplayRelevance")) if candidate.get("gameplayRelevance") is not None else None),
            gameplay_relevance_tier=str(candidate.get("gameplayRelevanceTier") or ""),
            method_verification=dict(candidate.get("methodVerification") or {}),
        ))

    for finding in analysis.get("findings", []):
        if finding.get("status") not in {"confirmed", "correlated"}:
            continue
        rvas = []
        for ev in finding.get("evidence", []):
            loc = str(ev.get("location", ""))
            m = re.search(r"RVA\s+0x([0-9a-fA-F]+)", loc)
            if m:
                rvas.append(int(m.group(1), 16))
        base = re.sub(r"[^A-Za-z0-9]+", "_", finding.get("id", "finding")).strip("_")[:40] or "finding"
        cid = base; n = 2
        while cid in used:
            cid = f"{base}_{n}"; n += 1
        used.add(cid)
        if rvas:
            controls.append(MenuControl(
                cid, finding.get("title", cid), "label", "Detected findings", finding.get("id"), rvas[0],
                note=f"Finding has RVA evidence 0x{rvas[0]:x}, retained as provenance only. Review exact symbol/signature before binding.",
                evidence_rva=rvas[0], evidence_confidence=float(finding.get("confidence", 0.0)),
                evidence_kind="finding-rva", evidence_source=str(finding.get("id", "")),
            ))
        else:
            controls.append(MenuControl(cid, finding.get("title", cid), "label", "Detected findings", finding.get("id"), note="Evidence found, but no unique callable RVA is available yet."))
    target_sha256 = ""
    for native in (analysis.get("inventory") or {}).get("native", []) or []:
        name = str(native.get("soname") or native.get("name") or "").replace("\\", "/").rsplit("/", 1)[-1]
        if name == "libil2cpp.so" and re.fullmatch(r"[0-9a-fA-F]{64}", str(native.get("sha256") or "")):
            target_sha256 = str(native.get("sha256")).lower()
            break
    source_apk_sha256 = str((analysis.get("apk") or {}).get("sha256") or "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", source_apk_sha256):
        source_apk_sha256 = ""
    return MenuSpec(title=title, controls=controls, target_sha256=target_sha256,
                    source_apk_sha256=source_apk_sha256.lower())


def _runtime_plan(spec: MenuSpec):
    """Translate only explicitly bound controls into the existing audited codegen IR."""
    from modkit.ir import Feature, FeatureKind, Plan, Program

    executable = [c for c in spec.controls if c.binding is not None]
    target_sos = {c.target_so for c in executable}
    if len(target_sos) > 1:
        raise ValueError("one runtime project can target only one native module")
    target_so = next(iter(target_sos), "libil2cpp.so")
    program = Program(source="modkit-menu-spec", so_name=target_so)
    features = []
    for c in executable:
        if c.binding == "action":
            kind, arg_type = FeatureKind.ACTION, None
        elif c.binding == "bool_setter":
            kind, arg_type = FeatureKind.TOGGLE, "System.Boolean"
        elif c.binding == "number_setter":
            kind = FeatureKind.SLIDER
            arg_type = "System.Int32" if c.type == "slider_int" else "System.Single"
        else:
            continue
        features.append(Feature(
            id=c.id,
            label=c.title,
            group=c.category,
            kind=kind,
            cls="MenuBinding",
            member=c.id,
            c_type="System.Void",
            arg_type=arg_type,
            value=c.default if c.default is not None else (1 if c.type != "slider_float" else 1.0),
            min_value=c.min_value if c.min_value is not None else 0,
            max_value=c.max_value if c.max_value is not None else 1,
            rva=c.rva,
            is_static=c.is_static,
            needs_instance=not c.is_static,
            confidence=1.0,
            notes=["Explicitly bound in Menu Builder"],
        ))
    # Instance-bound raw controls need a separately confirmed capture method. Do
    # not generate a silently invalid call.  This stage currently supports static
    # or native-wrapper bindings only.
    bad = [f.id for f in features if f.needs_instance]
    if bad:
        raise ValueError("instance bindings need a confirmed capture hook: " + ", ".join(bad))
    return Plan(program=program, features=features, notes=[
        "Generated from explicit Menu Builder bindings; auto-discovered review labels are not callable."
    ])


def write_project(spec: MenuSpec, output_dir: str | Path) -> dict:
    spec.validate()
    out = Path(output_dir)
    (out / "assets").mkdir(parents=True, exist_ok=True)
    (out / "native").mkdir(parents=True, exist_ok=True)
    data = spec.json()
    (out / "assets" / "modkit-menu.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "// Generated by ModKit Menu Builder. Review bindings before compilation.",
        "#pragma once",
        "#include <cstdint>",
        "namespace modkit_menu {",
        "struct Binding { const char* id; std::uint64_t rva; const char* call; };",
        "static constexpr Binding kBindings[] = {",
    ]
    for c in spec.controls:
        if c.rva is not None:
            call = c.binding or "review"
            lines.append(f'  {{"{c.id}", 0x{c.rva:x}ULL, "{call}"}},')
    lines.extend(["};", "}"])
    (out / "native" / "bindings.generated.h").write_text("\n".join(lines) + "\n", encoding="utf-8")

    executable = [c for c in spec.controls if c.binding is not None]
    probes = [c for c in spec.controls if c.probe_kind is not None]
    runtime = None
    runtime_mode = "none"
    if probes and not executable:
        runtime_mode = "built-in-generic-probe-config"
        runtime_dir = out / "runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        (runtime_dir / "MENU-SPEC.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        (runtime_dir / "README.txt").write_text(
            "This menu uses ModKit built-in runtime config v4 in read-only WATCH/PROBE mode.\n"
            "Probe entries resolve exact IL2CPP class identity and read exact field offsets; no setter or patch is executed.\n",
            encoding="utf-8")
        runtime = str(runtime_dir)
    elif executable:
        # IL2CPP ABI and instance+resolver calls are executed by the audited
        # built-in generic runtime.  The older standalone code generator only
        # models raw native/static calls and must never silently erase MethodInfo
        # or the instance resolver contract.
        generic_required = any((c.call_abi == "il2cpp" or not c.is_static) for c in executable)
        if generic_required:
            runtime_mode = "built-in-generic-config"
            runtime_dir = out / "runtime"
            runtime_dir.mkdir(parents=True, exist_ok=True)
            (runtime_dir / "MENU-SPEC.json").write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            (runtime_dir / "README.txt").write_text(
                "This menu uses ModKit's built-in generic runtime config v2.\n"
                "IL2CPP and instance resolver ABI is preserved in MENU-SPEC.json.\n",
                encoding="utf-8")
            runtime = str(runtime_dir)
        else:
            from modkit.codegen.project import BuildOptions, write_project as write_codegen_project
            plan = _runtime_plan(spec)
            runtime_dir = out / "runtime"
            package = "dev.modkit.generated"
            write_codegen_project(plan, runtime_dir, BuildOptions(
                package=package, app_name="ModKitMenu", abi="arm64-v8a",
                overlay=True, imgui=True, dobby=False, force=True, autoload=True,
            ))
            # Preserve the high-level spec beside the generated IR/code for audit.
            (runtime_dir / "MENU-SPEC.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            runtime = str(runtime_dir)
            runtime_mode = "standalone-native-project"

    return {
        "path": str(out),
        "controls": len(spec.controls),
        "rvaBindings": sum(c.rva is not None for c in spec.controls),
        "executableBindings": len(executable),
        "reviewBindings": sum(c.rva is not None and c.binding is None and c.probe_kind is None for c in spec.controls),
        "readOnlyProbes": len(probes),
        "runtimeProject": runtime,
        "runtimeMode": runtime_mode,
    }



def validate_bindings(spec: MenuSpec, source_apk: str | Path) -> dict:
    """Validate executable bindings and any instance resolver against the APK.

    A callable RVA is accepted only when it is file-backed and executable in the
    requested ARM64 image.  Instance IL2CPP controls must additionally carry a
    type-verified supported resolver whose RVA passes the same checks.
    """
    from modkit.arch import arm64
    from modkit.elf.reader import ElfFile

    spec.validate()
    source_apk = Path(source_apk)
    checks: list[dict] = []
    issues: list[dict] = []
    source_apk_hash = ""
    if spec.source_apk_sha256:
        h = hashlib.sha256()
        with source_apk.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        source_apk_hash = h.hexdigest()
        if source_apk_hash != spec.source_apk_sha256.lower():
            issues.append({"severity": "BLOCK", "code": "SOURCE_APK_HASH_MISMATCH",
                           "message": "source APK SHA-256 no longer matches the RE report used to seed Menu Builder"})
    executable = [c for c in spec.controls if c.binding is not None]
    if not executable:
        return {"schema": "modkit-menu-validation-1.2", "checks": [], "issues": issues,
                "blocked": any(i.get("severity") == "BLOCK" for i in issues),
                "sourceApkSha256": source_apk_hash or None,
                "expectedSourceApkSha256": spec.source_apk_sha256 or None,
                "expectedTargetSha256": spec.target_sha256 or None}

    with zipfile.ZipFile(source_apk) as z:
        names = [i.filename for i in z.infolist() if not i.is_dir()]
        cache: dict[str, tuple[str, ElfFile, str, str]] = {}
        module_errors: dict[str, tuple[str, str]] = {}

        def module_for(name: str) -> tuple[str, ElfFile, str, str] | None:
            if name in cache:
                return cache[name]
            preferred = f"lib/arm64-v8a/{Path(name).name}"
            candidates = [n for n in names if Path(n).name == Path(name).name and n.startswith("lib/")]
            chosen = preferred if preferred in names else next((n for n in candidates if "/arm64-v8a/" in n), None)
            if chosen:
                blob = z.read(chosen)
                sha = hashlib.sha256(blob).hexdigest()
                elf = ElfFile(blob)
                cache[name] = (chosen, elf, sha, "apk")
                return cache[name]

            # Split APK workflows often keep libil2cpp.so outside base.apk. The
            # Android app stores the explicitly selected copy as sibling
            # ``library.so``. Use it only when the RE report preserved the exact
            # SHA-256, so switching APKs/libraries cannot silently cross-bind.
            external = source_apk.parent / "library.so"
            if Path(name).name == "libil2cpp.so" and external.is_file():
                if not spec.target_sha256:
                    module_errors[name] = ("EXTERNAL_TARGET_HASH_UNAVAILABLE",
                                           "external library.so exists, but MenuSpec has no trusted target SHA-256")
                    return None
                blob = external.read_bytes()
                sha = hashlib.sha256(blob).hexdigest()
                if sha != spec.target_sha256.lower():
                    module_errors[name] = ("EXTERNAL_TARGET_HASH_MISMATCH",
                                           "external library.so SHA-256 does not match the RE report")
                    return None
                elf = ElfFile(blob)
                cache[name] = (f"external:{external.name}", elf, sha, "external-selected-library")
                return cache[name]
            return None

        def validate_code_rva(control_id: str, path: str, elf: ElfFile, rva: int, role: str) -> dict | None:
            prefix = "RESOLVER_" if role == "resolver" else ""
            off = elf.rva_to_off(rva)
            sec = next((sec for sec in elf.sections if sec.addr <= rva < sec.addr + sec.size), None)
            if off is None:
                issues.append({"severity": "BLOCK", "code": prefix + "RVA_NOT_FILE_BACKED",
                               "control": control_id, "message": f"{role} RVA 0x{rva:x} is not file-backed in {path}"})
                return None
            if sec is None or not sec.is_exec:
                issues.append({"severity": "BLOCK", "code": prefix + "RVA_NOT_EXECUTABLE",
                               "control": control_id, "message": f"{role} RVA 0x{rva:x} is not executable in {path}"})
                return None
            preview = []
            try:
                raw = elf.read_at_rva(rva, 16)
                for i, word in enumerate(arm64.read_u32s(raw)):
                    preview.append({"rva": rva + i * 4, "bytes": word.to_bytes(4, "little").hex(" "),
                                    "asm": arm64.insn_mnemonic(word)})
            except Exception as exc:
                issues.append({"severity": "WARN", "code": prefix + "DISASM_PREVIEW_FAILED",
                               "control": control_id, "message": str(exc)})
            return {"rva": rva, "fileOffset": off, "section": sec.name, "preview": preview}

        seen: dict[tuple[str, int], list[str]] = {}
        for c in executable:
            key = (c.target_so, int(c.rva or 0))
            seen.setdefault(key, []).append(c.id)
            module = module_for(c.target_so)
            if module is None:
                code, message = module_errors.get(c.target_so, (
                    "TARGET_SO_NOT_FOUND", f"{c.target_so} is not present for arm64-v8a in the APK or trusted external selection"))
                issues.append({"severity": "BLOCK", "code": code, "control": c.id, "message": message})
                continue
            path, elf, target_sha, module_source = module
            if (Path(c.target_so).name == "libil2cpp.so" and spec.target_sha256
                    and target_sha != spec.target_sha256.lower()):
                issues.append({"severity": "BLOCK", "code": "TARGET_SO_HASH_MISMATCH", "control": c.id,
                               "message": f"{path} SHA-256 does not match the RE report used for this MenuSpec"})
                continue
            if not elf.is_arm64():
                issues.append({"severity": "BLOCK", "code": "TARGET_NOT_ARM64", "control": c.id,
                               "message": f"{path} is not an ARM64 ELF"})
                continue
            main = validate_code_rva(c.id, path, elf, int(c.rva), "target")
            if main is None:
                continue

            resolver = None
            if not c.is_static:
                if c.call_abi != "il2cpp":
                    issues.append({"severity": "BLOCK", "code": "INSTANCE_ABI_UNSUPPORTED", "control": c.id,
                                   "message": "instance binding requires il2cpp ABI"})
                elif c.resolver_kind not in {"out_ptr_bool", "return_ptr"} or not c.resolver_rva:
                    issues.append({"severity": "BLOCK", "code": "INSTANCE_RESOLVER_MISSING", "control": c.id,
                                   "message": "instance binding requires a confirmed supported resolver"})
                elif not c.resolver_verified:
                    issues.append({"severity": "BLOCK", "code": "INSTANCE_RESOLVER_UNVERIFIED", "control": c.id,
                                   "message": "instance resolver type identity is not verified"})
                else:
                    resolver = validate_code_rva(c.id, path, elf, int(c.resolver_rva), "resolver")

            checks.append({
                "control": c.id, "binding": c.binding, "callAbi": c.call_abi, "isStatic": c.is_static,
                "targetSo": c.target_so, "apkPath": path, "moduleSource": module_source,
                "targetSha256": target_sha, **main,
                "resolverKind": c.resolver_kind, "resolverRva": c.resolver_rva,
                "resolverVerified": c.resolver_verified, "resolverMatch": c.resolver_match,
                "resolverTargetClass": c.resolver_target_class,
                "resolverFileOffset": resolver.get("fileOffset") if resolver else None,
                "resolverSection": resolver.get("section") if resolver else None,
                "resolverPreview": resolver.get("preview") if resolver else [],
            })

        for (so, rva), ids in seen.items():
            if rva and len(ids) > 1:
                issues.append({"severity": "WARN", "code": "SHARED_RVA", "controls": ids,
                               "message": f"{len(ids)} controls share {so} RVA 0x{rva:x}; review whether this is intentional"})

    return {
        "schema": "modkit-menu-validation-1.2",
        "sourceApk": str(source_apk),
        "sourceApkSha256": source_apk_hash or None,
        "expectedSourceApkSha256": spec.source_apk_sha256 or None,
        "expectedTargetSha256": spec.target_sha256 or None,
        "checks": checks,
        "issues": issues,
        "blocked": any(i.get("severity") == "BLOCK" for i in issues),
        "validatedBindings": len(checks),
        "requestedBindings": len(executable),
    }


def auto_confirm_bindings(spec: MenuSpec, source_apk: str | Path, *, min_confidence: float = 0.85) -> dict:
    """Promote only structurally proven IL2CPP candidates to executable bindings.

    This is intentionally narrower than a generic "auto mod" switch. A candidate
    must have an address-bearing Rodroid signature contract, a supported action or
    bool-setter calling shape, sufficient confidence, and (for instance methods) a
    same-class ``out_ptr_bool`` resolver. The proposed bindings are then checked
    against the actual APK ELF. Controls which produce a BLOCK are rolled back to
    review-only state.
    """
    spec.validate()
    source_apk = Path(source_apk)
    promoted_ids: list[str] = []
    skipped: list[dict] = []
    originals: dict[str, dict] = {}

    for c in spec.controls:
        if c.binding is not None:
            skipped.append({"id": c.id, "reason": "already-bound"})
            continue
        if c.suggested_binding not in {"action", "bool_setter", "number_setter"}:
            skipped.append({"id": c.id, "reason": "unsupported-or-missing-binding-suggestion"})
            continue
        if c.suggested_binding == "number_setter" and c.type not in {"slider_int", "slider_float"}:
            skipped.append({"id": c.id, "reason": "numeric-range-review-required"})
            continue
        if not c.evidence_signature or not c.evidence_rva or c.evidence_rva <= 0:
            skipped.append({"id": c.id, "reason": "missing-signature-or-rva"})
            continue
        from modkit.reworkspace.signature import rodroid_signature_contract
        verified_contract = rodroid_signature_contract(c.evidence_signature)
        if (not verified_contract.get("autoBindingSafe")
                or verified_contract.get("bindingSuggestion") != c.suggested_binding):
            skipped.append({"id": c.id, "reason": "signature-contract-mismatch"})
            continue
        if bool(verified_contract.get("isStatic")) != bool(c.evidence_is_static if c.evidence_is_static is not None else c.is_static):
            skipped.append({"id": c.id, "reason": "signature-staticness-mismatch"})
            continue
        if c.call_abi != "il2cpp":
            skipped.append({"id": c.id, "reason": "not-il2cpp-signature-evidence"})
            continue
        if c.evidence_confidence is None or float(c.evidence_confidence) < float(min_confidence):
            skipped.append({"id": c.id, "reason": "confidence-below-threshold"})
            continue
        if c.method_verification:
            if not c.method_verification.get("addressConfirmed"):
                skipped.append({"id": c.id, "reason": "method-address-not-structurally-confirmed"})
                continue
            if not c.method_verification.get("abiConfirmed"):
                skipped.append({"id": c.id, "reason": "method-abi-not-structurally-confirmed"})
                continue
            # For instance methods the candidate-level verification is upgraded
            # only after a metadata-type-exact resolver is attached.
            evidence_static_gate = c.evidence_is_static if c.evidence_is_static is not None else c.is_static
            if not evidence_static_gate and not c.method_verification.get("executableReady"):
                skipped.append({"id": c.id, "reason": "method-instance-resolver-not-structurally-confirmed"})
                continue
        if c.semantic_verified is False:
            skipped.append({"id": c.id, "reason": c.semantic_blocker or "semantic-xref-verification-required"})
            continue
        if c.context_verified is False:
            skipped.append({"id": c.id, "reason": c.context_blocker or "method-local-context-verification-required"})
            continue
        evidence_static = c.evidence_is_static if c.evidence_is_static is not None else c.is_static
        if not evidence_static and (c.resolver_kind not in {"out_ptr_bool", "return_ptr"} or not c.resolver_rva or c.resolver_rva <= 0):
            skipped.append({"id": c.id, "reason": "instance-resolver-not-confirmed"})
            continue
        if not evidence_static and not c.resolver_verified:
            skipped.append({"id": c.id, "reason": "instance-resolver-type-not-verified"})
            continue
        if not evidence_static:
            resolver_verified_contract = rodroid_signature_contract(c.resolver_signature)
            if resolver_verified_contract.get("resolverSuggestion") != c.resolver_kind:
                skipped.append({"id": c.id, "reason": "instance-resolver-signature-mismatch"})
                continue

        originals[c.id] = {
            "type": c.type, "rva": c.rva, "binding": c.binding,
            "target_so": c.target_so, "is_static": c.is_static, "note": c.note,
            "binding_blocker": c.binding_blocker,
        }
        if c.suggested_binding == "action":
            c.type = "button"
        elif c.suggested_binding == "bool_setter":
            c.type = "toggle"
        # number_setter keeps the analyst-reviewed slider type/range.
        c.rva = int(c.evidence_rva)
        c.binding = c.suggested_binding
        c.is_static = bool(evidence_static)
        if c.suggested_target_so:
            c.target_so = c.suggested_target_so
        c.note = (c.note + " Auto-confirmed by signature contract + ELF preflight.").strip()
        c.binding_blocker = None
        promoted_ids.append(c.id)

    if not promoted_ids:
        return {
            "schema": "modkit-menu-auto-confirm-1.1", "minConfidence": min_confidence,
            "promoted": [], "promotionRecords": [], "rejected": [], "skipped": skipped,
            "validation": validate_bindings(spec, source_apk),
        }

    validation = validate_bindings(spec, source_apk)
    blocked_ids = {
        str(issue.get("control")) for issue in validation.get("issues", [])
        if issue.get("severity") == "BLOCK" and issue.get("control")
    }
    rejected = []
    for cid in list(promoted_ids):
        if cid not in blocked_ids:
            continue
        c = next(x for x in spec.controls if x.id == cid)
        old = originals[cid]
        c.type = old["type"]; c.rva = old["rva"]; c.binding = old["binding"]
        c.target_so = old["target_so"]; c.is_static = old["is_static"]; c.note = old["note"]
        c.binding_blocker = old["binding_blocker"]
        rejected.append({"id": cid, "reason": "elf-preflight-block"})
        promoted_ids.remove(cid)

    final_validation = validate_bindings(spec, source_apk)
    checks_by_id = {str(row.get("control")): row for row in final_validation.get("checks", [])}
    promotion_records = []
    for cid in promoted_ids:
        c = next(x for x in spec.controls if x.id == cid)
        promotion_records.append({
            "id": c.id, "title": c.title, "binding": c.binding, "type": c.type,
            "callAbi": c.call_abi, "isStatic": c.is_static, "rva": c.rva,
            "resolverRva": c.resolver_rva, "resolverKind": c.resolver_kind,
            "resolverLabel": c.resolver_label, "resolverVerified": c.resolver_verified,
            "resolverMatch": c.resolver_match, "resolverTargetClass": c.resolver_target_class,
            "resolverContractSource": c.resolver_contract_source,
            "resolverSignature": c.resolver_signature, "targetSo": c.target_so,
            "signature": c.evidence_signature, "confidence": c.evidence_confidence,
            "evidenceSource": c.evidence_source, "evidenceKind": c.evidence_kind,
            "evidenceLocation": c.evidence_location, "evidenceStatus": c.evidence_status,
            "evidenceCount": c.evidence_count, "corroboratingEvidence": c.corroborating_evidence,
            "semanticVerified": c.semantic_verified, "semanticStatus": c.semantic_status,
            "semanticConfidence": c.semantic_confidence, "semanticTags": c.semantic_tags,
            "semanticEvidence": c.semantic_evidence,
            "contextVerified": c.context_verified, "contextStatus": c.context_status,
            "contextConfidence": c.context_confidence, "contextEvidence": c.context_evidence,
            "methodVerification": c.method_verification,
            "elfVerification": checks_by_id.get(c.id),
            "decision": (("auto-confirmed-signature-plus-semantic-xref-plus-method-context-plus-type-verified-resolver-plus-elf"
                          if not c.is_static else "auto-confirmed-signature-plus-semantic-xref-plus-method-context-plus-elf")
                         if c.semantic_verified is True and c.context_verified is True else
                         (("auto-confirmed-signature-plus-semantic-xref-plus-type-verified-resolver-plus-elf"
                           if not c.is_static else "auto-confirmed-signature-plus-semantic-xref-plus-elf")
                          if c.semantic_verified is True else
                          ("auto-confirmed-signature-plus-type-verified-resolver-plus-elf"
                           if not c.is_static else "auto-confirmed-signature-plus-elf"))),
        })
    return {
        "schema": "modkit-menu-auto-confirm-1.1", "minConfidence": min_confidence,
        "promoted": promoted_ids, "promotionRecords": promotion_records,
        "rejected": rejected, "skipped": skipped,
        "validation": final_validation,
    }


def review_preflight(spec: MenuSpec, source_apk: str | Path) -> dict:
    """Summarize Menu Builder review state without promoting evidence to code.

    Static evidence and an executable binding are deliberately separate states.
    This report tells the Android UI exactly what remains to be reviewed and
    delegates the only binary-address validity check to ``validate_bindings``.
    """
    spec.validate()
    source_apk = Path(source_apk)
    validation = validate_bindings(spec, source_apk)
    rows = []
    counts = {"total": len(spec.controls), "bound": 0, "probeReadOnly": 0, "evidenceOnly": 0, "unresolved": 0,
              "actionableReview": 0, "informationalReview": 0}
    for c in spec.controls:
        if c.binding is not None:
            state = "bound"
            counts["bound"] += 1
        elif c.probe_kind is not None:
            state = "watch-probe"
            counts["probeReadOnly"] += 1
        elif c.evidence_rva is not None or c.rva is not None:
            state = "evidence-only"
            counts["evidenceOnly"] += 1
        else:
            state = "unresolved"
            counts["unresolved"] += 1
        suggested_rva = c.evidence_rva if c.evidence_rva is not None else (c.rva if c.binding is None else None)
        actionable_review = bool(
            c.binding is None
            and c.evidence_rva is not None and c.evidence_rva > 0
            and c.evidence_signature
            and c.suggested_binding in {"action", "bool_setter", "number_setter"}
            and c.evidence_confidence is not None and float(c.evidence_confidence) >= 0.85
            and c.semantic_verified is not False
            and c.context_verified is not False
        )
        if c.binding is None:
            if actionable_review:
                counts["actionableReview"] += 1
            else:
                counts["informationalReview"] += 1
        rows.append({
            "id": c.id, "title": c.title, "state": state, "type": c.type,
            "binding": c.binding, "rva": c.rva, "suggestedType": c.suggested_type,
            "evidenceRva": c.evidence_rva, "suggestedRva": suggested_rva,
            "evidenceSource": c.evidence_source, "evidenceKind": c.evidence_kind,
            "evidenceLocation": c.evidence_location, "evidenceConfidence": c.evidence_confidence,
            "evidenceStatus": c.evidence_status, "evidenceCount": c.evidence_count,
            "corroboratingEvidence": c.corroborating_evidence,
            "targetSo": c.target_so, "suggestedTargetSo": c.suggested_target_so,
            "suggestedBinding": c.suggested_binding, "evidenceIsStatic": c.evidence_is_static,
            "bindingBlocker": c.binding_blocker, "evidenceSignature": c.evidence_signature,
            "callAbi": c.call_abi, "resolverRva": c.resolver_rva, "resolverKind": c.resolver_kind,
            "resolverLabel": c.resolver_label, "resolverSource": c.resolver_source,
            "semanticVerified": c.semantic_verified, "semanticStatus": c.semantic_status,
            "semanticConfidence": c.semantic_confidence, "semanticTags": c.semantic_tags,
            "semanticEvidence": c.semantic_evidence, "semanticBlocker": c.semantic_blocker,
            "contextVerified": c.context_verified, "contextStatus": c.context_status,
            "contextConfidence": c.context_confidence, "contextEvidence": c.context_evidence,
            "contextBlocker": c.context_blocker,
            "methodVerification": c.method_verification,
            "findingId": c.finding_id, "actionableReview": actionable_review,
            "probeKind": c.probe_kind, "probeOwner": c.probe_owner, "probeField": c.probe_field,
            "probeOffset": c.probe_offset, "probePrimitive": c.probe_primitive, "probeStatus": c.probe_status,
        })
    issues = list(validation.get("issues", []))
    if counts["bound"] == 0:
        issues.append({"severity": "INFO" if counts["probeReadOnly"] else "WARN", "code": "NO_EXECUTABLE_BINDINGS",
                       "message": "No executable controls are present; read-only probes remain safe to package." if counts["probeReadOnly"] else "No controls have an explicitly confirmed calling convention/RVA yet."})
    if counts["probeReadOnly"]:
        issues.append({"severity": "INFO", "code": "READ_ONLY_RUNTIME_PROBES",
                       "message": f"{counts['probeReadOnly']} read-only runtime probe(s) will observe exact IL2CPP fields without applying setters or patches."})
    if counts["evidenceOnly"]:
        issues.append({"severity": "INFO", "code": "EVIDENCE_REVIEW_REMAINING",
                       "message": f"{counts['evidenceOnly']} control(s) have static RVA evidence which is not executable until reviewed."})
    if counts["unresolved"]:
        issues.append({"severity": "INFO", "code": "UNRESOLVED_CONTROLS",
                       "message": f"{counts['unresolved']} control(s) have no address evidence yet."})
    if counts["actionableReview"]:
        issues.append({"severity": "WARN", "code": "ACTIONABLE_REVIEW_REMAINING",
                       "message": f"{counts['actionableReview']} high-confidence control(s) have callable evidence but still require review; automatic APK build will stop rather than silently omit them."})
    payload_host_available = True
    payload_host_candidates = []
    if counts["probeReadOnly"] and source_apk.is_file():
        try:
            with zipfile.ZipFile(source_apk) as z:
                payload_host_candidates = [n for n in z.namelist() if n.startswith("lib/arm64-v8a/") and n.endswith(".so")]
            payload_host_available = bool(payload_host_candidates)
        except Exception as exc:
            payload_host_available = False
            issues.append({"severity": "BLOCK", "code": "APK_NATIVE_HOST_SCAN_FAILED", "message": str(exc)})
        if not payload_host_available:
            issues.append({"severity": "BLOCK", "code": "NATIVE_SPLIT_APK_REQUIRED",
                           "message": "The selected base APK contains no arm64 native library. Runtime Probe spec is valid, but a native split APK containing libil2cpp/libunity (or another always-loaded host) is required to package the in-process runtime."})
    ready_payload = (counts["bound"] > 0 or counts["probeReadOnly"] > 0) and not validation.get("blocked", False) and payload_host_available
    ready_probe_spec = counts["probeReadOnly"] > 0 and not validation.get("blocked", False)
    ready_auto = ready_payload and counts["actionableReview"] == 0
    return {
        "schema": "modkit-menu-preflight-1.1",
        "sourceApk": str(source_apk),
        "counts": counts,
        "controls": rows,
        "validation": validation,
        "issues": issues,
        "readyForPayload": ready_payload,
        "readyForProbeSpec": ready_probe_spec,
        "payloadHostAvailable": payload_host_available,
        "payloadHostCandidates": payload_host_candidates[:32],
        "readyForAutoBuild": ready_auto,
        "blocked": bool(validation.get("blocked", False)),
    }



def probe_spec_from_gameplay(coverage: dict, *, title: str = "ModKit Probe Menu",
                             base_spec: MenuSpec | None = None, max_probes: int = 48) -> MenuSpec:
    """Create read-only WATCH controls from exact gameplay field evidence.

    The function never turns a field into an executable binding.  It accepts only
    exact runtime offsets with primitive value shapes that the generic runtime can
    safely display.  A separately proven executable ``base_spec`` may be supplied
    (for example a static time-scale setter); those controls are copied unchanged.
    """
    cards = list(coverage.get("cards") or coverage.get("categories") or [])
    controls = list(base_spec.controls) if base_spec is not None else []
    used = {c.id for c in controls}
    status_rank = {"CONFIRMED": 0, "FIELD OBSERVED": 1, "PACKAGE OBSERVED": 3,
                   "SCRIPT/CONTENT SEARCH": 4, "REVIEW": 5, "NOT FOUND LOCAL": 6}
    candidates: list[tuple] = []
    for card in cards:
        domain = str(card.get("domain") or card.get("id") or "review")
        status = str(card.get("status") or "REVIEW")
        for f in card.get("fields") or []:
            owner = str(f.get("declaringType") or "").strip()
            name = str(f.get("name") or "").strip()
            off = f.get("runtimeOffset")
            primitive = str(f.get("primitive") or "").lower()
            if not owner or not name or off is None or primitive not in {"bool", "int32", "uint32", "float"}:
                continue
            try:
                off_i = int(off)
            except Exception:
                continue
            if off_i < 0 or off_i > 0x100000:
                continue
            # Exact gameplay fields outrank generic constructor/config fields.
            gameplay_owner = 0 if any(tok in owner.lower() for tok in ("hero", "avatar", "unit", "actor", "player", "game", "battle", "camera", "weather")) else 1
            candidates.append((status_rank.get(status, 9), gameplay_owner, domain, owner, name, off_i, primitive, status, f))
    candidates.sort(key=lambda x: (x[0], x[1], x[2], x[3], x[4], x[5]))
    seen_fields = set()
    for _rank, _ownrank, domain, owner, name, off, primitive, status, f in candidates:
        key = (owner, name, off)
        if key in seen_fields:
            continue
        seen_fields.add(key)
        raw = re.sub(r"[^A-Za-z0-9]+", "_", f"watch_{domain}_{owner}_{name}").strip("_")[:58] or "watch_field"
        cid = raw
        n = 2
        while cid in used:
            suffix = f"_{n}"
            cid = raw[:64-len(suffix)] + suffix
            n += 1
        used.add(cid)
        label = f"WATCH {name}"
        controls.append(MenuControl(
            id=cid, title=label, type="label", category=domain.title(), binding=None,
            note=f"Read-only runtime probe: {owner}.{name} @ 0x{off:x} ({primitive}); static status={status}",
            evidence_status=status, evidence_confidence=1.0,
            probe_kind="watch", probe_owner=owner, probe_field=name,
            probe_offset=off, probe_primitive=primitive, probe_status=status,
            method_verification={"runtimeTruth": "not-observed", "probeReadOnly": True,
                                 "fieldDefinitionIndex": f.get("fieldDefinitionIndex"),
                                 "declaringTypeIndex": f.get("declaringTypeIndex")},
        ))
        if sum(1 for c in controls if c.probe_kind) >= int(max_probes):
            break
    return MenuSpec(title=title,
                    icon_text=base_spec.icon_text if base_spec is not None else "MK",
                    controls=controls,
                    target_sha256=base_spec.target_sha256 if base_spec is not None else "",
                    source_apk_sha256=base_spec.source_apk_sha256 if base_spec is not None else "")

def detect_render_host(source_apk: str | Path) -> dict:
    """Pick a likely native module whose import table can host EGL/touch GOT hooks.

    This is evidence-based and sequential: only one candidate .so is inflated at a
    time, and libraries over 128 MiB are skipped for this optional heuristic.
    """
    source_apk = Path(source_apk)
    candidates = []
    with zipfile.ZipFile(source_apk) as z:
        infos = [i for i in z.infolist() if i.filename.startswith("lib/arm64-v8a/") and i.filename.endswith(".so")]
        for info in infos:
            base = Path(info.filename).name
            score = 0
            reasons = []
            if base == "libunity.so": score += 10; reasons.append("Unity render module")
            elif base == "libmain.so": score += 6; reasons.append("main native module")
            elif base == "libgame.so": score += 5; reasons.append("game native module")
            if info.file_size <= 128 * 1024 * 1024:
                try:
                    elf = ElfFile(z.read(info))
                    syms = {s.name: s for s in elf.symbols() if s.name}
                    for symbol, points in (("eglSwapBuffers", 8), ("AMotionEvent_getAction", 6)):
                        sym = syms.get(symbol)
                        if sym is not None and sym.shndx == 0:
                            score += points; reasons.append(f"imports {symbol}")
                    needed = set(elf.needed())
                    if "libEGL.so" in needed: score += 2; reasons.append("needs libEGL.so")
                    if "libandroid.so" in needed: score += 1; reasons.append("needs libandroid.so")
                except Exception as exc:
                    reasons.append(f"ELF scan skipped: {exc}")
            else:
                reasons.append("optional import scan skipped above 128 MiB")
            candidates.append({"path": info.filename, "name": base, "score": score, "reasons": reasons, "size": info.file_size})
    candidates.sort(key=lambda x: (-x["score"], x["size"], x["name"]))
    selected = candidates[0]["name"] if candidates else "libunity.so"
    return {"selected": selected, "candidates": candidates[:12]}

def write_patch_payload(spec: MenuSpec, source_apk: str | Path, runtime_so: str | Path,
                        output_zip: str | Path, *, host_so: str | None = None,
                        render_host: str | None = None) -> dict:
    """Package a compiled Menu Builder runtime as a DEX-free native Patch Pack.

    The runtime is loaded by adding one conservative ``DT_NEEDED`` entry to an
    already-loaded host library.  No existing classes*.dex is replaced.  This
    function validates bindings first, writes an auditable payload manifest, then
    runs the normal Patch Pack inspector over the finished ZIP before returning it.
    """
    import hashlib
    from modkit.elf.reader import ElfFile
    from modkit.patchpack import inspect_pack

    spec.validate()
    source_apk = Path(source_apk)
    runtime_so = Path(runtime_so)
    output_zip = Path(output_zip)
    if not source_apk.is_file():
        raise ValueError("source APK is missing")
    if not runtime_so.is_file():
        raise ValueError("compiled runtime .so is missing")

    validation = validate_bindings(spec, source_apk)
    if validation.get("blocked"):
        raise ValueError("menu bindings are blocked by source-APK validation")
    render_detection = detect_render_host(source_apk) if not render_host else {"selected": render_host, "candidates": []}
    render_host = render_detection["selected"]

    runtime_blob = runtime_so.read_bytes()
    runtime_elf = ElfFile(runtime_blob)
    if not runtime_elf.is_arm64():
        raise ValueError("Menu Builder payload currently supports arm64-v8a runtime only")
    runtime_config = None
    runtime_config_mode = "compiled-per-spec"
    if runtime_elf.section(".modkitcfg") is not None or b"MODKITCFG_RESERVED_V1\x00" in runtime_blob:
        from modkit.menu.runtime_config import encode_runtime_config, patch_runtime_blob
        config_blob = encode_runtime_config(spec, render_host=render_host)
        runtime_blob, runtime_config = patch_runtime_blob(runtime_blob, config_blob)
        runtime_elf = ElfFile(runtime_blob)
        runtime_config_mode = "embedded-generic-runtime"
    dependency = runtime_so.name
    if not re.fullmatch(r"lib[^/\\\x00]+\.so", dependency):
        raise ValueError("runtime filename must be a plain lib*.so soname")

    executable = [c for c in spec.controls if c.binding is not None]
    targets = {c.target_so for c in executable}
    if len(targets) > 1:
        raise ValueError("one payload can target only one native module")
    preferred_target = next(iter(targets)) if targets else "libil2cpp.so"
    with zipfile.ZipFile(source_apk) as z:
        apk_names = set(z.namelist())
        arm64_hosts = [n for n in apk_names if n.startswith("lib/arm64-v8a/") and n.endswith(".so")]
        if host_so:
            target_name = host_so
        elif f"lib/arm64-v8a/{preferred_target}" in apk_names:
            target_name = preferred_target
        elif f"lib/arm64-v8a/{render_host}" in apk_names:
            target_name = render_host
        elif arm64_hosts:
            target_name = Path(sorted(arm64_hosts)[0]).name
        else:
            raise ValueError("selected APK contains no arm64 native host; choose the native split APK before building the runtime payload")
        if not re.fullmatch(r"lib[^/\\\x00]+\.so", target_name):
            raise ValueError("host_so must be a plain lib*.so name")
        host_path = f"lib/arm64-v8a/{target_name}"
        if host_path not in apk_names:
            raise ValueError(f"source APK does not contain {host_path}")
        # Preflight the exact ELF mutation before writing a payload artifact.
        host = ElfFile(z.read(host_path))
        edit_preview = host.add_needed(dependency)
        if dependency not in ElfFile(host.blob).needed():
            raise ValueError("DT_NEEDED preflight did not persist")

    spec_bytes = json.dumps(spec.json(), ensure_ascii=False, indent=2).encode("utf-8")
    validation_bytes = json.dumps(validation, ensure_ascii=False, indent=2).encode("utf-8")
    source_hash = hashlib.sha256()
    with source_apk.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            source_hash.update(chunk)

    manifest = {
        "schema": "modkit-payload-1.0",
        "generator": "ModKit Menu Builder",
        "sourceApkSha256": source_hash.hexdigest(),
        "abi": "arm64-v8a",
        "hostModule": target_name,
        "runtime": dependency,
        "runtimeSha256": hashlib.sha256(runtime_blob).hexdigest(),
        "runtimeConfigMode": runtime_config_mode,
        "runtimeConfig": runtime_config,
        "renderHost": render_host,
        "renderHostDetection": render_detection,
        "menuSpecSha256": hashlib.sha256(spec_bytes).hexdigest(),
        "bindingValidationSha256": hashlib.sha256(validation_bytes).hexdigest(),
        "autoload": [{"host": host_path, "dependency": dependency, "strategy": "safe-system-chain"}],
        "preflight": edit_preview,
    }
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()
    try:
        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
            zi = zipfile.ZipInfo(f"lib/arm64-v8a/{dependency}")
            zi.compress_type = zipfile.ZIP_STORED
            z.writestr(zi, runtime_blob)
            z.writestr("modkit-payload.json", json.dumps(manifest, ensure_ascii=False, indent=2))
            z.writestr("MENU-SPEC.json", spec_bytes)
            z.writestr("binding-validation.json", validation_bytes)
        inspection = inspect_pack(source_apk, output_zip)
        if inspection.get("blocked"):
            raise ValueError("generated payload was blocked by Patch Pack inspection: " + "; ".join(
                i.get("message", "") for i in inspection.get("issues", []) if i.get("severity") == "BLOCK"
            ))
    except Exception:
        output_zip.unlink(missing_ok=True)
        raise

    return {
        "path": str(output_zip),
        "sha256": hashlib.sha256(output_zip.read_bytes()).hexdigest(),
        "runtime": dependency,
        "host": host_path,
        "runtimeConfigMode": runtime_config_mode,
        "runtimeConfig": runtime_config,
        "renderHost": render_host,
        "renderHostDetection": render_detection,
        "bindings": validation.get("validatedBindings", 0),
        "inspection": inspection,
    }
