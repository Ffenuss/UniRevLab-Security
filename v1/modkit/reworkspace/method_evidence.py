"""Universal IL2CPP method evidence and retention policy.

The resolver deliberately separates *identity/address proof* from semantic
interpretation.  A method name can influence retention/ranking, but can never
by itself make an RVA or runtime behaviour "confirmed".

This module is application-agnostic: no package, game, assembly or fixture name
is special-cased.  It is shared by the metadata resolver, RE correlator and
Menu Builder provenance layer.
"""
from __future__ import annotations

import re
from typing import Iterable

_SCHEMA = "modkit-method-verification-1.0"

# Compiler/runtime lifecycle shapes are useful RE inventory but poor automatic
# control candidates.  Keep this generic and engine-wide rather than app-based.
_LIFECYCLE = {
    ".ctor", ".cctor", "awake", "start", "update", "lateupdate", "fixedupdate",
    "onenable", "ondisable", "ondestroy", "reset", "movenext", "setstatemachine",
    "begininvoke", "endinvoke", "invoke",
}

# Generic API morphology only.  These are not behaviour claims; they are used
# to retain address-bearing methods for later xref/context verification.
_ACTION_PREFIXES = (
    "set", "enable", "disable", "toggle", "activate", "deactivate", "apply",
    "change", "switch", "show", "hide", "open", "close", "spawn", "create",
    "add", "remove", "clear", "reset", "refresh", "reload", "start", "stop",
    "pause", "resume", "play", "execute", "run", "trigger", "request",
)
_QUERY_PREFIXES = ("get", "is", "has", "can", "tryget", "find", "resolve")
_RESOLVER_NAMES = {"instance", "getinstance", "get_instance"}


def _bare_method(label_or_name: str) -> str:
    text = str(label_or_name or "")
    if "::" in text:
        text = text.rsplit("::", 1)[-1]
    return text.split("(", 1)[0].strip()


def method_role(label_or_name: str, contract: dict | None = None) -> str:
    """Classify generic API morphology without claiming behaviour."""
    name = _bare_method(label_or_name)
    low = name.casefold()
    compact = re.sub(r"[^a-z0-9]+", "", low)
    contract = contract or {}

    if not name:
        return "unknown"
    if low in _LIFECYCLE or compact in {x.replace(".", "") for x in _LIFECYCLE}:
        return "lifecycle"
    if "<" in name or ">" in name or low.startswith("lambda$"):
        return "generated"
    if contract.get("resolverSuggestion") in {"out_ptr_bool", "return_ptr"}:
        return "instance_resolver"
    if compact in _RESOLVER_NAMES or low.startswith("tryget"):
        return "instance_resolver"
    if low.startswith("set_") or (low.startswith("set") and len(low) > 3 and low[3].isalnum()):
        return "setter"
    if low.startswith(("enable", "disable", "toggle", "activate", "deactivate")):
        return "toggle_action"
    if low.startswith(_ACTION_PREFIXES):
        return "action"
    if low.startswith(_QUERY_PREFIXES):
        return "query"
    return "unknown"


def retention_priority(row: dict, *, semantic_tags: Iterable[str] = (), wanted: bool = False) -> int:
    """Bounded, app-agnostic priority for retaining detailed metadata rows.

    Every metadata row is still scanned for unique CodeRegistration address
    coverage by the caller.  This score only decides which rows deserve the more
    expensive typed-parameter/signature materialization kept in the JSON report.
    """
    if wanted:
        return 10_000
    name = str(row.get("name") or "")
    role = method_role(name)
    args = int(row.get("args") or 0)
    score = 0

    score += {
        "instance_resolver": 44,
        "setter": 34,
        "toggle_action": 32,
        "action": 24,
        "query": 10,
        "unknown": 0,
        "lifecycle": -30,
        "generated": -28,
    }.get(role, 0)

    # Low arity is materially more useful for ABI reconstruction.  This is a
    # structural heuristic, not a semantic one.
    if args == 0:
        score += 8
    elif args == 1:
        score += 10
    elif args == 2:
        score += 5
    elif args <= 4:
        score += 1
    else:
        score -= 12

    if not row.get("generic"):
        score += 4
    else:
        score -= 18
    if not row.get("abstract"):
        score += 3
    else:
        score -= 24

    tags = tuple(semantic_tags or ())
    if tags:
        # Semantic vocabulary widens retention but never proves the method.
        score += min(18, 6 + 3 * len(set(tags)))

    # Preserve exact singleton-like resolver names even before typed return
    # information is materialized.
    compact = re.sub(r"[^a-z0-9]+", "", name.casefold())
    if compact in _RESOLVER_NAMES or compact.startswith("tryget"):
        score += 16
    return score


def should_retain_metadata_row(row: dict, *, semantic_tags: Iterable[str] = (), wanted: bool = False) -> bool:
    """Whether to materialize a detailed callable row after the full scan."""
    return retention_priority(row, semantic_tags=semantic_tags, wanted=wanted) >= 20


def structurally_actionable(label: str, contract: dict | None = None) -> bool:
    """Whether a callable is worth control-oriented review without name vocab."""
    contract = contract or {}
    role = method_role(label, contract)
    binding = contract.get("bindingSuggestion")
    if role in {"lifecycle", "generated", "query", "instance_resolver"}:
        return False
    if binding in {"action", "bool_setter", "number_setter"}:
        return role in {"setter", "toggle_action", "action"} or role == "unknown"
    return False


def build_method_verification(row: dict, resolver: dict | None = None) -> dict:
    """Create a fail-closed evidence record for one resolved method row.

    `runtimeStatus` is intentionally never promoted here. Static analysis can
    prove identity/address/ABI relations, but not that invoking a method produces
    an intended in-app effect.
    """
    contract = row.get("signature_contract") or row.get("signatureContract") or {}
    label = str(row.get("label") or "")
    rva = row.get("rva")
    offset = row.get("offset")
    resolution = str(row.get("resolution") or "")
    confirmed_unique = resolution.startswith("confirmed-unique")
    executable_address = isinstance(rva, int) and rva > 0 and (offset is None or isinstance(offset, int))
    identity = bool(row.get("metadata_token") is not None or contract.get("metadataToken") is not None
                    or row.get("metadata_method_id") is not None or contract.get("metadataMethodId") is not None)
    staticness = contract.get("staticnessVerified") is not False and contract.get("isStatic") is not None
    shape = bool(contract.get("shapeSupported"))
    binding = contract.get("bindingSuggestion")
    resolver_kind = contract.get("resolverSuggestion")
    is_static = contract.get("isStatic")
    dump_match = bool(contract.get("dumpArityVerified") is True and contract.get("dumpStaticnessVerified") is True)

    resolver_verified = bool(resolver and resolver.get("verified"))
    # ABI truth and UI-binding intent are deliberately separate. A method can
    # have an exactly known static/instance ABI even when its obfuscated name
    # gives us no safe reason to call it a setter/action automatically.
    abi_confirmed = bool(shape and staticness)
    address_confirmed = bool(confirmed_unique and executable_address and identity)

    resolver_required = bool(is_static is False)
    contract_blocker = contract.get("bindingBlocker")
    blocker = contract_blocker
    if resolver_required and resolver_verified and blocker == "instance-method-needs-confirmed-instance-resolver":
        blocker = None
    elif resolver_required and not resolver_verified:
        blocker = blocker or "instance-method-needs-confirmed-instance-resolver"

    binding_ready = bool(binding and not blocker)
    if abi_confirmed and not binding and blocker is None and not resolver_kind:
        blocker = "method-intent-unproven-for-auto-binding"
    callable_ready = bool(address_confirmed and abi_confirmed
                          and not (contract_blocker in {
                              "generic-or-abstract-method",
                              "metadata-primitive-signature-unsupported",
                              "metadata-dump-signature-mismatch",
                          })
                          and (is_static is True or resolver_verified))
    executable_ready = bool(callable_ready and binding_ready)

    incoming_direct_bl = int(row.get("static_incoming_direct_bl_count") or 0)
    incoming_thunk = int(row.get("static_incoming_thunk_count") or 0)
    incoming_tail = int(row.get("static_incoming_tail_b_count") or 0)
    incoming_indirect = int(row.get("static_incoming_indirect_count") or 0)
    incoming_virtual = int(row.get("static_incoming_virtual_count") or 0)
    incoming_exact = incoming_direct_bl + incoming_thunk + incoming_tail + incoming_indirect + incoming_virtual
    first_direct_bl = row.get("static_first_call_rva")

    score = 0.0
    if confirmed_unique:
        score += 0.34
    if executable_address:
        score += 0.14
    if identity:
        score += 0.12
    if staticness:
        score += 0.08
    if shape:
        score += 0.10
    if binding:
        score += 0.04
    if abi_confirmed:
        score += 0.04
    if dump_match:
        score += 0.05
    if is_static is True:
        score += 0.04
    elif resolver_verified:
        score += 0.09
    if incoming_exact:
        score += min(0.10, 0.04 + 0.01 * min(incoming_exact, 6))
    if incoming_indirect:
        score += min(0.04, 0.02 + 0.01 * min(incoming_indirect, 2))
    score = round(max(0.0, min(0.99, score)), 2)

    evidence = []
    if confirmed_unique:
        evidence.append({"kind": "unique-code-registration", "rationale": "unique metadata key and unique executable method pointer"})
    if executable_address:
        evidence.append({"kind": "executable-rva", "rva": rva, "offset": offset})
    if identity:
        evidence.append({"kind": "metadata-identity", "token": row.get("metadata_token", contract.get("metadataToken")),
                         "methodId": row.get("metadata_method_id", contract.get("metadataMethodId"))})
    if shape:
        evidence.append({"kind": "typed-abi-shape", "signature": contract.get("signature", ""),
                         "binding": binding})
    if dump_match:
        evidence.append({"kind": "dump-corroboration", "rationale": "dump.cs arity/staticness agrees with metadata"})
    if resolver_verified:
        evidence.append({"kind": "instance-resolver", "rva": resolver.get("rva"),
                         "match": resolver.get("match"), "targetClass": resolver.get("targetClass")})
    if incoming_direct_bl:
        evidence.append({
            "kind": "native-direct-bl-target", "count": incoming_direct_bl,
            "firstCallRva": first_direct_bl,
            "rationale": "ARM64 direct BL resolves exactly to this unique metadata RVA; caller attribution is a separate proof stage",
        })
    if incoming_thunk:
        evidence.append({
            "kind": "native-bl-via-thunk-target", "count": incoming_thunk,
            "rationale": "ARM64 BL reaches a statically canonicalized tail thunk for this metadata method",
        })
    if incoming_tail:
        evidence.append({
            "kind": "native-tail-b-target", "count": incoming_tail,
            "rationale": "ARM64 tail B resolves exactly to this metadata method in the shared evidence graph",
        })
    if incoming_indirect:
        evidence.append({
            "kind": "native-indirect-blr-target", "count": incoming_indirect,
            "rationale": "Nearby AArch64 register/data-flow resolves BLR to this exact executable target",
        })
    if incoming_virtual:
        evidence.append({
            "kind": "native-virtual-vtable-target", "count": incoming_virtual,
            "rationale": "ARM64 BLR receiver type and metadata vtable jointly resolve the exact managed target",
        })

    if executable_ready:
        level = "executable-ready-static"
    elif callable_ready:
        level = "callable-abi-confirmed"
    elif address_confirmed and abi_confirmed:
        level = "callable-structural"
    elif address_confirmed:
        level = "address-confirmed"
    elif confirmed_unique:
        level = "mapping-confirmed"
    else:
        level = "review"

    return {
        "schema": _SCHEMA,
        "label": label,
        "role": method_role(label, contract),
        "addressStatus": "confirmed" if address_confirmed else ("mapped" if confirmed_unique else "review"),
        "abiStatus": "confirmed" if abi_confirmed else ("unsupported" if contract.get("shapeSupported") is False else "review"),
        "relationStatus": "observed-static-xref" if incoming_exact else "not-observed",
        "contextStatus": "not-observed",
        "semanticStatus": "unclassified",
        "runtimeStatus": "not-observed",
        "confirmationLevel": level,
        "structuralConfidence": score,
        "addressConfirmed": address_confirmed,
        "abiConfirmed": abi_confirmed,
        "callableReady": callable_ready,
        "bindingReady": binding_ready,
        "executableReady": executable_ready,
        "runtimeConfirmed": False,
        "resolverRequired": resolver_required,
        "resolverVerified": resolver_verified,
        "bindingSuggestion": binding,
        "bindingBlocker": blocker,
        "evidence": evidence,
    }


def enrich_method_verification(verification: dict, *, incoming_refs: list[dict] | None = None,
                               outgoing_refs: list[dict] | None = None,
                               method_context: dict | None = None) -> dict:
    """Attach static relationship/context evidence without changing runtime truth."""
    v = dict(verification or {})
    evidence = list(v.get("evidence") or [])
    incoming_refs = incoming_refs or []
    outgoing_refs = outgoing_refs or []

    exact = []
    for direction, refs in (("incoming", incoming_refs), ("outgoing", outgoing_refs)):
        for ref in refs:
            if ref.get("sourceAttribution") not in {"unique-managed-interval", "unique-metadata-method-interval"}:
                continue
            exact.append((direction, ref))
            if len(exact) >= 12:
                break
        if len(exact) >= 12:
            break
    if exact:
        v["relationStatus"] = "confirmed-static-xref"
        for direction, ref in exact[:6]:
            evidence.append({
                "kind": "managed-direct-call-xref", "direction": direction,
                "callRva": ref.get("callRva"), "targetRva": ref.get("targetRva"),
                "sourceAttribution": ref.get("sourceAttribution"),
            })

    ctx = method_context or {}
    context_hits = 0
    if ctx:
        calls = ctx.get("outgoingManagedCalls") or []
        strings = ctx.get("stringRefs") or []
        fields = ctx.get("thisOffsetCandidates") or []
        context_hits = int(bool(calls)) + int(bool(strings)) + int(bool(fields))
        if context_hits:
            v["contextStatus"] = "corroborated-static-context"
            evidence.append({"kind": "method-local-context", "managedCalls": len(calls),
                             "stringRefs": len(strings), "thisOffsetCandidates": len(fields)})

    score = float(v.get("structuralConfidence") or 0.0)
    if exact:
        score += min(0.12, 0.06 + 0.02 * (len(exact) - 1))
    if context_hits:
        score += min(0.08, 0.03 * context_hits)
    v["structuralConfidence"] = round(min(0.99, score), 2)
    v["evidence"] = evidence[:32]

    if v.get("executableReady") and exact:
        v["confirmationLevel"] = "executable-ready-xref-corroborated"
    elif v.get("addressConfirmed") and exact:
        v["confirmationLevel"] = "address-confirmed-xref-corroborated"
    return v


def apply_semantic_result(verification: dict, *, status: str, confidence: float | None,
                          verified: bool | None, tags: Iterable[str] = ()) -> dict:
    """Merge semantic classification while preserving static/runtime separation."""
    v = dict(verification or {})
    v["semanticStatus"] = str(status or "unclassified")
    v["semanticConfidence"] = None if confidence is None else round(float(confidence), 2)
    v["semanticVerified"] = verified
    v["semanticTags"] = sorted(set(str(x) for x in (tags or ()) if x))
    if verified is True and v.get("executableReady"):
        v["confirmationLevel"] = "executable-ready-semantic-corroborated"
    # Runtime remains explicitly unobserved unless a future dynamic verifier sets it.
    v.setdefault("runtimeStatus", "not-observed")
    v.setdefault("runtimeConfirmed", False)
    return v
