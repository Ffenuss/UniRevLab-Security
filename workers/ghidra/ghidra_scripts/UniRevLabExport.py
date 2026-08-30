# UniRevLab headless native analysis exporter.
# Intended for Ghidra 12.1+ PyGhidra headless mode.
#@category UniRevLab

from __future__ import annotations

import json
import os
import re

from ghidra.framework import Application
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.pcode import PcodeOp


JNI_SIGNATURE_RE = re.compile(r"^\([^)]*\).+")
JNI_METHOD_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$<>]{0,255}$")
JNI_CLASS_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:/[A-Za-z_$][A-Za-z0-9_$]*)+$")
IL2CPP_NAMES = {
    "CODE_REGISTRATION": ("g_CodeRegistration", "s_CodeRegistration", "CodeRegistration"),
    "METADATA_REGISTRATION": ("g_MetadataRegistration", "s_MetadataRegistration", "MetadataRegistration"),
    "CODEGEN_REGISTER": ("il2cpp_codegen_register",),
}


def _args():
    values = list(getScriptArgs())
    if len(values) != 2:
        raise RuntimeError("expected arguments: <job.json> <result.json>")
    return values[0], values[1]


def _rva(address):
    if address is None or not address.isMemoryAddress():
        return None
    value = int(address.getOffset()) - int(currentProgram.getImageBase().getOffset())
    return value if value >= 0 else None


def _flow_kind(flow):
    if flow is None:
        return "OTHER"
    try:
        if flow.isCall():
            return "CALL"
        if flow.isConditional():
            return "CONDITIONAL"
        if flow.isJump():
            return "UNCONDITIONAL"
        if flow.isComputed():
            return "COMPUTED"
        if flow.hasFallthrough():
            return "FALL_THROUGH"
    except Exception:
        pass
    return "OTHER"


def _xref_kind(ref_type):
    try:
        if ref_type.isCall():
            return "CALL"
        if ref_type.isJump():
            return "JUMP"
        if ref_type.isRead():
            return "READ"
        if ref_type.isWrite():
            return "WRITE"
        if ref_type.isData():
            return "DATA"
    except Exception:
        pass
    return "OTHER"


def _function_signature(fn):
    try:
        return str(fn.getSignature())
    except Exception:
        try:
            return str(fn.getPrototypeString(False, False))
        except Exception:
            return ""


def _namespace(fn):
    try:
        ns = fn.getParentNamespace()
        return str(ns.getName(True)) if ns is not None else ""
    except Exception:
        return ""


def _decompile(interface, fn, per_function_chars, remaining_chars, timeout_seconds):
    if per_function_chars <= 0 or remaining_chars <= 0:
        return None
    try:
        response = interface.decompileFunction(fn, max(1, min(timeout_seconds, 300)), monitor)
        if not response.decompileCompleted():
            return None
        decompiled = response.getDecompiledFunction()
        if decompiled is None:
            return None
        text = decompiled.getC()
        if text is None:
            return None
        limit = min(per_function_chars, remaining_chars)
        text = str(text)
        return text[:limit]
    except Exception:
        return None


def _collect_functions(job):
    limits = job["limits"]
    modes = set(job["analysisModes"])
    targets = set(int(x) for x in job.get("decompilerTargets", []))
    all_decompile = "DECOMPILER" in modes and not targets
    use_decompiler = "DECOMPILER" in modes
    interface = None
    if use_decompiler:
        try:
            interface = DecompInterface()
            interface.toggleCCode(True)
            interface.toggleSyntaxTree(True)
            interface.setSimplificationStyle("decompile")
            if not interface.openProgram(currentProgram):
                interface = None
        except Exception:
            interface = None

    fm = currentProgram.getFunctionManager()
    discovered = int(fm.getFunctionCount())
    functions = []
    decompiled_count = 0
    total_chars = 0
    truncated = False
    for fn in fm.getFunctions(True):
        if len(functions) >= int(limits["maxFunctions"]):
            truncated = True
            break
        entry_rva = _rva(fn.getEntryPoint())
        if entry_rva is None:
            continue
        preview = None
        if interface is not None and (all_decompile or entry_rva in targets):
            remaining = int(limits["maxDecompilerTotalChars"]) - total_chars
            preview = _decompile(
                interface,
                fn,
                int(limits["maxDecompilerCharsPerFunction"]),
                remaining,
                max(1, int(limits["wallClockSeconds"]) // 4),
            )
            if preview is not None:
                total_chars += len(preview)
                decompiled_count += 1
        try:
            size = int(fn.getBody().getNumAddresses())
        except Exception:
            size = 0
        functions.append({
            "rva": entry_rva,
            "name": str(fn.getName()),
            "namespace": _namespace(fn),
            "signature": _function_signature(fn),
            "sizeBytes": max(0, size),
            "isThunk": bool(fn.isThunk()),
            "decompilerPreview": preview,
        })
    if interface is not None:
        try:
            interface.dispose()
        except Exception:
            pass
    return functions, discovered, decompiled_count, truncated


def _collect_cfg(job, function_rvas):
    if "CFG_INDEX" not in set(job["analysisModes"]):
        return [], False
    max_blocks = int(job["limits"]["maxCfgBlocks"])
    fm = currentProgram.getFunctionManager()
    model = BasicBlockModel(currentProgram)
    out = []
    total = 0
    truncated = False
    for function_rva in function_rvas:
        addr = currentProgram.getImageBase().add(function_rva)
        fn = fm.getFunctionAt(addr)
        if fn is None:
            continue
        blocks_out = []
        edges_out = []
        try:
            blocks = model.getCodeBlocksContaining(fn.getBody(), monitor)
            while blocks.hasNext():
                if total >= max_blocks:
                    truncated = True
                    break
                block = blocks.next()
                start = _rva(block.getFirstStartAddress())
                end = _rva(block.getMaxAddress())
                if start is None or end is None:
                    continue
                blocks_out.append({
                    "startRva": start,
                    "endRva": end,
                    "flowType": str(block.getFlowType()),
                })
                total += 1
                try:
                    destinations = block.getDestinations(monitor)
                    while destinations.hasNext():
                        edge = destinations.next()
                        dest = _rva(edge.getDestinationAddress())
                        if dest is None:
                            continue
                        edges_out.append({
                            "fromRva": start,
                            "toRva": dest,
                            "kind": _flow_kind(edge.getFlowType()),
                        })
                except Exception:
                    pass
            out.append({"functionRva": function_rva, "blocks": blocks_out, "edges": edges_out})
            if truncated:
                break
        except Exception:
            out.append({"functionRva": function_rva, "blocks": [], "edges": []})
    return out, truncated


def _collect_xrefs(job, function_rvas):
    if "XREF_INDEX" not in set(job["analysisModes"]):
        return [], False
    max_xrefs = int(job["limits"]["maxXrefs"])
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    out = []
    seen = set()
    truncated = False
    for function_rva in function_rvas:
        fn = fm.getFunctionAt(currentProgram.getImageBase().add(function_rva))
        if fn is None:
            continue
        instructions = listing.getInstructions(fn.getBody(), True)
        while instructions.hasNext():
            ins = instructions.next()
            from_rva = _rva(ins.getAddress())
            if from_rva is None:
                continue
            for ref in ins.getReferencesFrom():
                if len(out) >= max_xrefs:
                    truncated = True
                    return out, truncated
                to_addr = ref.getToAddress()
                if to_addr is None or not to_addr.isMemoryAddress() or not memory.contains(to_addr):
                    continue
                to_rva = _rva(to_addr)
                if to_rva is None:
                    continue
                item = (from_rva, to_rva, _xref_kind(ref.getReferenceType()))
                if item in seen:
                    continue
                seen.add(item)
                out.append({"fromRva": item[0], "toRva": item[1], "kind": item[2]})
    return out, truncated


def _decode_jni_export(name):
    if not name.startswith("Java_"):
        return None
    encoded = name[5:]
    base = encoded.split("__", 1)[0]
    parts = base.split("_")
    if len(parts) < 2:
        return None
    method = parts[-1].replace("_1", "_")
    cls = "/".join(parts[:-1]).replace("_1", "_")
    return cls, method


def _read_pointer(addr, pointer_size):
    memory = currentProgram.getMemory()
    try:
        if pointer_size == 8:
            raw = int(memory.getLong(addr)) & 0xFFFFFFFFFFFFFFFF
        else:
            raw = int(memory.getInt(addr)) & 0xFFFFFFFF
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(raw)
    except Exception:
        return None


def _read_c_string(addr, max_len=1024):
    memory = currentProgram.getMemory()
    if addr is None or not addr.isMemoryAddress() or not memory.contains(addr):
        return None
    data = bytearray()
    for i in range(max_len):
        try:
            value = int(memory.getByte(addr.add(i))) & 0xFF
        except Exception:
            return None
        if value == 0:
            break
        if value < 0x20 or value > 0x7E:
            return None
        data.append(value)
    if not data or len(data) >= max_len:
        return None
    try:
        return data.decode("ascii")
    except Exception:
        return None


def _symbol_addresses_named(*needles):
    out = []
    symbols = currentProgram.getSymbolTable().getAllSymbols(True)
    lowered = tuple(value.lower() for value in needles)
    while symbols.hasNext():
        symbol = symbols.next()
        name = str(symbol.getName()).lower()
        if any(value in name for value in lowered):
            out.append(symbol.getAddress())
    return out


def _function_reference_callsite(fn, target_addresses):
    if fn is None or not target_addresses:
        return None
    ref_manager = currentProgram.getReferenceManager()
    candidates = []
    for target in target_addresses:
        try:
            refs = ref_manager.getReferencesTo(target)
            while refs.hasNext():
                ref = refs.next()
                source = ref.getFromAddress()
                if fn.getBody().contains(source):
                    rva = _rva(source)
                    if rva is not None:
                        candidates.append(rva)
        except Exception:
            pass
    return min(candidates) if candidates else None


def _jni_class_strings_in_function(fn):
    if fn is None:
        return []
    listing = currentProgram.getListing()
    out = set()
    try:
        instructions = listing.getInstructions(fn.getBody(), True)
        while instructions.hasNext():
            ins = instructions.next()
            for ref in ins.getReferencesFrom():
                target = ref.getToAddress()
                if target is None or not target.isMemoryAddress():
                    continue
                data = listing.getDataAt(target)
                if data is None:
                    continue
                try:
                    value = str(data.getValue())
                except Exception:
                    continue
                value = value.strip('"')
                if len(value) <= 1024 and JNI_CLASS_RE.match(value):
                    out.add(value)
    except Exception:
        pass
    return sorted(out)


def _infer_jni_context(table_addr):
    ref_manager = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()
    find_class_targets = _symbol_addresses_named("FindClass")
    register_targets = _symbol_addresses_named("RegisterNatives")
    caller_functions = []
    # Tables may be referenced through any field of the first JNINativeMethod record.
    for delta in (0, int(currentProgram.getDefaultPointerSize()), int(currentProgram.getDefaultPointerSize()) * 2):
        try:
            refs = ref_manager.getReferencesTo(table_addr.add(delta))
            while refs.hasNext():
                fn = fm.getFunctionContaining(refs.next().getFromAddress())
                if fn is not None and fn not in caller_functions:
                    caller_functions.append(fn)
        except Exception:
            pass
    candidates = []
    for fn in caller_functions[:32]:
        classes = _jni_class_strings_in_function(fn)
        register_callsite = _function_reference_callsite(fn, register_targets)
        find_callsite = _function_reference_callsite(fn, find_class_targets)
        if register_callsite is None or len(classes) != 1:
            continue
        evidence = "FUNCTION_CLASS_STRING_AND_REGISTER_NATIVES"
        if find_callsite is not None:
            evidence = "FUNCTION_FINDCLASS_STRING_AND_REGISTER_NATIVES"
        candidates.append((classes[0], register_callsite, find_callsite, evidence))
    unique = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    return unique[0] if len(unique) == 1 else None


def _collect_jni(job):
    if "JNI_REGISTRATION_RECOVERY" not in set(job["analysisModes"]):
        return []
    out = []
    seen = set()
    symbol_table = currentProgram.getSymbolTable()
    memory = currentProgram.getMemory()
    fm = currentProgram.getFunctionManager()

    # Tier 1: static JNI exports.
    symbols = symbol_table.getAllSymbols(True)
    while symbols.hasNext():
        symbol = symbols.next()
        name = str(symbol.getName())
        decoded = _decode_jni_export(name)
        if decoded is None:
            continue
        rva = _rva(symbol.getAddress())
        if rva is None:
            continue
        key = ("STATIC_EXPORT", decoded[0], decoded[1], "", rva)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "source": "STATIC_EXPORT",
            "className": decoded[0],
            "methodName": decoded[1],
            "signature": "",
            "functionRva": rva,
            "confidence": "MEDIUM",
            "tableRva": None,
            "registerNativesCallsiteRva": None,
            "findClassCallsiteRva": None,
            "classEvidence": "STATIC_JNI_EXPORT_NAME",
        })

    # Tier 2: recover JNINativeMethod triples by following references to signature strings.
    pointer_size = int(currentProgram.getDefaultPointerSize())
    listing = currentProgram.getListing()
    ref_manager = currentProgram.getReferenceManager()
    data_iter = listing.getDefinedData(True)
    inspected = 0
    while data_iter.hasNext() and inspected < 1000000:
        inspected += 1
        data = data_iter.next()
        try:
            value = data.getValue()
            if value is None:
                continue
            signature = str(value)
        except Exception:
            continue
        if not JNI_SIGNATURE_RE.match(signature) or len(signature) > 1024:
            continue
        refs = ref_manager.getReferencesTo(data.getAddress())
        while refs.hasNext():
            ref = refs.next()
            sig_ptr = ref.getFromAddress()
            try:
                base = sig_ptr.subtract(pointer_size)
                name_addr = _read_pointer(base, pointer_size)
                sig_addr = _read_pointer(base.add(pointer_size), pointer_size)
                fn_addr = _read_pointer(base.add(pointer_size * 2), pointer_size)
            except Exception:
                continue
            if sig_addr is None or fn_addr is None or name_addr is None:
                continue
            recovered_sig = _read_c_string(sig_addr, 1024)
            method_name = _read_c_string(name_addr, 256)
            fn_rva = _rva(fn_addr)
            table_rva = _rva(base)
            if recovered_sig != signature or method_name is None or fn_rva is None or table_rva is None:
                continue
            if not JNI_METHOD_RE.match(method_name) or not memory.contains(fn_addr):
                continue
            # Require Ghidra to recognize code/function at or containing the target.
            if fm.getFunctionContaining(fn_addr) is None and listing.getInstructionAt(fn_addr) is None:
                continue
            context = _infer_jni_context(base)
            class_name = context[0] if context else "<dynamic>"
            register_callsite = context[1] if context else None
            find_callsite = context[2] if context else None
            class_evidence = context[3] if context else "JNINATIVE_METHOD_TABLE_ONLY"
            confidence = "HIGH" if context and find_callsite is not None else ("MEDIUM" if context else "HIGH")
            key = ("REGISTER_NATIVES_TABLE", class_name, method_name, signature, fn_rva, table_rva)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "source": "REGISTER_NATIVES_TABLE",
                "className": class_name,
                "methodName": method_name,
                "signature": signature,
                "functionRva": fn_rva,
                "confidence": confidence,
                "tableRva": table_rva,
                "registerNativesCallsiteRva": register_callsite,
                "findClassCallsiteRva": find_callsite,
                "classEvidence": class_evidence,
            })

    # Propagate a uniquely recovered FindClass/RegisterNatives context across adjacent
    # JNINativeMethod rows. Only contiguous triples receive the context; no global guessing.
    dynamic = sorted(
        [item for item in out if item["source"] == "REGISTER_NATIVES_TABLE" and item.get("tableRva") is not None],
        key=lambda item: item["tableRva"],
    )
    stride = pointer_size * 3
    groups = []
    current = []
    for item in dynamic:
        if current and item["tableRva"] != current[-1]["tableRva"] + stride:
            groups.append(current)
            current = []
        current.append(item)
    if current:
        groups.append(current)
    for group in groups:
        contexts = {(item["className"], item.get("registerNativesCallsiteRva"), item.get("findClassCallsiteRva"), item.get("classEvidence"))
                    for item in group if item["className"] != "<dynamic>"}
        if len(contexts) != 1:
            continue
        class_name, register_callsite, find_callsite, evidence = next(iter(contexts))
        for item in group:
            if item["className"] == "<dynamic>":
                item["className"] = class_name
                item["registerNativesCallsiteRva"] = register_callsite
                item["findClassCallsiteRva"] = find_callsite
                item["classEvidence"] = "ADJACENT_JNINATIVE_METHOD_TABLE_" + (evidence or "CONTEXT")
                item["confidence"] = "MEDIUM"
    return out


def _address_from_varnode(varnode):
    if varnode is None:
        return None
    memory = currentProgram.getMemory()
    factory = currentProgram.getAddressFactory()
    try:
        if varnode.isAddress():
            addr = varnode.getAddress()
            if addr is not None and addr.isMemoryAddress() and memory.contains(addr):
                return addr
        if varnode.isConstant():
            raw = int(varnode.getOffset())
            addr = factory.getDefaultAddressSpace().getAddress(raw)
            if memory.contains(addr):
                return addr
            base = currentProgram.getImageBase()
            if raw >= 0:
                relative = base.add(raw)
                if memory.contains(relative):
                    return relative
    except Exception:
        return None
    return None


def _recover_codegen_call_arguments(target_address, max_calls=128):
    fm = currentProgram.getFunctionManager()
    refs = currentProgram.getReferenceManager().getReferencesTo(target_address)
    caller_entries = []
    while refs.hasNext() and len(caller_entries) < max_calls * 4:
        ref = refs.next()
        fn = fm.getFunctionContaining(ref.getFromAddress())
        if fn is not None and fn not in caller_entries:
            caller_entries.append(fn)
    interface = DecompInterface()
    interface.toggleCCode(False)
    interface.toggleSyntaxTree(True)
    interface.setSimplificationStyle("decompile")
    if not interface.openProgram(currentProgram):
        interface.dispose()
        return []
    out = []
    try:
        for fn in caller_entries[:max_calls]:
            try:
                response = interface.decompileFunction(fn, 60, monitor)
                if not response.decompileCompleted() or response.getHighFunction() is None:
                    continue
                ops = response.getHighFunction().getPcodeOps()
                while ops.hasNext():
                    op = ops.next()
                    if op.getOpcode() != PcodeOp.CALL or op.getNumInputs() < 1:
                        continue
                    target = _address_from_varnode(op.getInput(0))
                    if target is None or target != target_address:
                        continue
                    args = []
                    for index in range(1, min(op.getNumInputs(), 4)):
                        args.append(_address_from_varnode(op.getInput(index)))
                    while len(args) < 3:
                        args.append(None)
                    callsite = _rva(op.getSeqnum().getTarget())
                    if callsite is None:
                        continue
                    recovered = sum(1 for value in args if value is not None)
                    out.append({
                        "callsiteRva": callsite,
                        "codeRegistrationRva": _rva(args[0]),
                        "metadataRegistrationRva": _rva(args[1]),
                        "codegenOptionsRva": _rva(args[2]),
                        "evidence": "DECOMPILER_PCODE_CALL_ARGUMENTS",
                        "confidence": "HIGH" if recovered >= 2 else "MEDIUM",
                    })
            except Exception:
                continue
    finally:
        interface.dispose()
    deduped = []
    seen = set()
    for item in out:
        key = (item["callsiteRva"], item["codeRegistrationRva"], item["metadataRegistrationRva"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _read_u32(addr):
    try:
        return int(currentProgram.getMemory().getInt(addr)) & 0xFFFFFFFF
    except Exception:
        return None


def _is_executable_address(addr):
    if addr is None:
        return False
    try:
        block = currentProgram.getMemory().getBlock(addr)
        return block is not None and bool(block.isExecute())
    except Exception:
        return False


def _collect_executable_pointer_tables(owner_rva, pointer_size, max_pairs=40, max_sample=32):
    if owner_rva is None:
        return []
    memory = currentProgram.getMemory()
    try:
        owner = currentProgram.getImageBase().add(int(owner_rva))
    except Exception:
        return []
    if not memory.contains(owner):
        return []
    pointer_offset = 8 if pointer_size == 8 else 4
    stride = 16 if pointer_size == 8 else 8
    out = []
    for pair in range(max_pairs):
        field_offset = pair * stride
        count = _read_u32(owner.add(field_offset))
        if count is None or count <= 0 or count > 5000000:
            continue
        table_addr = _read_pointer(owner.add(field_offset + pointer_offset), pointer_size)
        table_rva = _rva(table_addr)
        if table_addr is None or table_rva is None or not memory.contains(table_addr):
            continue
        sampled = min(int(count), max_sample)
        if sampled <= 0:
            continue
        executable = 0
        samples = []
        valid_reads = 0
        for index in range(sampled):
            try:
                fn_addr = _read_pointer(table_addr.add(index * pointer_size), pointer_size)
            except Exception:
                fn_addr = None
            if fn_addr is None:
                continue
            valid_reads += 1
            if _is_executable_address(fn_addr):
                executable += 1
                rva = _rva(fn_addr)
                if rva is not None and len(samples) < 16:
                    samples.append(rva)
        if valid_reads == 0:
            continue
        ratio = float(executable) / float(valid_reads)
        required = 1.0 if valid_reads < 4 else 0.75
        if ratio < required:
            continue
        confidence = "HIGH" if valid_reads >= 8 and ratio >= 0.95 else "MEDIUM"
        out.append({
            "ownerRva": int(owner_rva),
            "fieldOffsetBytes": field_offset,
            "entryCount": int(count),
            "tableRva": table_rva,
            "sampledEntries": valid_reads,
            "executableEntries": executable,
            "sampleFunctionRvas": sorted(set(samples)),
            "confidence": confidence,
        })
    return out



def _collect_codegen_modules(owner_rva, pointer_size, max_pairs=40, max_modules=256, max_method_slots=4096):
    if owner_rva is None:
        return []
    memory = currentProgram.getMemory()
    try:
        owner = currentProgram.getImageBase().add(int(owner_rva))
    except Exception:
        return []
    if not memory.contains(owner):
        return []
    pointer_offset = 8 if pointer_size == 8 else 4
    stride = 16 if pointer_size == 8 else 8
    method_ptr_offset = 16 if pointer_size == 8 else 8
    out = []
    seen = set()
    for pair in range(max_pairs):
        field_offset = pair * stride
        count = _read_u32(owner.add(field_offset))
        if count is None or count <= 0 or count > max_modules:
            continue
        modules_addr = _read_pointer(owner.add(field_offset + pointer_offset), pointer_size)
        if modules_addr is None or not memory.contains(modules_addr):
            continue
        valid = []
        for i in range(int(count)):
            module_addr = _read_pointer(modules_addr.add(i * pointer_size), pointer_size)
            if module_addr is None or not memory.contains(module_addr):
                continue
            name_ptr = _read_pointer(module_addr, pointer_size)
            module_name = _read_c_string(name_ptr, 512)
            if not module_name or not (module_name.endswith('.dll') or module_name.endswith('.exe')):
                continue
            method_count = _read_u32(module_addr.add(pointer_size))
            method_table = _read_pointer(module_addr.add(method_ptr_offset), pointer_size)
            if method_count is None or method_count < 0 or method_count > 5000000 or method_table is None or not memory.contains(method_table):
                continue
            sample_n = min(int(method_count), max_method_slots)
            slots = []
            readable = 0
            executable = 0
            for slot in range(sample_n):
                fn_addr = _read_pointer(method_table.add(slot * pointer_size), pointer_size)
                if fn_addr is None:
                    continue
                readable += 1
                if _is_executable_address(fn_addr):
                    executable += 1
                    rva = _rva(fn_addr)
                    if rva is not None:
                        slots.append({"slotIndex": slot, "functionRva": rva})
            if method_count > 0 and readable == 0:
                continue
            ratio = 1.0 if readable == 0 else float(executable) / float(readable)
            if method_count > 0 and ratio < 0.50:
                continue
            module_rva = _rva(module_addr)
            table_rva = _rva(method_table)
            if module_rva is None or table_rva is None:
                continue
            valid.append({
                "ownerCodeRegistrationRva": int(owner_rva),
                "moduleRva": module_rva,
                "moduleName": module_name,
                "methodPointerCount": int(method_count),
                "methodPointersRva": table_rva,
                "sampledMethodPointers": slots,
                "evidence": "CODE_REGISTRATION_MODULE_ARRAY_STRUCTURAL",
                "confidence": "HIGH" if ratio >= 0.90 else "MEDIUM",
            })
        if len(valid) != int(count):
            continue
        for item in valid:
            key = (item["moduleRva"], item["moduleName"], item["methodPointersRva"])
            if key not in seen:
                seen.add(key)
                out.append(item)
    return out[:max_modules]

def _collect_il2cpp(job):
    if "IL2CPP_REGISTRATION_CORRELATION" not in set(job["analysisModes"]):
        return [], [], [], []
    out = []
    seen = set()
    symbol_table = currentProgram.getSymbolTable()
    ref_manager = currentProgram.getReferenceManager()
    symbols = symbol_table.getAllSymbols(True)
    all_symbols = []
    while symbols.hasNext():
        all_symbols.append(symbols.next())

    codegen_addresses = []
    for kind, names in IL2CPP_NAMES.items():
        for symbol in all_symbols:
            name = str(symbol.getName())
            lower = name.lower()
            if not any(candidate.lower() in lower for candidate in names):
                continue
            rva = _rva(symbol.getAddress())
            if rva is None:
                continue
            key = (kind, rva, name, "DEFINED_SYMBOL")
            if key not in seen:
                seen.add(key)
                out.append({
                    "kind": kind,
                    "rva": rva,
                    "symbolName": name,
                    "evidence": "DEFINED_SYMBOL",
                    "confidence": "HIGH" if name in names else "MEDIUM",
                })
            if kind == "CODEGEN_REGISTER":
                codegen_addresses.append(symbol.getAddress())
                try:
                    refs = ref_manager.getReferencesTo(symbol.getAddress())
                    while refs.hasNext():
                        ref = refs.next()
                        callsite = _rva(ref.getFromAddress())
                        if callsite is None:
                            continue
                        ckey = (kind, callsite, name, "CALLSITE_REFERENCE")
                        if ckey in seen:
                            continue
                        seen.add(ckey)
                        out.append({
                            "kind": kind,
                            "rva": callsite,
                            "symbolName": name,
                            "evidence": "CALLSITE_REFERENCE",
                            "confidence": "MEDIUM",
                        })
                except Exception:
                    pass

    codegen_calls = []
    for address in codegen_addresses[:16]:
        codegen_calls.extend(_recover_codegen_call_arguments(address))
    pointer_size = int(currentProgram.getDefaultPointerSize())
    pointer_tables = []
    seen_tables = set()
    for call in codegen_calls:
        for table in _collect_executable_pointer_tables(call.get("codeRegistrationRva"), pointer_size):
            key = (table["ownerRva"], table["fieldOffsetBytes"], table["tableRva"])
            if key not in seen_tables:
                seen_tables.add(key)
                pointer_tables.append(table)
    codegen_modules = []
    seen_modules = set()
    for call in codegen_calls:
        for module in _collect_codegen_modules(call.get("codeRegistrationRva"), pointer_size):
            key = (module["moduleRva"], module["moduleName"], module["methodPointersRva"])
            if key not in seen_modules:
                seen_modules.add(key)
                codegen_modules.append(module)
    return out, codegen_calls[:256], pointer_tables[:256], codegen_modules[:256]

def main():
    job_path, output_path = _args()
    with open(job_path, "r", encoding="utf-8") as stream:
        job = json.load(stream)
    warnings = []
    functions, discovered, decompiled_count, fn_truncated = _collect_functions(job)
    function_rvas = [item["rva"] for item in functions]
    cfg, cfg_truncated = _collect_cfg(job, function_rvas)
    xrefs, xref_truncated = _collect_xrefs(job, function_rvas)
    jni = _collect_jni(job)
    il2cpp, il2cpp_codegen_calls, il2cpp_pointer_tables, il2cpp_codegen_modules = _collect_il2cpp(job)
    truncated = bool(fn_truncated or cfg_truncated or xref_truncated)
    if truncated:
        warnings.append("one or more result collections reached the configured worker resource ceiling")
    result = {
        "schemaVersion": "1.3",
        "assessmentId": job["assessmentId"],
        "artifactSha256": job["artifactSha256"],
        "libraryEntry": job["libraryEntry"],
        "status": "PARTIAL" if truncated else "COMPLETE",
        "engine": {
            "name": "Ghidra",
            "version": str(Application.getApplicationVersion()),
            "pyGhidra": True,
            "analysisProfile": job["analysisProfile"],
        },
        "architecture": {
            "processor": str(currentProgram.getLanguage().getProcessor()),
            "pointerSize": int(currentProgram.getDefaultPointerSize()),
            "endian": "BIG" if currentProgram.getLanguage().isBigEndian() else "LITTLE",
        },
        "coverage": {
            "functionsDiscovered": discovered,
            "functionsReported": len(functions),
            "cfgBlocksReported": sum(len(item["blocks"]) for item in cfg),
            "xrefsReported": len(xrefs),
            "decompilerFunctionsReported": decompiled_count,
            "truncated": truncated,
        },
        "functions": functions,
        "cfg": cfg,
        "xrefs": xrefs,
        "jniRegistrations": jni,
        "il2cppRegistrations": il2cpp,
        "il2cppCodegenCalls": il2cpp_codegen_calls,
        "il2cppPointerTables": il2cpp_pointer_tables,
        "il2cppCodegenModules": il2cpp_codegen_modules,
        "warnings": warnings,
    }
    tmp = output_path + ".write"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    os.replace(tmp, output_path)


main()
