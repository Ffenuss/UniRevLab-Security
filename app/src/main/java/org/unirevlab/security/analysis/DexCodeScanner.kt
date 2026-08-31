package org.unirevlab.security.analysis

import org.unirevlab.security.model.DexBasicBlock
import org.unirevlab.security.model.DexConstantReference
import org.unirevlab.security.model.DexInvokeArgument
import org.unirevlab.security.model.DexInvokeObservation
import org.unirevlab.security.model.DexFieldXref
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodCodeReference
import org.unirevlab.security.model.DexStringXref
import org.unirevlab.security.model.DexTypeXref
import java.io.File
import java.io.InterruptedIOException
import java.io.RandomAccessFile
import java.net.URI

/**
 * Bounded Dalvik bytecode indexer for defensive static analysis.
 *
 * The scanner never loads target classes and never executes target bytecode. M2.2 adds field xrefs,
 * normal-control-flow basic blocks, and deliberately conservative intra-block constant observations.
 * Unknown instructions clear the local constant state to avoid turning stale register values into
 * misleading security evidence.
 */
object DexCodeScanner {
    data class Limits(
        val maxDexBytes: Long = 96L * 1024L * 1024L,
        val maxMethodsWithCode: Int = 20_000,
        val maxInstructionUnitsPerMethod: Int = 1_000_000,
        val maxTotalInstructionUnits: Long = 8_000_000,
        val maxCallXrefs: Int = 100_000,
        val maxStringXrefs: Int = 60_000,
        val maxTypeXrefs: Int = 60_000,
        val maxFieldXrefs: Int = 80_000,
        val maxBasicBlocks: Int = 100_000,
        val maxConstants: Int = 60_000,
        val maxInvokeObservations: Int = 40_000,
        val maxObservedArguments: Int = 8,
        val maxStringBytes: Int = 64 * 1024,
        val maxProtoParameters: Int = 512,
        val maxEncodedMembersPerClass: Int = 100_000,
    )

    data class FileResult(
        val codeMethods: List<DexMethodCodeReference>,
        val callXrefs: List<DexMethodCallXref>,
        val stringXrefs: List<DexStringXref>,
        val typeXrefs: List<DexTypeXref>,
        val fieldXrefs: List<DexFieldXref>,
        val basicBlocks: List<DexBasicBlock>,
        val constants: List<DexConstantReference>,
        val invokeObservations: List<DexInvokeObservation>,
        val decodedInstructionUnits: Long,
        val decodeErrors: Int,
        val truncated: Boolean,
    )

    class DexCodeFormatException(message: String) : Exception(message)

    private data class Header(
        val fileSize: Long,
        val stringIdsSize: Int,
        val stringIdsOff: Long,
        val typeIdsSize: Int,
        val typeIdsOff: Long,
        val protoIdsSize: Int,
        val protoIdsOff: Long,
        val fieldIdsSize: Int,
        val fieldIdsOff: Long,
        val methodIdsSize: Int,
        val methodIdsOff: Long,
        val classDefsSize: Int,
        val classDefsOff: Long,
    )

    private data class MethodRef(
        val methodIndex: Int,
        val declaringClass: String,
        val name: String,
        val prototype: String,
    )

    private data class FieldRef(
        val fieldIndex: Int,
        val declaringClass: String,
        val name: String,
        val type: String,
    )

    private data class Instruction(
        val pc: Int,
        val width: Int,
        val opcode: Int,
        val branchTargets: List<Int> = emptyList(),
        val fallsThrough: Boolean = true,
        val terminalKind: String = "FALLTHROUGH",
    )

    private data class RegValue(val kind: String, val value: String)

    fun scan(
        dexEntry: String,
        file: File,
        limits: Limits = Limits(),
        structuralIndex: DexStringScanner.StructuralIndex? = null,
        onProgress: ((percent: Int, detail: String, completed: Int, total: Int) -> Unit)? = null,
    ): FileResult {
        require(file.length() <= limits.maxDexBytes) { "DEX exceeds ${limits.maxDexBytes} byte limit" }
        checkCancelled()
        onProgress?.invoke(0, "Подготовка bytecode index", 0, 1)
        RandomAccessFile(file, "r").use { raf ->
            val h = readHeader(raf)
            val codeMethods = mutableListOf<DexMethodCodeReference>()
            val calls = mutableListOf<DexMethodCallXref>()
            val strings = mutableListOf<DexStringXref>()
            val types = mutableListOf<DexTypeXref>()
            val fields = mutableListOf<DexFieldXref>()
            val blocks = mutableListOf<DexBasicBlock>()
            val constants = mutableListOf<DexConstantReference>()
            val observations = mutableListOf<DexInvokeObservation>()
            val methodCache = mutableMapOf<Int, MethodRef>()
            val fieldCache = mutableMapOf<Int, FieldRef>()
            var totalUnits = 0L
            var decodeErrors = 0
            var truncated = false

            val sharedMethods = structuralIndex?.methodsByIndex?.takeIf { it.size == h.methodIdsSize }
            fun methodRef(index: Int): MethodRef {
                val shared = sharedMethods?.getOrNull(index)
                if (shared != null) return MethodRef(shared.methodIndex, shared.declaringClass, shared.name, shared.prototype)
                return methodCache.getOrPut(index) { readMethod(raf, h, index, limits) }
            }
            fun fieldRef(index: Int): FieldRef = fieldCache.getOrPut(index) { readField(raf, h, index, limits) }

            fun decodeMethod(methodIndex: Int, codeOff: Long) {
                checkCancelled()
                if (codeMethods.size >= limits.maxMethodsWithCode || totalUnits >= limits.maxTotalInstructionUnits) {
                    truncated = true
                    return
                }
                try {
                    val ref = methodRef(methodIndex)
                    val decoded = decodeCodeItem(
                        raf = raf,
                        h = h,
                        dexEntry = dexEntry,
                        caller = ref,
                        codeOff = codeOff,
                        limits = limits,
                        calls = calls,
                        strings = strings,
                        types = types,
                        fields = fields,
                        blocks = blocks,
                        constants = constants,
                        observations = observations,
                        methodRef = ::methodRef,
                        fieldRef = ::fieldRef,
                    )
                    codeMethods += decoded.first
                    totalUnits += decoded.second
                    if (decoded.third) truncated = true
                } catch (_: DexCodeFormatException) {
                    decodeErrors++
                }
            }

            val reusableLocations = structuralIndex?.codeLocationsInClassOrder?.takeIf { sharedMethods != null }
            if (reusableLocations != null) {
                val totalLocations = reusableLocations.size.coerceAtLeast(1)
                for ((locationIndex, location) in reusableLocations.withIndex()) {
                    if ((locationIndex and 0x1f) == 0) {
                        checkCancelled()
                        onProgress?.invoke(scaleProgress(locationIndex, totalLocations), "Bytecode methods / xrefs", locationIndex, totalLocations)
                    }
                    if (codeMethods.size >= limits.maxMethodsWithCode || totalUnits >= limits.maxTotalInstructionUnits) {
                        truncated = true
                        break
                    }
                    decodeMethod(location.methodIndex, location.codeOffset)
                }
            } else {
                for (classDefIndex in 0 until h.classDefsSize) {
                    if ((classDefIndex and 0x3f) == 0) {
                        checkCancelled()
                        onProgress?.invoke(scaleProgress(classDefIndex, h.classDefsSize.coerceAtLeast(1)), "Bytecode class_data / xrefs", classDefIndex, h.classDefsSize)
                    }
                    if (codeMethods.size >= limits.maxMethodsWithCode || totalUnits >= limits.maxTotalInstructionUnits) {
                        truncated = true
                        break
                    }
                    val base = h.classDefsOff + classDefIndex.toLong() * 32L
                    val classDataOff = readU32(raf, base + 24)
                    if (classDataOff == 0L) continue
                    if (classDataOff >= h.fileSize) throw DexCodeFormatException("class_data_off outside DEX")
                    raf.seek(classDataOff)
                    val staticFields = readUleb128(raf, h.fileSize)
                    val instanceFields = readUleb128(raf, h.fileSize)
                    val directMethods = readUleb128(raf, h.fileSize)
                    val virtualMethods = readUleb128(raf, h.fileSize)
                    val memberCount = staticFields + instanceFields + directMethods + virtualMethods
                    if (memberCount > limits.maxEncodedMembersPerClass) throw DexCodeFormatException("class_data member count exceeds limit")
                    repeat((staticFields + instanceFields).toInt()) { memberIndex ->
                        if ((memberIndex and 0xff) == 0) checkCancelled()
                        readUleb128(raf, h.fileSize)
                        readUleb128(raf, h.fileSize)
                    }

                    fun decodeMethodList(count: Int) {
                        var methodIndex = 0L
                        repeat(count) { memberIndex ->
                            if ((memberIndex and 0xff) == 0) checkCancelled()
                            methodIndex += readUleb128(raf, h.fileSize)
                            readUleb128(raf, h.fileSize) // access_flags
                            val codeOff = readUleb128(raf, h.fileSize)
                            if (methodIndex > Int.MAX_VALUE || methodIndex >= h.methodIdsSize) throw DexCodeFormatException("encoded method_idx outside method_ids")
                            if (codeOff == 0L) return@repeat
                            if (codeMethods.size >= limits.maxMethodsWithCode || totalUnits >= limits.maxTotalInstructionUnits) {
                                truncated = true
                                return@repeat
                            }
                            val classDataCursor = raf.filePointer
                            try {
                                decodeMethod(methodIndex.toInt(), codeOff)
                            } finally {
                                raf.seek(classDataCursor)
                            }
                        }
                    }

                    decodeMethodList(directMethods.toInt())
                    decodeMethodList(virtualMethods.toInt())
                }
            }

            checkCancelled()
            val progressTotal = reusableLocations?.size ?: h.classDefsSize
            onProgress?.invoke(100, "Bytecode xrefs/CFG готовы", progressTotal, progressTotal)
            return FileResult(
                // Decoder visits each valid method/instruction position once. Avoid terminal
                // distinctBy copies here: on very large DEX files they temporarily doubled the
                // xref/CFG graph and its key sets, which could kill the Android process.
                codeMethods = codeMethods,
                callXrefs = calls,
                stringXrefs = strings,
                typeXrefs = types,
                fieldXrefs = fields,
                basicBlocks = blocks,
                constants = constants,
                invokeObservations = observations,
                decodedInstructionUnits = totalUnits,
                decodeErrors = decodeErrors,
                truncated = truncated,
            )
        }
    }

    /** Returns method metadata, decoded code-unit count, and whether bounded result lists truncated. */
    private fun decodeCodeItem(
        raf: RandomAccessFile,
        h: Header,
        dexEntry: String,
        caller: MethodRef,
        codeOff: Long,
        limits: Limits,
        calls: MutableList<DexMethodCallXref>,
        strings: MutableList<DexStringXref>,
        types: MutableList<DexTypeXref>,
        fields: MutableList<DexFieldXref>,
        blocks: MutableList<DexBasicBlock>,
        constants: MutableList<DexConstantReference>,
        observations: MutableList<DexInvokeObservation>,
        methodRef: (Int) -> MethodRef,
        fieldRef: (Int) -> FieldRef,
    ): Triple<DexMethodCodeReference, Long, Boolean> {
        ensureRange(codeOff, 16, h.fileSize, "code_item")
        val registersSize = readU16(raf, codeOff)
        val insSize = readU16(raf, codeOff + 2)
        val outsSize = readU16(raf, codeOff + 4)
        val triesSize = readU16(raf, codeOff + 6)
        val insnsSizeLong = readU32(raf, codeOff + 12)
        if (insnsSizeLong > limits.maxInstructionUnitsPerMethod) throw DexCodeFormatException("code_item exceeds instruction limit")
        val insnsSize = insnsSizeLong.toInt()
        val insnsOff = codeOff + 16
        ensureRange(insnsOff, insnsSizeLong * 2L, h.fileSize, "code_item instructions")
        val meta = DexMethodCodeReference(
            dexEntry = dexEntry,
            methodIndex = caller.methodIndex,
            declaringClass = caller.declaringClass,
            name = caller.name,
            prototype = caller.prototype,
            codeOffset = codeOff,
            registersSize = registersSize,
            insSize = insSize,
            outsSize = outsSize,
            triesSize = triesSize,
            instructionUnits = insnsSize,
        )

        val decodedInstructions = mutableListOf<Instruction>()
        var pc = 0
        var truncated = false
        while (pc < insnsSize) {
            val unit0 = readU16(raf, insnsOff + pc.toLong() * 2L)
            val opcode = unit0 and 0xff
            val width = instructionWidth(raf, insnsOff, pc, insnsSize, unit0)
            if (width <= 0 || pc > insnsSize - width) throw DexCodeFormatException("instruction exceeds code_item")

            when (opcode) {
                0x1a -> { // const-string vAA, string@BBBB
                    val index = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    if (index >= h.stringIdsSize) throw DexCodeFormatException("const-string index outside string_ids")
                    val safe = safeString(readString(raf, h, index, limits.maxStringBytes))
                    if (strings.size < limits.maxStringXrefs) {
                        strings += DexStringXref(
                            dexEntry, caller.methodIndex, caller.declaringClass, caller.name,
                            index, safe, pc,
                        )
                    } else truncated = true
                }
                0x1b -> { // const-string/jumbo
                    val indexLong = readU32FromUnits(raf, insnsOff, pc + 1, insnsSize).toLong() and 0xffffffffL
                    if (indexLong > Int.MAX_VALUE || indexLong >= h.stringIdsSize) throw DexCodeFormatException("jumbo string index outside string_ids")
                    if (strings.size < limits.maxStringXrefs) {
                        val index = indexLong.toInt()
                        val safe = safeString(readString(raf, h, index, limits.maxStringBytes))
                            strings += DexStringXref(
                            dexEntry, caller.methodIndex, caller.declaringClass, caller.name,
                            index, safe, pc,
                        )
                    } else truncated = true
                }
                0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25 -> {
                    val typeIndex = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    if (typeIndex >= h.typeIdsSize) throw DexCodeFormatException("type reference outside type_ids")
                    val descriptor = typeDescriptor(raf, h, typeIndex, limits.maxStringBytes)
                    if (types.size < limits.maxTypeXrefs) {
                        types += DexTypeXref(
                            dexEntry, caller.methodIndex, caller.declaringClass, caller.name,
                            typeIndex, descriptor, typeXrefKind(opcode), pc,
                        )
                    } else truncated = true
                }
                in 0x52..0x6d -> {
                    val fieldIndex = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    if (fieldIndex >= h.fieldIdsSize) throw DexCodeFormatException("field reference outside field_ids")
                    if (fields.size < limits.maxFieldXrefs) {
                        val field = fieldRef(fieldIndex)
                        fields += DexFieldXref(
                            dexEntry, caller.methodIndex, caller.declaringClass, caller.name,
                            field.fieldIndex, field.declaringClass, field.name, field.type,
                            fieldXrefKind(opcode), pc,
                        )
                    } else truncated = true
                }
                in 0x6e..0x72, in 0x74..0x78, 0xfa, 0xfb -> {
                    val methodIndex = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    if (methodIndex >= h.methodIdsSize) throw DexCodeFormatException("invoke method index outside method_ids")
                    if (calls.size < limits.maxCallXrefs) {
                        val callee = methodRef(methodIndex)
                        calls += DexMethodCallXref(
                            dexEntry, caller.methodIndex, caller.declaringClass, caller.name,
                            callee.methodIndex, callee.declaringClass, callee.name, callee.prototype, pc,
                        )
                    } else truncated = true
                }
            }

            decodedInstructions += decodeControlFlowInstruction(raf, insnsOff, pc, insnsSize, unit0, width)
            pc += width
        }

        val methodBlocks = buildBasicBlocks(dexEntry, caller, decodedInstructions, insnsSize)
        if (blocks.size < limits.maxBasicBlocks) {
            val remaining = limits.maxBasicBlocks - blocks.size
            blocks += methodBlocks.take(remaining)
            if (methodBlocks.size > remaining) truncated = true
        } else if (methodBlocks.isNotEmpty()) truncated = true

        val observed = observeConstants(
            raf, h, dexEntry, caller, insnsOff, insnsSize, decodedInstructions, methodBlocks, limits, methodRef,
        )
        val methodConstants = observed.first
        val methodObservations = observed.second
        if (constants.size < limits.maxConstants) {
            val remaining = limits.maxConstants - constants.size
            constants += methodConstants.take(remaining)
            if (methodConstants.size > remaining) truncated = true
        } else if (methodConstants.isNotEmpty()) truncated = true
        if (observations.size < limits.maxInvokeObservations) {
            val remaining = limits.maxInvokeObservations - observations.size
            observations += methodObservations.take(remaining)
            if (methodObservations.size > remaining) truncated = true
        } else if (methodObservations.isNotEmpty()) truncated = true

        return Triple(meta, insnsSizeLong, truncated)
    }

    private fun decodeControlFlowInstruction(
        raf: RandomAccessFile,
        insnsOff: Long,
        pc: Int,
        insnsSize: Int,
        unit0: Int,
        width: Int,
    ): Instruction {
        val opcode = unit0 and 0xff
        fun validTarget(target: Int): Int {
            if (target !in 0 until insnsSize) throw DexCodeFormatException("branch target outside code_item")
            return target
        }
        return when (opcode) {
            0x28 -> {
                val rel = ((unit0 ushr 8) and 0xff).toByte().toInt()
                Instruction(pc, width, opcode, listOf(validTarget(pc + rel)), fallsThrough = false, terminalKind = "GOTO")
            }
            0x29 -> {
                val rel = readUnit(raf, insnsOff, pc + 1, insnsSize).toShort().toInt()
                Instruction(pc, width, opcode, listOf(validTarget(pc + rel)), fallsThrough = false, terminalKind = "GOTO")
            }
            0x2a -> {
                val rel = readI32FromUnits(raf, insnsOff, pc + 1, insnsSize)
                Instruction(pc, width, opcode, listOf(validTarget(pc + rel)), fallsThrough = false, terminalKind = "GOTO")
            }
            0x2b, 0x2c -> {
                val payloadRel = readI32FromUnits(raf, insnsOff, pc + 1, insnsSize)
                val payloadPc = validTarget(pc + payloadRel)
                val targets = readSwitchTargets(raf, insnsOff, pc, payloadPc, insnsSize, opcode)
                Instruction(pc, width, opcode, targets, fallsThrough = true, terminalKind = "SWITCH")
            }
            in 0x32..0x3d -> {
                val rel = readUnit(raf, insnsOff, pc + 1, insnsSize).toShort().toInt()
                Instruction(pc, width, opcode, listOf(validTarget(pc + rel)), fallsThrough = true, terminalKind = "CONDITIONAL")
            }
            in 0x0e..0x11 -> Instruction(pc, width, opcode, fallsThrough = false, terminalKind = "RETURN")
            0x27 -> Instruction(pc, width, opcode, fallsThrough = false, terminalKind = "THROW")
            else -> Instruction(pc, width, opcode)
        }
    }

    private fun readSwitchTargets(
        raf: RandomAccessFile,
        insnsOff: Long,
        switchPc: Int,
        payloadPc: Int,
        insnsSize: Int,
        opcode: Int,
    ): List<Int> {
        val ident = readUnit(raf, insnsOff, payloadPc, insnsSize)
        val size = readUnit(raf, insnsOff, payloadPc + 1, insnsSize)
        if (size > 65_535) throw DexCodeFormatException("switch payload size invalid")
        val targetStart = when (opcode) {
            0x2b -> {
                if (ident != 0x0100) throw DexCodeFormatException("packed-switch payload identifier mismatch")
                payloadPc + 4
            }
            0x2c -> {
                if (ident != 0x0200) throw DexCodeFormatException("sparse-switch payload identifier mismatch")
                payloadPc + 2 + size * 2
            }
            else -> throw DexCodeFormatException("not a switch opcode")
        }
        val needed = targetStart.toLong() + size.toLong() * 2L
        if (needed > insnsSize) throw DexCodeFormatException("switch payload exceeds code_item")
        return buildList {
            repeat(size) { i ->
                val rel = readI32FromUnits(raf, insnsOff, targetStart + i * 2, insnsSize)
                val target = switchPc.toLong() + rel.toLong()
                if (target < 0 || target >= insnsSize) throw DexCodeFormatException("switch target outside code_item")
                add(target.toInt())
            }
        }.distinct()
    }

    private fun buildBasicBlocks(
        dexEntry: String,
        caller: MethodRef,
        instructions: List<Instruction>,
        insnsSize: Int,
    ): List<DexBasicBlock> {
        if (instructions.isEmpty()) return emptyList()
        val leaders = sortedSetOf(0)
        instructions.forEach { insn ->
            insn.branchTargets.forEach(leaders::add)
            val next = insn.pc + insn.width
            if ((insn.branchTargets.isNotEmpty() || !insn.fallsThrough) && next < insnsSize) leaders += next
        }
        val starts = leaders.filter { it in 0 until insnsSize }.sorted()
        val byPc = instructions.associateBy { it.pc }
        return starts.mapIndexedNotNull { index, start ->
            val end = starts.getOrNull(index + 1) ?: insnsSize
            if (end <= start) return@mapIndexedNotNull null
            val last = instructions.lastOrNull { it.pc in start until end } ?: return@mapIndexedNotNull null
            val successors = linkedSetOf<Int>()
            last.branchTargets.filterTo(successors) { it in starts }
            val fallthrough = last.pc + last.width
            if (last.fallsThrough && fallthrough < insnsSize) {
                val successorStart = starts.firstOrNull { it >= fallthrough }
                if (successorStart != null) successors += successorStart
            }
            val terminal = when {
                last.terminalKind != "FALLTHROUGH" -> last.terminalKind
                successors.isEmpty() -> "END"
                else -> "FALLTHROUGH"
            }
            // Ensure every block start resolves to a decoded instruction. Payload leaders are never added.
            if (byPc[start] == null) return@mapIndexedNotNull null
            DexBasicBlock(
                dexEntry = dexEntry,
                methodIndex = caller.methodIndex,
                blockIndex = index,
                startCodeUnit = start,
                endCodeUnitExclusive = end,
                successorCodeUnits = successors.toList().sorted(),
                terminalKind = terminal,
            )
        }
    }

    /**
     * Performs local constant propagation inside individual basic blocks only. This deliberately
     * avoids merging values across branches, exception edges, or loops until a later data-flow pass.
     */
    private fun observeConstants(
        raf: RandomAccessFile,
        h: Header,
        dexEntry: String,
        caller: MethodRef,
        insnsOff: Long,
        insnsSize: Int,
        instructions: List<Instruction>,
        blocks: List<DexBasicBlock>,
        limits: Limits,
        methodRef: (Int) -> MethodRef,
    ): Pair<List<DexConstantReference>, List<DexInvokeObservation>> {
        val blockStarts = blocks.mapTo(hashSetOf()) { it.startCodeUnit }
        val state = mutableMapOf<Int, RegValue>()
        val constants = mutableListOf<DexConstantReference>()
        val out = mutableListOf<DexInvokeObservation>()
        fun record(register: Int, kind: String, value: String, pc: Int) {
            state[register] = RegValue(kind, value)
            constants += DexConstantReference(dexEntry, caller.methodIndex, register, kind, value, pc)
        }

        for (insn in instructions) {
            if (insn.pc in blockStarts) state.clear()
            val pc = insn.pc
            val unit0 = readU16(raf, insnsOff + pc.toLong() * 2L)
            val opcode = insn.opcode
            when (opcode) {
                0x01, 0x04, 0x07 -> { // move/move-wide/move-object 12x
                    val dest = (unit0 ushr 8) and 0x0f
                    val src = (unit0 ushr 12) and 0x0f
                    assignMove(state, dest, src)
                }
                0x02, 0x05, 0x08 -> { // 22x
                    val dest = (unit0 ushr 8) and 0xff
                    val src = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    assignMove(state, dest, src)
                }
                0x03, 0x06, 0x09 -> { // 32x
                    val dest = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    val src = readUnit(raf, insnsOff, pc + 2, insnsSize)
                    assignMove(state, dest, src)
                }
                0x12 -> { // const/4
                    val dest = (unit0 ushr 8) and 0x0f
                    val nibble = (unit0 ushr 12) and 0x0f
                    val value = if (nibble and 0x8 != 0) nibble - 16 else nibble
                    record(dest, if (value == 0) "NULL_OR_INT" else "INT", value.toString(), pc)
                }
                0x13 -> {
                    val dest = (unit0 ushr 8) and 0xff
                    record(dest, "INT", readUnit(raf, insnsOff, pc + 1, insnsSize).toShort().toInt().toString(), pc)
                }
                0x14 -> {
                    val dest = (unit0 ushr 8) and 0xff
                    record(dest, "INT", readI32FromUnits(raf, insnsOff, pc + 1, insnsSize).toString(), pc)
                }
                0x15 -> {
                    val dest = (unit0 ushr 8) and 0xff
                    val value = readUnit(raf, insnsOff, pc + 1, insnsSize).toShort().toInt() shl 16
                    record(dest, "INT", value.toString(), pc)
                }
                0x16 -> {
                    val dest = (unit0 ushr 8) and 0xff
                    record(dest, "LONG", readUnit(raf, insnsOff, pc + 1, insnsSize).toShort().toLong().toString(), pc)
                }
                0x17 -> {
                    val dest = (unit0 ushr 8) and 0xff
                    record(dest, "LONG", readI32FromUnits(raf, insnsOff, pc + 1, insnsSize).toLong().toString(), pc)
                }
                0x18 -> {
                    val dest = (unit0 ushr 8) and 0xff
                    val lo = readU32FromUnits(raf, insnsOff, pc + 1, insnsSize).toLong() and 0xffffffffL
                    val hi = readU32FromUnits(raf, insnsOff, pc + 3, insnsSize).toLong()
                    val value = (hi shl 32) or lo
                    record(dest, "LONG", value.toString(), pc)
                }
                0x19 -> {
                    val dest = (unit0 ushr 8) and 0xff
                    val value = readUnit(raf, insnsOff, pc + 1, insnsSize).toShort().toLong() shl 48
                    record(dest, "LONG", value.toString(), pc)
                }
                0x1a -> {
                    val dest = (unit0 ushr 8) and 0xff
                    val index = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    record(dest, "STRING", safeString(readString(raf, h, index, limits.maxStringBytes)), pc)
                }
                0x1b -> {
                    val dest = (unit0 ushr 8) and 0xff
                    val indexLong = readU32FromUnits(raf, insnsOff, pc + 1, insnsSize).toLong() and 0xffffffffL
                    if (indexLong > Int.MAX_VALUE || indexLong >= h.stringIdsSize) {
                        state.remove(dest)
                    } else {
                        record(dest, "STRING", safeString(readString(raf, h, indexLong.toInt(), limits.maxStringBytes)), pc)
                    }
                }
                0x1c -> {
                    val dest = (unit0 ushr 8) and 0xff
                    val typeIndex = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    record(dest, "TYPE", typeDescriptor(raf, h, typeIndex, limits.maxStringBytes), pc)
                }
                in 0x6e..0x72, in 0x74..0x78, 0xfa, 0xfb -> {
                    val methodIndex = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    if (methodIndex in 0 until h.methodIdsSize) {
                        val callee = methodRef(methodIndex)
                        val registers = invokeRegisters(raf, insnsOff, pc, insnsSize, unit0, opcode)
                        val args = registers.take(limits.maxObservedArguments).mapIndexedNotNull { argumentIndex, register ->
                            state[register]?.let { value -> DexInvokeArgument(argumentIndex, register, value.kind, value.value) }
                        }
                        if (args.isNotEmpty()) {
                            out += DexInvokeObservation(
                                dexEntry = dexEntry,
                                callerMethodIndex = caller.methodIndex,
                                callerClass = caller.declaringClass,
                                callerName = caller.name,
                                calleeMethodIndex = callee.methodIndex,
                                calleeClass = callee.declaringClass,
                                calleeName = callee.name,
                                calleePrototype = callee.prototype,
                                instructionOffsetCodeUnits = pc,
                                arguments = args,
                            )
                        }
                    }
                }
                // These are reads/control-flow operations and do not overwrite tracked source registers.
                0x00, in 0x0e..0x11, 0x1d, 0x1e, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, in 0x32..0x3d -> Unit
                else -> state.clear() // conservative kill for unmodelled register writes/side effects
            }
        }
        return constants to out
    }

    private fun assignMove(state: MutableMap<Int, RegValue>, dest: Int, src: Int) {
        val value = state[src]
        if (value == null) state.remove(dest) else state[dest] = value
    }

    private fun invokeRegisters(
        raf: RandomAccessFile,
        insnsOff: Long,
        pc: Int,
        insnsSize: Int,
        unit0: Int,
        opcode: Int,
    ): List<Int> = when (opcode) {
        in 0x6e..0x72, 0xfa -> {
            val count = (unit0 ushr 12) and 0x0f
            if (count > 5) throw DexCodeFormatException("invoke register count exceeds format")
            val g = (unit0 ushr 8) and 0x0f
            val packed = readUnit(raf, insnsOff, pc + 2, insnsSize)
            val regs = listOf(packed and 0x0f, (packed ushr 4) and 0x0f, (packed ushr 8) and 0x0f, (packed ushr 12) and 0x0f, g)
            regs.take(count)
        }
        in 0x74..0x78, 0xfb -> {
            val count = (unit0 ushr 8) and 0xff
            val first = readUnit(raf, insnsOff, pc + 2, insnsSize)
            if (count > 255 || first.toLong() + count.toLong() > 65_536L) throw DexCodeFormatException("invoke/range registers invalid")
            (0 until count).map { first + it }
        }
        else -> emptyList()
    }

    private fun typeXrefKind(opcode: Int): String = when (opcode) {
        0x1c -> "CONST_CLASS"
        0x1f -> "CHECK_CAST"
        0x20 -> "INSTANCE_OF"
        0x22 -> "NEW_INSTANCE"
        0x23 -> "NEW_ARRAY"
        0x24, 0x25 -> "FILLED_NEW_ARRAY"
        else -> "TYPE_REFERENCE"
    }

    private fun fieldXrefKind(opcode: Int): String = when (opcode) {
        in 0x52..0x58 -> "INSTANCE_GET"
        in 0x59..0x5f -> "INSTANCE_PUT"
        in 0x60..0x66 -> "STATIC_GET"
        in 0x67..0x6d -> "STATIC_PUT"
        else -> "FIELD_REFERENCE"
    }

    private fun safeString(value: String): String {
        SensitiveStringClassifier.detectKind(value)?.let { kind ->
            return "<redacted:$kind sha256=${SensitiveStringClassifier.sha256(value)}>"
        }
        val trimmed = value.take(512)
        if (trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true)) {
            return try {
                val uri = URI(trimmed)
                URI(uri.scheme, uri.userInfo, uri.host, uri.port, uri.path, null, null).toString().take(512)
            } catch (_: Exception) {
                trimmed.substringBefore('?').substringBefore('#')
            }
        }
        return trimmed
    }

    private fun instructionWidth(raf: RandomAccessFile, insnsOff: Long, pc: Int, insnsSize: Int, unit0: Int): Int {
        val opcode = unit0 and 0xff
        if (opcode == 0x00) {
            return when ((unit0 ushr 8) and 0xff) {
                0x00 -> 1
                0x01 -> { // packed-switch-payload
                    val size = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    checkedWidth(4L + size.toLong() * 2L)
                }
                0x02 -> { // sparse-switch-payload
                    val size = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    checkedWidth(2L + size.toLong() * 4L)
                }
                0x03 -> { // fill-array-data-payload
                    val elementWidth = readUnit(raf, insnsOff, pc + 1, insnsSize)
                    val size = readU32FromUnits(raf, insnsOff, pc + 2, insnsSize).toLong() and 0xffffffffL
                    val bytes = size.checkedMul(elementWidth.toLong())
                    checkedWidth(4L + ((bytes + 1L) / 2L))
                }
                else -> throw DexCodeFormatException("unknown payload ident")
            }
        }
        return when (opcode) {
            0x01, 0x04, 0x07, in 0x0a..0x12, 0x1d, 0x1e, 0x21, 0x27, 0x28,
            in 0x7b..0x8f, in 0xb0..0xcf -> 1
            0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20,
            0x22, 0x23, 0x29, in 0x2d..0x3d, in 0x44..0x6d, in 0x90..0xaf,
            in 0xd0..0xe2, 0xfe, 0xff -> 2
            0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c,
            in 0x6e..0x72, in 0x74..0x78, 0xfc, 0xfd -> 3
            0xfa, 0xfb -> 4
            0x18 -> 5
            else -> throw DexCodeFormatException("unsupported/invalid DEX opcode 0x${opcode.toString(16)}")
        }
    }

    private fun checkedWidth(value: Long): Int {
        if (value <= 0 || value > Int.MAX_VALUE) throw DexCodeFormatException("payload width overflow")
        return value.toInt()
    }

    private fun Long.checkedMul(other: Long): Long {
        if (this != 0L && other > Long.MAX_VALUE / this) throw DexCodeFormatException("size multiplication overflow")
        return this * other
    }

    private fun readUnit(raf: RandomAccessFile, insnsOff: Long, pc: Int, insnsSize: Int): Int {
        if (pc !in 0 until insnsSize) throw DexCodeFormatException("instruction operand outside code_item")
        return readU16(raf, insnsOff + pc.toLong() * 2L)
    }

    private fun readU32FromUnits(raf: RandomAccessFile, insnsOff: Long, pc: Int, insnsSize: Int): Int {
        val lo = readUnit(raf, insnsOff, pc, insnsSize)
        val hi = readUnit(raf, insnsOff, pc + 1, insnsSize)
        return lo or (hi shl 16)
    }

    private fun readI32FromUnits(raf: RandomAccessFile, insnsOff: Long, pc: Int, insnsSize: Int): Int =
        readU32FromUnits(raf, insnsOff, pc, insnsSize)

    private fun checkCancelled() {
        if (Thread.currentThread().isInterrupted) throw InterruptedIOException("DEX bytecode analysis cancelled")
    }

    private fun scaleProgress(completed: Int, total: Int): Int {
        if (total <= 0) return 100
        return ((completed.toDouble() / total.toDouble()).coerceIn(0.0, 1.0) * 100.0).toInt()
    }

    private fun readHeader(raf: RandomAccessFile): Header {
        if (raf.length() < 0x70) throw DexCodeFormatException("DEX header truncated")
        val magic = ByteArray(8)
        raf.seek(0); raf.readFully(magic)
        if (!(magic[0] == 'd'.code.toByte() && magic[1] == 'e'.code.toByte() && magic[2] == 'x'.code.toByte() && magic[3] == '\n'.code.toByte() && magic[7] == 0.toByte())) {
            throw DexCodeFormatException("invalid DEX magic")
        }
        val fileSize = readU32(raf, 0x20)
        if (fileSize > raf.length() || fileSize < 0x70) throw DexCodeFormatException("invalid DEX file_size")
        if (readU32(raf, 0x24) != 0x70L || readU32(raf, 0x28) != 0x12345678L) throw DexCodeFormatException("unsupported DEX header")
        fun table(sizeOff: Long, offOff: Long, itemSize: Long, label: String): Pair<Int, Long> {
            val sizeLong = readU32(raf, sizeOff)
            val off = readU32(raf, offOff)
            if (sizeLong > Int.MAX_VALUE) throw DexCodeFormatException("$label too large")
            if (sizeLong > 0) {
                if (off == 0L) throw DexCodeFormatException("$label offset missing")
                ensureRange(off, sizeLong.checkedMul(itemSize), fileSize, label)
            }
            return sizeLong.toInt() to off
        }
        val strings = table(0x38, 0x3c, 4, "string_ids")
        val types = table(0x40, 0x44, 4, "type_ids")
        val protos = table(0x48, 0x4c, 12, "proto_ids")
        val fields = table(0x50, 0x54, 8, "field_ids")
        val methods = table(0x58, 0x5c, 8, "method_ids")
        val classes = table(0x60, 0x64, 32, "class_defs")
        return Header(
            fileSize, strings.first, strings.second, types.first, types.second, protos.first, protos.second,
            fields.first, fields.second, methods.first, methods.second, classes.first, classes.second,
        )
    }

    private fun readMethod(raf: RandomAccessFile, h: Header, index: Int, limits: Limits): MethodRef {
        if (index !in 0 until h.methodIdsSize) throw DexCodeFormatException("method index outside table")
        val base = h.methodIdsOff + index.toLong() * 8L
        val classIdx = readU16(raf, base)
        val protoIdx = readU16(raf, base + 2)
        val nameIdx = readU32(raf, base + 4).toIntChecked("name_idx")
        if (classIdx !in 0 until h.typeIdsSize || protoIdx !in 0 until h.protoIdsSize) throw DexCodeFormatException("method metadata index outside table")
        return MethodRef(index, typeDescriptor(raf, h, classIdx, limits.maxStringBytes), readString(raf, h, nameIdx, limits.maxStringBytes), readPrototype(raf, h, protoIdx, limits))
    }

    private fun readField(raf: RandomAccessFile, h: Header, index: Int, limits: Limits): FieldRef {
        if (index !in 0 until h.fieldIdsSize) throw DexCodeFormatException("field index outside table")
        val base = h.fieldIdsOff + index.toLong() * 8L
        val classIdx = readU16(raf, base)
        val typeIdx = readU16(raf, base + 2)
        val nameIdx = readU32(raf, base + 4).toIntChecked("field name_idx")
        if (classIdx !in 0 until h.typeIdsSize || typeIdx !in 0 until h.typeIdsSize) throw DexCodeFormatException("field metadata index outside table")
        return FieldRef(
            fieldIndex = index,
            declaringClass = typeDescriptor(raf, h, classIdx, limits.maxStringBytes),
            name = readString(raf, h, nameIdx, limits.maxStringBytes),
            type = typeDescriptor(raf, h, typeIdx, limits.maxStringBytes),
        )
    }

    private fun readPrototype(raf: RandomAccessFile, h: Header, protoIdx: Int, limits: Limits): String {
        val base = h.protoIdsOff + protoIdx.toLong() * 12L
        val returnTypeIdx = readU32(raf, base + 4).toIntChecked("return_type_idx")
        val parametersOff = readU32(raf, base + 8)
        val ret = typeDescriptor(raf, h, returnTypeIdx, limits.maxStringBytes)
        if (parametersOff == 0L) return "()$ret"
        ensureRange(parametersOff, 4, h.fileSize, "type_list")
        val count = readU32(raf, parametersOff)
        if (count > limits.maxProtoParameters) throw DexCodeFormatException("too many prototype parameters")
        ensureRange(parametersOff + 4, count.checkedMul(2), h.fileSize, "type_list items")
        return buildString {
            append('(')
            repeat(count.toInt()) { i -> append(typeDescriptor(raf, h, readU16(raf, parametersOff + 4 + i.toLong() * 2), limits.maxStringBytes)) }
            append(')').append(ret)
        }
    }

    private fun typeDescriptor(raf: RandomAccessFile, h: Header, typeIndex: Int, maxStringBytes: Int): String {
        if (typeIndex !in 0 until h.typeIdsSize) throw DexCodeFormatException("type index outside table")
        val stringIndex = readU32(raf, h.typeIdsOff + typeIndex.toLong() * 4L).toIntChecked("descriptor_idx")
        return readString(raf, h, stringIndex, maxStringBytes)
    }

    private fun readString(raf: RandomAccessFile, h: Header, index: Int, maxBytes: Int): String {
        if (index !in 0 until h.stringIdsSize) throw DexCodeFormatException("string index outside table")
        val offset = readU32(raf, h.stringIdsOff + index.toLong() * 4L)
        if (offset >= h.fileSize) throw DexCodeFormatException("string_data_off outside DEX")
        raf.seek(offset)
        readUleb128(raf, h.fileSize) // UTF-16 unit count
        val bytes = ByteArray(maxBytes)
        var count = 0
        var terminated = false
        while (raf.filePointer < h.fileSize) {
            val b = raf.read()
            if (b < 0) break
            if (b == 0) { terminated = true; break }
            if (count >= maxBytes) throw DexCodeFormatException("string exceeds bounded code-xref limit")
            bytes[count++] = b.toByte()
        }
        if (!terminated) throw DexCodeFormatException("unterminated string")
        return bytes.copyOf(count).toString(Charsets.UTF_8)
    }

    private fun readUleb128(raf: RandomAccessFile, fileSize: Long): Long {
        var result = 0L
        var shift = 0
        repeat(5) {
            if (raf.filePointer >= fileSize) throw DexCodeFormatException("truncated uleb128")
            val b = raf.readUnsignedByte()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        throw DexCodeFormatException("uleb128 exceeds 5 bytes")
    }

    private fun readU16(raf: RandomAccessFile, offset: Long): Int {
        ensureRange(offset, 2, raf.length(), "u16")
        raf.seek(offset)
        return raf.readUnsignedByte() or (raf.readUnsignedByte() shl 8)
    }

    private fun readU32(raf: RandomAccessFile, offset: Long): Long {
        ensureRange(offset, 4, raf.length(), "u32")
        raf.seek(offset)
        return raf.readUnsignedByte().toLong() or
            (raf.readUnsignedByte().toLong() shl 8) or
            (raf.readUnsignedByte().toLong() shl 16) or
            (raf.readUnsignedByte().toLong() shl 24)
    }

    private fun Long.toIntChecked(label: String): Int {
        if (this < 0 || this > Int.MAX_VALUE) throw DexCodeFormatException("$label outside Int range")
        return toInt()
    }

    private fun ensureRange(offset: Long, size: Long, bound: Long, label: String) {
        if (offset < 0 || size < 0 || offset > bound || size > bound - offset) throw DexCodeFormatException("$label range outside DEX")
    }
}
