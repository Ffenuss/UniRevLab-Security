package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport

/** Runtime self-diagnostics for the analyzer's stored report and derived indexes. Target code is never executed. */
object DiagnosticsEngine {
    enum class Status { PASS, WARN, FAIL }

    data class Check(
        val id: String,
        val title: String,
        val status: Status,
        val detail: String,
    )

    data class Result(
        val checks: List<Check>,
        val passed: Int,
        val warnings: Int,
        val failed: Int,
    ) {
        val healthy: Boolean get() = failed == 0
    }

    fun run(report: StaticAnalysisReport): Result {
        val checks = buildList {
            add(reportIntegrity(report))
            add(dexIndex(report))
            add(dexXrefs(report))
            add(callGraph(report))
            add(deobfuscation(report))
            add(findings(report))
            add(nativeIndex(report))
            add(supplyChain(report))
            add(coverage(report))
        }
        return Result(
            checks = checks,
            passed = checks.count { it.status == Status.PASS },
            warnings = checks.count { it.status == Status.WARN },
            failed = checks.count { it.status == Status.FAIL },
        )
    }

    private fun reportIntegrity(report: StaticAnalysisReport): Check {
        val sha = report.artifact.sha256
        val validSha = sha.length == 64 && sha.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
        return when {
            report.artifact.displayName.isBlank() -> Check("REPORT", "Report model", Status.FAIL, "Artifact display name is empty")
            !validSha -> Check("REPORT", "Report model", Status.WARN, "Artifact SHA-256 is not a canonical 64-character digest")
            else -> Check("REPORT", "Report model", Status.PASS, "Artifact identity and report schema are readable")
        }
    }

    private fun dexIndex(report: StaticAnalysisReport): Check {
        val dex = report.dex ?: return Check("DEX_INDEX", "DEX structural index", Status.WARN, "No DEX index is present for this artifact")
        val invalid = dex.dexFilesScanned > dex.dexFilesDiscovered ||
            dex.classesIndexed > dex.classesDeclared ||
            dex.methodsIndexed > dex.methodsDeclared ||
            dex.stringsScanned > dex.stringsDeclared
        return if (invalid) {
            Check("DEX_INDEX", "DEX structural index", Status.FAIL, "Indexed counters exceed declared DEX counters")
        } else {
            Check(
                "DEX_INDEX", "DEX structural index", Status.PASS,
                "DEX ${dex.dexFilesScanned}/${dex.dexFilesDiscovered}; classes ${dex.classesIndexed}/${dex.classesDeclared}; methods ${dex.methodsIndexed}/${dex.methodsDeclared}",
            )
        }
    }

    private fun dexXrefs(report: StaticAnalysisReport): Check {
        val dex = report.dex ?: return Check("DEX_XREF", "DEX xref consistency", Status.WARN, "Skipped because DEX is unavailable")
        if (dex.callXrefs.isEmpty() && dex.stringXrefs.isEmpty() && dex.fieldXrefs.isEmpty() && dex.typeXrefs.isEmpty()) {
            return Check("DEX_XREF", "DEX xref consistency", Status.WARN, "No xrefs were retained in the bounded index")
        }
        val knownMethods = dex.methods.asSequence().map { it.dexEntry to it.methodIndex }.toHashSet()
        val missingCallers = dex.callXrefs.count { (it.dexEntry to it.callerMethodIndex) !in knownMethods }
        val missingStringCallers = dex.stringXrefs.count { (it.dexEntry to it.callerMethodIndex) !in knownMethods }
        val missing = missingCallers + missingStringCallers
        return if (missing > 0) {
            Check("DEX_XREF", "DEX xref consistency", Status.WARN, "$missing retained xrefs reference caller methods outside the structural method index")
        } else {
            Check("DEX_XREF", "DEX xref consistency", Status.PASS, "Caller endpoints resolve for retained call/string xrefs")
        }
    }

    private fun callGraph(report: StaticAnalysisReport): Check {
        val dex = report.dex ?: return Check("CALL_GRAPH", "Call graph", Status.WARN, "Skipped because DEX is unavailable")
        val first = dex.callXrefs.firstOrNull() ?: return Check("CALL_GRAPH", "Call graph", Status.WARN, "No call edges were retained")
        val root = DexCallGraph.MethodKey(first.dexEntry, first.callerMethodIndex)
        val slice = runCatching { DexCallGraph.reachableSlice(dex, setOf(root), maxDepth = 2, maxNodes = 128) }
            .getOrElse { return Check("CALL_GRAPH", "Call graph", Status.FAIL, "Graph query failed: ${it.javaClass.simpleName}") }
        return if (slice.nodes.isEmpty()) {
            Check("CALL_GRAPH", "Call graph", Status.FAIL, "A retained call edge could not produce a graph root")
        } else {
            Check("CALL_GRAPH", "Call graph", Status.PASS, "Bounded graph query returned ${slice.nodes.size} nodes / ${slice.edges.size} edges")
        }
    }

    private fun deobfuscation(report: StaticAnalysisReport): Check {
        val result = runCatching { AnalystMappingEngine.generate(report, maxEntries = 2_000) }
            .getOrElse { return Check("DEOB", "Deobfuscation / analyst mapping", Status.FAIL, "Mapping generation failed: ${it.javaClass.simpleName}") }
        return Check(
            "DEOB", "Deobfuscation / analyst mapping", Status.PASS,
            "Score ${result.obfuscationScore}/100; mapped ${result.mappedSymbols}/${result.suspectedSymbols}; semantic ${result.semanticMappings}",
        )
    }

    private fun findings(report: StaticAnalysisReport): Check {
        val severeWithoutEvidence = report.findings.count {
            (it.severity.name == "CRITICAL" || it.severity.name == "HIGH") && it.evidence.isEmpty()
        }
        return if (severeWithoutEvidence > 0) {
            Check("FINDINGS", "Finding evidence", Status.WARN, "$severeWithoutEvidence Critical/High findings have no retained evidence items")
        } else {
            Check("FINDINGS", "Finding evidence", Status.PASS, "${report.findings.size} findings; severe findings have retained evidence")
        }
    }

    private fun nativeIndex(report: StaticAnalysisReport): Check {
        val native = report.native ?: return Check("NATIVE", "Native / JNI index", Status.WARN, "No native libraries were indexed")
        return when {
            native.librariesScanned > native.librariesDiscovered -> Check("NATIVE", "Native / JNI index", Status.FAIL, "Scanned library count exceeds discovered count")
            native.parseErrors > 0 -> Check("NATIVE", "Native / JNI index", Status.WARN, "${native.parseErrors} native parse errors; ${native.librariesScanned}/${native.librariesDiscovered} libraries scanned")
            else -> Check("NATIVE", "Native / JNI index", Status.PASS, "${native.librariesScanned}/${native.librariesDiscovered} libraries scanned; JNI bridges ${native.jniBridges.size}")
        }
    }

    private fun supplyChain(report: StaticAnalysisReport): Check {
        val supply = report.supplyChain ?: return Check("SBOM", "Supply-chain index", Status.WARN, "Supply-chain inventory is unavailable")
        return Check(
            "SBOM", "Supply-chain index", if (supply.truncated) Status.WARN else Status.PASS,
            "Components ${supply.components.size}; native dependencies ${supply.nativeDependencies.size}; advisory matches ${supply.vulnerabilities.size}",
        )
    }

    private fun coverage(report: StaticAnalysisReport): Check {
        val partial = buildList {
            if (report.artifact.truncatedArchiveScan) add("archive")
            if (report.dex?.truncated == true) add("DEX")
            if (report.native?.truncated == true) add("native")
            if (report.il2cpp?.truncated == true) add("IL2CPP")
            if (report.runtimeArtifacts?.flutter?.truncated == true) add("Flutter")
            if (report.runtimeArtifacts?.hermes?.truncated == true) add("Hermes")
            if (report.runtimeArtifacts?.unityMono?.truncated == true) add("Unity Mono")
            if (report.runtimeArtifacts?.unreal?.truncated == true) add("Unreal")
            if (report.supplyChain?.truncated == true) add("SBOM")
        }
        return if (partial.isEmpty()) {
            Check("COVERAGE", "Bounded-analysis coverage", Status.PASS, "No truncation flags are set in the stored report")
        } else {
            Check("COVERAGE", "Bounded-analysis coverage", Status.WARN, "Partial indexes: ${partial.joinToString()}")
        }
    }
}
