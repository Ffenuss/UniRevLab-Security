package org.unirevlab.security.analysis

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.StaticAnalysisReport

/** End-to-end inert analysis for a dumped global-metadata.dat + matching libil2cpp.so pair. */
object Il2CppPairAssessmentEngine {
    data class Result(
        val report: StaticAnalysisReport,
        val risk: Il2CppMonetizationRiskEngine.Result,
        val mapping: Il2CppSemanticMappingEngine.Result,
        val nativeEvidence: Il2CppNativeEvidenceEngine.Result,
        val moddingResistance: Il2CppModdingResistanceEngine.Result,
        val realDump: RealIl2CppDumpEngine.Result,
        val aggregateSha256: String,
        val warnings: List<String>,
    )

    fun analyze(
        metadataFile: File,
        libraryFile: File,
        projectName: String = "IL2CPP dump review",
        organization: String = "Local authorized assessment",
        dumpOutputDirectory: File = File(metadataFile.parentFile, "real-il2cpp-dump"),
    ): Result {
        val realDump = RealIl2CppDumpEngine.dump(metadataFile, libraryFile, dumpOutputDirectory)
        val pair = Il2CppScanner.scanPair(metadataFile, libraryFile)
        val aggregateSha = aggregateSha256(metadataFile, libraryFile)
        val report = StaticAnalysisReport(
            engineVersion = "${LocalArtifactInspector.ENGINE_VERSION}-il2cpp-pair",
            assessment = AssessmentScope(
                projectName = projectName.ifBlank { "IL2CPP dump review" },
                organization = organization.ifBlank { "Local authorized assessment" },
                purpose = "Defensive IL2CPP metadata and monetization attack-surface review",
                confirmsAuthority = true,
            ),
            artifact = ArtifactSummary(
                displayName = "${metadataFile.name} + ${libraryFile.name}",
                sizeBytes = metadataFile.length() + libraryFile.length(),
                sha256 = aggregateSha,
                archiveEntries = null,
                dexFiles = 0,
                nativeLibraries = 1,
                hasAndroidManifest = false,
                suspiciousArchivePaths = 0,
                truncatedArchiveScan = false,
                sourceKind = "IL2CPP_PAIR",
            ),
            manifest = null,
            native = pair.native,
            il2cpp = pair.il2cpp,
            findings = emptyList(),
        )
        val nativeEvidence = Il2CppNativeEvidenceEngine.analyze(report)
        val mapping = Il2CppSemanticMappingEngine.analyze(report)
        val risk = Il2CppMonetizationRiskEngine.analyze(report)
        val moddingResistance = Il2CppModdingResistanceEngine.analyze(report, risk, nativeEvidence)
        val warnings = buildList {
            if (pair.il2cpp.metadata?.magicValid != true) add("global-metadata.dat magic/version could not be validated.")
            if (!realDump.complete) add("Настоящий IL2CPP dump не создан: ${realDump.error ?: realDump.status}. Никакие офсеты не были выдуманы.")
            if (realDump.complete) add("Настоящий dump подтверждён ${realDump.engine}; registrations ${realDump.codeRegistration}/${realDump.metadataRegistration}.")
            if (pair.il2cpp.metadata?.reconstructionTruncated == true || pair.il2cpp.truncated) add("IL2CPP reconstruction is partial; absence of a candidate is not proof of absence.")
            if (pair.native.libraries.firstOrNull()?.stripped == true) add("libil2cpp.so is stripped; exact native symbol correlation is limited without an external symbol/Ghidra result.")
            if (pair.il2cpp.metadata?.metadataVersion !in 27..31) add("Structured type/method/field reconstruction is currently optimized for metadata versions 27-31.")
            if (mapping.likelyObfuscated) add("Managed metadata appears obfuscated (score ${mapping.obfuscationScore}/100); contextual aliases are analyst hypotheses, not recovered source names.")
            if (mapping.contextualMappings > 0) add("${mapping.contextualMappings} obfuscated symbols received contextual semantic aliases for review.")
            if (!nativeEvidence.correlationDataAvailable) add("Pair-only scan has no external Ghidra correlation dataset; native identity verification becomes available in the full APK audit.")
            if (nativeEvidence.conflicting > 0) add("${nativeEvidence.conflicting} IL2CPP method correlation(s) conflict with canonical metadata identity/token evidence and were not trusted.")
            if (moddingResistance.clientAuthoritative > 0) add("${moddingResistance.clientAuthoritative} monetization/entitlement target(s) appear client-authoritative and require trust-boundary remediation.")
            add("Pair matching is assumed from the supplied files unless independent build/provenance evidence is available.")
        }
        return Result(
            report = report,
            risk = risk,
            mapping = mapping,
            nativeEvidence = nativeEvidence,
            moddingResistance = moddingResistance,
            realDump = realDump,
            aggregateSha256 = aggregateSha,
            warnings = warnings,
        )
    }

    private fun aggregateSha256(metadataFile: File, libraryFile: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        updateDigest(digest, "global-metadata.dat", metadataFile)
        updateDigest(digest, "libil2cpp.so", libraryFile)
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun updateDigest(digest: MessageDigest, label: String, file: File) {
        digest.update(label.toByteArray(Charsets.UTF_8))
        digest.update(0.toByte())
        FileInputStream(file).buffered(128 * 1024).use { input ->
            val buffer = ByteArray(128 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
    }
}

