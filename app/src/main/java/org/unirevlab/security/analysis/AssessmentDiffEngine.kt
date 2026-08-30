package org.unirevlab.security.analysis

import java.security.MessageDigest
import org.unirevlab.security.model.*

object AssessmentDiffEngine {
    fun diff(before: StaticAnalysisReport, after: StaticAnalysisReport): AssessmentDiff {
        val items = mutableListOf<DiffItem>()
        val bm = before.manifest
        val am = after.manifest
        val packageName = am?.packageName ?: bm?.packageName ?: after.artifact.sourcePackageName ?: before.artifact.sourcePackageName

        if (bm != null && am != null) {
            compareScalar(items, "manifest", "minSdk", bm.minSdk?.toString(), am.minSdk?.toString())
            compareScalar(items, "manifest", "targetSdk", bm.targetSdk?.toString(), am.targetSdk?.toString())
            compareScalar(items, "manifest", "debuggable", bm.debuggable.toString(), am.debuggable.toString(), if (am.debuggable && !bm.debuggable) Severity.HIGH else null)
            compareScalar(items, "manifest", "allowBackup", bm.allowBackup.toString(), am.allowBackup.toString(), if (am.allowBackup && !bm.allowBackup) Severity.MEDIUM else null)
            compareScalar(items, "manifest", "usesCleartextTraffic", bm.usesCleartextTraffic.toString(), am.usesCleartextTraffic.toString(), if (am.usesCleartextTraffic && !bm.usesCleartextTraffic) Severity.HIGH else null)
            setDiff(items, "permission", bm.requestedPermissions, am.requestedPermissions, Severity.MEDIUM)
            setDiff(items, "dangerousPermission", bm.dangerousPermissions, am.dangerousPermissions, Severity.HIGH)
            setDiff(items, "exportedComponent", exportedKeys(bm), exportedKeys(am), Severity.HIGH)
            setDiff(items, "deepLink", deepLinkKeys(bm), deepLinkKeys(am), Severity.MEDIUM)
            setDiff(items, "signingScheme", bm.signingSchemes, am.signingSchemes, Severity.MEDIUM)
        }

        setDiff(items, "finding", findingKeys(before), findingKeys(after), Severity.MEDIUM)
        setDiff(items, "dependency", dependencyKeys(before), dependencyKeys(after), Severity.MEDIUM)
        setDiff(items, "dexClass", before.dex?.classes?.map { it.descriptor }.orEmpty(), after.dex?.classes?.map { it.descriptor }.orEmpty(), null)
        setDiff(items, "dexMethod", methodKeys(before), methodKeys(after), null)
        setDiff(items, "nativeLibrary", nativeLibraryKeys(before), nativeLibraryKeys(after), Severity.MEDIUM)
        setDiff(items, "nativeExport", nativeExportKeys(before), nativeExportKeys(after), null)
        val beforeFunctions = ghidraFunctionFingerprints(before)
        val afterFunctions = ghidraFunctionFingerprints(after)
        setDiff(items, "nativeFunction", beforeFunctions.keys, afterFunctions.keys, null)
        (beforeFunctions.keys intersect afterFunctions.keys).sorted().forEach { key ->
            val beforeFingerprint = beforeFunctions.getValue(key)
            val afterFingerprint = afterFunctions.getValue(key)
            if (beforeFingerprint != afterFingerprint) {
                items += DiffItem(
                    category = "nativeFunctionShape",
                    key = key,
                    change = "CHANGED",
                    before = beforeFingerprint,
                    after = afterFingerprint,
                    severityHint = null,
                )
            }
        }

        val signerChanged = bm != null && am != null && bm.signingCertificateSha256.toSet() != am.signingCertificateSha256.toSet()
        if (signerChanged) {
            items += DiffItem(
                category = "signing",
                key = "certificateSha256",
                change = "CHANGED",
                before = bm!!.signingCertificateSha256.sorted().joinToString(","),
                after = am!!.signingCertificateSha256.sorted().joinToString(","),
                severityHint = Severity.HIGH,
            )
        }

        return AssessmentDiff(
            packageName = packageName,
            fromVersion = bm?.versionName ?: before.artifact.displayName,
            toVersion = am?.versionName ?: after.artifact.displayName,
            signerChanged = signerChanged,
            items = items.sortedWith(compareBy<DiffItem>({ it.category }, { it.key }, { it.change })),
        )
    }

    private fun compareScalar(items: MutableList<DiffItem>, category: String, key: String, before: String?, after: String?, severity: Severity? = null) {
        if (before != after) items += DiffItem(category, key, "CHANGED", before, after, severity)
    }

    private fun setDiff(items: MutableList<DiffItem>, category: String, before: Collection<String>, after: Collection<String>, severity: Severity?) {
        val b = before.toSet(); val a = after.toSet()
        (a - b).sorted().forEach { items += DiffItem(category, it, "ADDED", null, it, severity) }
        (b - a).sorted().forEach { items += DiffItem(category, it, "REMOVED", it, null, null) }
    }

    private fun exportedKeys(m: ManifestSummary): List<String> = m.components.filter { it.exported }.map { "${it.kind}:${it.name}" }
    private fun deepLinkKeys(m: ManifestSummary): List<String> = m.deepLinks.map { d ->
        listOf(d.componentName, d.schemes.sorted().joinToString(","), d.hosts.sorted().joinToString(","), d.autoVerify.toString()).joinToString("|")
    }
    private fun findingKeys(r: StaticAnalysisReport): List<String> = r.findings.map { "${it.id}:${it.severity}" }
    private fun dependencyKeys(r: StaticAnalysisReport): List<String> = r.supplyChain?.components?.map { "${it.id}:${it.version ?: "?"}" }.orEmpty()
    private fun methodKeys(r: StaticAnalysisReport): List<String> = r.dex?.methods?.map { "${it.declaringClass}->${it.name}${it.prototype}" }.orEmpty()
    private fun nativeLibraryKeys(r: StaticAnalysisReport): List<String> = r.native?.libraries?.map { "${it.entryName}:${it.buildId ?: "?"}" }.orEmpty()
    private fun nativeExportKeys(r: StaticAnalysisReport): List<String> = r.native?.libraries?.flatMap { lib -> lib.exportedSymbols.map { "${lib.entryName}:${it.name}" } }.orEmpty()

    private fun ghidraFunctionFingerprints(report: StaticAnalysisReport): Map<String, String> = buildMap {
        report.ghidra.sortedBy { it.libraryEntry }.forEach { analysis ->
            val cfgByRva = analysis.cfg.associateBy { it.functionRva }
            val incoming = analysis.xrefs.groupingBy { it.toRva }.eachCount()
            val outgoing = analysis.xrefs.groupingBy { it.fromRva }.eachCount()
            analysis.functions.forEach { fn ->
                val key = ghidraFunctionKey(analysis.libraryEntry, fn)
                val previewDigest = fn.decompilerPreview?.takeIf { it.isNotBlank() }?.let(::sha256) ?: "-"
                val cfg = cfgByRva[fn.rva]
                put(
                    key,
                    "size=${fn.sizeBytes}|thunk=${fn.isThunk}|blocks=${cfg?.blocks?.size ?: 0}|edges=${cfg?.edges?.size ?: 0}|in=${incoming[fn.rva] ?: 0}|out=${outgoing[fn.rva] ?: 0}|decomp=$previewDigest",
                )
            }
        }
    }

    private fun ghidraFunctionKey(libraryEntry: String, fn: GhidraFunctionSummary): String {
        val library = libraryEntry.substringAfterLast('/')
        val autoNamed = fn.name.startsWith("FUN_") || fn.name.startsWith("LAB_") || fn.name.isBlank()
        return if (autoNamed) {
            "$library|rva=0x${fn.rva.toString(16)}"
        } else {
            "$library|${fn.namespace}|${fn.name}|${fn.signature}"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.trim().replace("\r\n", "\n").toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
