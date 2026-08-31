package org.unirevlab.security.analysis

import org.unirevlab.security.model.ComponentExposure
import org.unirevlab.security.model.CrossRuntimeCorrelationSummary
import org.unirevlab.security.model.DeclaredPermission
import org.unirevlab.security.model.DeepLinkDeclaration
import org.unirevlab.security.model.ProviderDeclaration
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.Il2CppMetadataSummary
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.DexTypeXref
import org.unirevlab.security.model.DexStringXref
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodCodeReference
import org.unirevlab.security.model.DexNativeMethodDeclaration
import org.unirevlab.security.model.DexFieldXref
import org.unirevlab.security.model.DexBasicBlock
import org.unirevlab.security.model.DexConstantReference
import org.unirevlab.security.model.RuntimeSummary
import org.unirevlab.security.model.RuntimeArtifactSummary
import org.unirevlab.security.model.RuntimeFileReference
import org.unirevlab.security.model.FlutterRuntimeSummary
import org.unirevlab.security.model.HermesRuntimeSummary
import org.unirevlab.security.model.HermesBytecodeSummary
import org.unirevlab.security.model.UnityMonoRuntimeSummary
import org.unirevlab.security.model.ManagedAssemblySummary
import org.unirevlab.security.model.UnrealRuntimeSummary
import org.unirevlab.security.model.UnrealContainerSummary
import org.unirevlab.security.model.DexInvokeObservation
import org.unirevlab.security.model.Il2CppTableRange
import org.unirevlab.security.model.Il2CppTypeDefinitionSummary
import org.unirevlab.security.model.Il2CppMethodDefinitionSummary
import org.unirevlab.security.model.Il2CppRegistrationCandidate
import org.unirevlab.security.model.DexStringReference
import org.unirevlab.security.model.SecretCandidate
import org.unirevlab.security.model.Evidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.GhidraLibraryAnalysis
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.ManifestDexReachabilitySummary
import org.unirevlab.security.model.JniBridgeReference
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.NetworkSecurityConfigSummary
import org.unirevlab.security.model.NativeSecretCandidate
import org.unirevlab.security.model.NativeSymbolReference
import org.unirevlab.security.model.SecurityReference
import org.unirevlab.security.model.StaticAnalysisReport
import org.unirevlab.security.model.SigningCertificateSummary
import org.unirevlab.security.model.SupplyChainSummary
import org.unirevlab.security.model.ResourceTableSummary

/** Deterministic JSON writer: stable field and list ordering make reports diff-friendly and reproducible. */
object ReportJsonExporter {
    private fun Appendable.append(value: Int): Appendable = append(value.toString())
    private fun Appendable.append(value: Long): Appendable = append(value.toString())
    private fun Appendable.append(value: Float): Appendable = append(value.toString())
    private fun Appendable.append(value: Double): Appendable = append(value.toString())
    private fun Appendable.append(value: Boolean): Appendable = append(value.toString())

    fun export(report: StaticAnalysisReport): String = buildString { appendReport(report) }

    /** Stream the deterministic report without materializing the whole JSON in memory. */
    fun write(report: StaticAnalysisReport, out: Appendable) {
        out.appendReport(report)
    }

    private fun Appendable.appendReport(report: StaticAnalysisReport) {
        append("{\n")
        field("schemaVersion", report.schemaVersion, 1, comma = true)
        field("engineVersion", report.engineVersion, 1, comma = true)
        append(indent(1)).append("\"assessment\": {\n")
        val scope = report.assessment
        field("assessmentId", scope.assessmentId, 2, true)
        numberField("createdAtEpochMs", scope.createdAtEpochMs, 2, true)
        field("projectName", scope.projectName, 2, true)
        field("organization", scope.organization, 2, true)
        field("purpose", scope.purpose, 2, true)
        booleanField("authorityConfirmed", scope.confirmsAuthority, 2, true)
        stringArrayField("modes", buildList {
            if (scope.staticAnalysis) add("static")
            if (scope.reverseEngineering) add("reverse")
            if (scope.dynamicAnalysis) add("dynamic")
            if (scope.networkTesting) add("network")
        }, 2, false)
        append(indent(1)).append("},\n")
        append(indent(1)).append("\"artifact\": {\n")
        val a = report.artifact
        field("displayName", a.displayName, 2, true)
        field("sourceKind", a.sourceKind, 2, true)
        nullableStringField("sourcePackageName", a.sourcePackageName, 2, true)
        nullableStringField("sourceInstallerPackageName", a.sourceInstallerPackageName, 2, true)
        numberField("splitApkCount", a.splitApkCount.toLong(), 2, true)
        numberField("sizeBytes", a.sizeBytes, 2, true)
        field("sha256", a.sha256, 2, true)
        numberField("archiveEntries", a.archiveEntries?.toLong(), 2, true)
        numberField("dexFiles", a.dexFiles?.toLong(), 2, true)
        numberField("nativeLibraries", a.nativeLibraries?.toLong(), 2, true)
        nullableBooleanField("hasAndroidManifest", a.hasAndroidManifest, 2, true)
        numberField("suspiciousArchivePaths", a.suspiciousArchivePaths?.toLong(), 2, true)
        booleanField("truncatedArchiveScan", a.truncatedArchiveScan, 2, false)
        append(indent(1)).append("},\n")
        append(indent(1)).append("\"manifest\": ")
        if (report.manifest == null) append("null") else appendManifest(report.manifest, 1)
        append(",\n")
        resources(report.resources, 1, true)
        append(indent(1)).append("\"dex\": ")
        if (report.dex == null) append("null") else appendDex(report.dex, 1)
        append(",\n")
        append(indent(1)).append("\"native\": ")
        if (report.native == null) append("null") else appendNative(report.native, 1)
        append(",\n")
        append(indent(1)).append("\"il2cpp\": ")
        if (report.il2cpp == null) append("null") else appendIl2Cpp(report.il2cpp, 1)
        append(",\n")
        ghidraAnalyses(report.ghidra, 1, true)
        correlations(report.correlations, 1, true)
        manifestDexReachability(report.manifestDexReachability, 1, true)
        runtimeSummary(report.runtimes, 1, true)
        runtimeArtifacts(report.runtimeArtifacts, 1, true)
        supplyChain(report.supplyChain, 1, true)
        append(indent(1)).append("\"findings\": [")
        if (report.findings.isNotEmpty()) append('\n')
        report.findings.forEachIndexed { index, finding ->
            appendFinding(finding, 2)
            if (index != report.findings.lastIndex) append(',')
            append('\n')
        }
        if (report.findings.isNotEmpty()) append(indent(1))
        append("]\n}")
    }

    private fun Appendable.manifestDexReachability(value: ManifestDexReachabilitySummary?, level: Int, comma: Boolean) {
        append(indent(level)).append("\"manifestDexReachability\": ")
        if (value == null) {
            append("null")
        } else {
            append("{\n")
            numberField("externallyAddressableComponents", value.externallyAddressableComponents.toLong(), level + 1, true)
            numberField("reachableMethods", value.reachableMethods.toLong(), level + 1, true)
            booleanField("truncated", value.truncated, level + 1, true)
            append(indent(level + 1)).append("\"components\": [")
            if (value.components.isNotEmpty()) append('\n')
            value.components.forEachIndexed { index, component ->
                append(indent(level + 2)).append("{\n")
                field("componentKind", component.componentKind, level + 3, true)
                field("componentName", component.componentName, level + 3, true)
                field("classDescriptor", component.classDescriptor, level + 3, true)
                booleanField("exported", component.exported, level + 3, true)
                booleanField("externallyAddressable", component.externallyAddressable, level + 3, true)
                booleanField("classPresent", component.classPresent, level + 3, true)
                numberArrayField("entryMethodIndexes", component.entryMethodIndexes, level + 3, true)
                numberArrayField("reachableMethodIndexes", component.reachableMethodIndexes, level + 3, true)
                numberField("reachableMethodCount", component.reachableMethodCount.toLong(), level + 3, true)
                numberField("maxDepthReached", component.maxDepthReached.toLong(), level + 3, true)
                booleanField("truncated", component.truncated, level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != value.components.lastIndex) append(',')
                append('\n')
            }
            if (value.components.isNotEmpty()) append(indent(level + 1))
            append("]\n")
            append(indent(level)).append('}')
        }
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.appendManifest(m: ManifestSummary, level: Int) {
        append("{\n")
        field("packageName", m.packageName, level + 1, true)
        nullableStringField("versionName", m.versionName, level + 1, true)
        numberField("versionCode", m.versionCode, level + 1, true)
        numberField("minSdk", m.minSdk?.toLong(), level + 1, true)
        numberField("targetSdk", m.targetSdk?.toLong(), level + 1, true)
        booleanField("debuggable", m.debuggable, level + 1, true)
        booleanField("allowBackup", m.allowBackup, level + 1, true)
        nullableBooleanField("fullBackupContentConfigured", m.fullBackupContentConfigured, level + 1, true)
        nullableBooleanField("dataExtractionRulesConfigured", m.dataExtractionRulesConfigured, level + 1, true)
        booleanField("usesCleartextTraffic", m.usesCleartextTraffic, level + 1, true)
        nullableBooleanField("networkSecurityConfigConfigured", m.networkSecurityConfigConfigured, level + 1, true)
        stringArrayField("requestedPermissions", m.requestedPermissions.sorted(), level + 1, true)
        stringArrayField("dangerousPermissions", m.dangerousPermissions.sorted(), level + 1, true)
        declaredPermissionsArray(m.declaredPermissions, level + 1, true)
        stringArrayField("signingCertificateSha256", m.signingCertificateSha256.sorted(), level + 1, true)
        signingCertificatesArray(m.signingCertificates, level + 1, true)
        stringArrayField("signingSchemes", m.signingSchemes.sorted(), level + 1, true)
        stringArrayField("signingBlockIds", m.signingBlockIds.sorted(), level + 1, true)
        stringArrayField("v1SignatureFiles", m.v1SignatureFiles.sorted(), level + 1, true)
        nullableStringField("signingParseError", m.signingParseError, level + 1, true)
        networkSecurity(m.networkSecurity, level + 1, true)
        append(indent(level + 1)).append("\"components\": [")
        if (m.components.isNotEmpty()) append('\n')
        m.components.sortedWith(compareBy<ComponentExposure>({ it.kind }, { it.name })).forEachIndexed { i, c ->
            append(indent(level + 2)).append("{\n")
            field("kind", c.kind, level + 3, true)
            field("name", c.name, level + 3, true)
            booleanField("exported", c.exported, level + 3, true)
            stringArrayField("permissions", c.permissions.sorted(), level + 3, false)
            append(indent(level + 2)).append('}')
            if (i != m.components.lastIndex) append(',')
            append('\n')
        }
        if (m.components.isNotEmpty()) append(indent(level + 1))
        append("],\n")
        deepLinksArray(m.deepLinks, level + 1, true)
        providersArray(m.providers, level + 1, false)
        append(indent(level)).append('}')
    }

    private fun Appendable.networkSecurity(value: NetworkSecurityConfigSummary?, level: Int, comma: Boolean) {
        append(indent(level)).append("\"networkSecurity\": ")
        if (value == null) {
            append("null")
        } else {
            append("{\n")
            nullableStringField("manifestReference", value.manifestReference, level + 1, true)
            nullableStringField("resolvedManifestEntry", value.resolvedManifestEntry, level + 1, true)
            stringArrayField("configEntries", value.configEntries.sorted(), level + 1, true)
            nullableBooleanField("baseCleartextTrafficPermitted", value.baseCleartextTrafficPermitted, level + 1, true)
            booleanField("debugOverridesPresent", value.debugOverridesPresent, level + 1, true)
            booleanField("pinSetPresent", value.pinSetPresent, level + 1, true)
            numberField("parseErrors", value.parseErrors.toLong(), level + 1, true)
            booleanField("truncated", value.truncated, level + 1, true)
            append(indent(level + 1)).append("\"domainConfigs\": [")
            if (value.domainConfigs.isNotEmpty()) append('\n')
            value.domainConfigs.forEachIndexed { index, domain ->
                append(indent(level + 2)).append("{\n")
                nullableBooleanField("cleartextTrafficPermitted", domain.cleartextTrafficPermitted, level + 3, true)
                booleanField("includeSubdomains", domain.includeSubdomains, level + 3, true)
                stringArrayField("domains", domain.domains.sorted(), level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != value.domainConfigs.lastIndex) append(',')
                append('\n')
            }
            if (value.domainConfigs.isNotEmpty()) append(indent(level + 1))
            append("],\n")
            append(indent(level + 1)).append("\"trustAnchors\": [")
            if (value.trustAnchors.isNotEmpty()) append('\n')
            value.trustAnchors.forEachIndexed { index, anchor ->
                append(indent(level + 2)).append("{\n")
                field("source", anchor.source, level + 3, true)
                booleanField("inDebugOverrides", anchor.inDebugOverrides, level + 3, true)
                nullableBooleanField("overridePins", anchor.overridePins, level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != value.trustAnchors.lastIndex) append(',')
                append('\n')
            }
            if (value.trustAnchors.isNotEmpty()) append(indent(level + 1))
            append("]\n")
            append(indent(level)).append('}')
        }
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.resources(value: ResourceTableSummary?, level: Int, comma: Boolean) {
        append(indent(level)).append("\"resources\": ")
        if (value == null) {
            append("null")
        } else {
            append("{\n")
            stringArrayField("packages", value.packages.sorted(), level + 1, true)
            numberField("parseErrors", value.parseErrors.toLong(), level + 1, true)
            booleanField("truncated", value.truncated, level + 1, true)
            append(indent(level + 1)).append("\"resolutions\": [")
            val ordered = value.resolutions.sortedBy { it.resourceId }
            if (ordered.isNotEmpty()) append('\n')
            ordered.forEachIndexed { index, item ->
                append(indent(level + 2)).append("{\n")
                numberField("resourceId", item.resourceId, level + 3, true)
                numberField("packageId", item.packageId.toLong(), level + 3, true)
                numberField("typeId", item.typeId.toLong(), level + 3, true)
                numberField("entryId", item.entryId.toLong(), level + 3, true)
                nullableStringField("packageName", item.packageName, level + 3, true)
                nullableStringField("typeName", item.typeName, level + 3, true)
                nullableStringField("entryName", item.entryName, level + 3, true)
                numberField("dataType", item.dataType.toLong(), level + 3, true)
                numberField("dataValue", item.dataValue, level + 3, true)
                nullableStringField("stringValue", item.stringValue, level + 3, true)
                nullableStringField("fileEntry", item.fileEntry, level + 3, true)
                booleanField("complex", item.complex, level + 3, true)
                numberField("parentResourceId", item.parentResourceId, level + 3, true)
                numberField("mapEntryCount", item.mapEntryCount.toLong(), level + 3, true)
                field("sourceArchive", item.sourceArchive, level + 3, true)
                nullableStringField("configurationSha256", item.configurationSha256, level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != ordered.lastIndex) append(',')
                append('\n')
            }
            if (ordered.isNotEmpty()) append(indent(level + 1))
            append("],\n")
            append(indent(level + 1)).append("\"referenceChains\": [")
            val chains = value.referenceChains.sortedBy { it.requestedResourceId }
            if (chains.isNotEmpty()) append('\n')
            chains.forEachIndexed { index, chain ->
                append(indent(level + 2)).append("{\n")
                numberField("requestedResourceId", chain.requestedResourceId, level + 3, true)
                numberField("terminalResourceId", chain.terminalResourceId, level + 3, true)
                nullableStringField("terminalFileEntry", chain.terminalFileEntry, level + 3, true)
                booleanField("cycleDetected", chain.cycleDetected, level + 3, true)
                booleanField("depthExceeded", chain.depthExceeded, level + 3, true)
                booleanField("unresolved", chain.unresolved, level + 3, true)
                booleanField("ambiguousVariant", chain.ambiguousVariant, level + 3, true)
                nullableStringField("sourceArchive", chain.sourceArchive, level + 3, true)
                nullableStringField("configurationSha256", chain.configurationSha256, level + 3, true)
                append(indent(level + 3)).append("\"hops\": [")
                if (chain.hops.isNotEmpty()) append('\n')
                chain.hops.forEachIndexed { hi, hop ->
                    append(indent(level + 4)).append("{\n")
                    numberField("resourceId", hop.resourceId, level + 5, true)
                    numberField("dataType", hop.dataType.toLong(), level + 5, true)
                    numberField("dataValue", hop.dataValue, level + 5, true)
                    nullableStringField("typeName", hop.typeName, level + 5, true)
                    nullableStringField("entryName", hop.entryName, level + 5, true)
                    nullableStringField("stringValue", hop.stringValue, level + 5, true)
                    nullableStringField("fileEntry", hop.fileEntry, level + 5, true)
                    nullableStringField("sourceArchive", hop.sourceArchive, level + 5, true)
                    nullableStringField("configurationSha256", hop.configurationSha256, level + 5, false)
                    append(indent(level + 4)).append('}')
                    if (hi != chain.hops.lastIndex) append(',')
                    append('\n')
                }
                if (chain.hops.isNotEmpty()) append(indent(level + 3))
                append("]\n")
                append(indent(level + 2)).append('}')
                if (index != chains.lastIndex) append(',')
                append('\n')
            }
            if (chains.isNotEmpty()) append(indent(level + 1))
            append("],\n")
            append(indent(level + 1)).append("\"sources\": [")
            val sources = value.sources.sortedBy { it.sourceArchive }
            if (sources.isNotEmpty()) append('\n')
            sources.forEachIndexed { index, source ->
                append(indent(level + 2)).append("{\n")
                field("sourceArchive", source.sourceArchive, level + 3, true)
                stringArrayField("packages", source.packages.sorted(), level + 3, true)
                numberField("resolutionCount", source.resolutionCount.toLong(), level + 3, true)
                numberField("configurationCount", source.configurationCount.toLong(), level + 3, true)
                numberField("parseErrors", source.parseErrors.toLong(), level + 3, true)
                booleanField("truncated", source.truncated, level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != sources.lastIndex) append(',')
                append('\n')
            }
            if (sources.isNotEmpty()) append(indent(level + 1))
            append("]\n")
            append(indent(level)).append('}')
        }
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.signingCertificatesArray(values: List<SigningCertificateSummary>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"signingCertificates\": [")
        val ordered = values.sortedWith(compareBy<SigningCertificateSummary>({ it.lineageIndex ?: Int.MAX_VALUE }, { it.sha256 }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { i, cert ->
            append(indent(level + 1)).append("{\n")
            field("sha256", cert.sha256, level + 2, true)
            nullableStringField("subjectDn", cert.subjectDn, level + 2, true)
            nullableStringField("issuerDn", cert.issuerDn, level + 2, true)
            nullableStringField("serialNumberHex", cert.serialNumberHex, level + 2, true)
            numberField("notBeforeEpochMs", cert.notBeforeEpochMs, level + 2, true)
            numberField("notAfterEpochMs", cert.notAfterEpochMs, level + 2, true)
            nullableStringField("signatureAlgorithm", cert.signatureAlgorithm, level + 2, true)
            nullableStringField("publicKeyAlgorithm", cert.publicKeyAlgorithm, level + 2, true)
            numberField("publicKeySizeBits", cert.publicKeySizeBits?.toLong(), level + 2, true)
            booleanField("currentSigner", cert.currentSigner, level + 2, true)
            numberField("lineageIndex", cert.lineageIndex?.toLong(), level + 2, false)
            append(indent(level + 1)).append('}')
            if (i != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.declaredPermissionsArray(values: List<DeclaredPermission>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"declaredPermissions\": [")
        val ordered = values.sortedBy { it.name }
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { i, permission ->
            append(indent(level + 1)).append("{\n")
            field("name", permission.name, level + 2, true)
            field("protectionLevel", permission.protectionLevel, level + 2, false)
            append(indent(level + 1)).append('}')
            if (i != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.deepLinksArray(values: List<DeepLinkDeclaration>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"deepLinks\": [")
        val ordered = values.sortedWith(compareBy({ it.componentName }, { it.schemes.joinToString() }, { it.hosts.joinToString() }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { i, link ->
            append(indent(level + 1)).append("{\n")
            field("componentName", link.componentName, level + 2, true)
            stringArrayField("schemes", link.schemes.sorted(), level + 2, true)
            stringArrayField("hosts", link.hosts.sorted(), level + 2, true)
            stringArrayField("ports", link.ports.sorted(), level + 2, true)
            stringArrayField("paths", link.paths.sorted(), level + 2, true)
            stringArrayField("pathPrefixes", link.pathPrefixes.sorted(), level + 2, true)
            stringArrayField("pathPatterns", link.pathPatterns.sorted(), level + 2, true)
            stringArrayField("mimeTypes", link.mimeTypes.sorted(), level + 2, true)
            booleanField("autoVerify", link.autoVerify, level + 2, true)
            booleanField("browsable", link.browsable, level + 2, true)
            booleanField("viewAction", link.viewAction, level + 2, false)
            append(indent(level + 1)).append('}')
            if (i != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.providersArray(values: List<ProviderDeclaration>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"providers\": [")
        val ordered = values.sortedBy { it.name }
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { i, provider ->
            append(indent(level + 1)).append("{\n")
            field("name", provider.name, level + 2, true)
            stringArrayField("authorities", provider.authorities.sorted(), level + 2, true)
            nullableBooleanField("exported", provider.exported, level + 2, true)
            booleanField("grantUriPermissions", provider.grantUriPermissions, level + 2, true)
            nullableStringField("readPermission", provider.readPermission, level + 2, true)
            nullableStringField("writePermission", provider.writePermission, level + 2, true)
            append(indent(level + 2)).append("\"pathPermissions\": [")
            if (provider.pathPermissions.isNotEmpty()) append('\n')
            provider.pathPermissions.forEachIndexed { pi, pp ->
                append(indent(level + 3)).append("{\n")
                nullableStringField("path", pp.path, level + 4, true)
                nullableStringField("pathPrefix", pp.pathPrefix, level + 4, true)
                nullableStringField("pathPattern", pp.pathPattern, level + 4, true)
                nullableStringField("readPermission", pp.readPermission, level + 4, true)
                nullableStringField("writePermission", pp.writePermission, level + 4, false)
                append(indent(level + 3)).append('}')
                if (pi != provider.pathPermissions.lastIndex) append(',')
                append('\n')
            }
            if (provider.pathPermissions.isNotEmpty()) append(indent(level + 2))
            append("]\n")
            append(indent(level + 1)).append('}')
            if (i != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.appendDex(d: DexSummary, level: Int) {
        append("{\n")
        numberField("dexFilesDiscovered", d.dexFilesDiscovered.toLong(), level + 1, true)
        numberField("dexFilesScanned", d.dexFilesScanned.toLong(), level + 1, true)
        numberField("stringsDeclared", d.stringsDeclared, level + 1, true)
        numberField("stringsScanned", d.stringsScanned, level + 1, true)
        numberField("typesDeclared", d.typesDeclared, level + 1, true)
        numberField("typesIndexed", d.typesIndexed, level + 1, true)
        numberField("classesDeclared", d.classesDeclared, level + 1, true)
        numberField("classesIndexed", d.classesIndexed, level + 1, true)
        numberField("methodsDeclared", d.methodsDeclared, level + 1, true)
        numberField("methodsIndexed", d.methodsIndexed, level + 1, true)
        numberField("parseErrors", d.parseErrors.toLong(), level + 1, true)
        booleanField("truncated", d.truncated, level + 1, true)
        dexClassesArray(d.classes, level + 1, true)
        dexMethodsArray("methods", d.methods, level + 1, true)
        dexNativeMethodsArray(d.nativeMethods, level + 1, true)
        dexCodeMethodsArray(d.codeMethods, level + 1, true)
        dexCallXrefsArray(d.callXrefs, level + 1, true)
        dexStringXrefsArray(d.stringXrefs, level + 1, true)
        dexTypeXrefsArray(d.typeXrefs, level + 1, true)
        dexFieldXrefsArray(d.fieldXrefs, level + 1, true)
        dexBasicBlocksArray(d.basicBlocks, level + 1, true)
        dexConstantsArray(d.constants, level + 1, true)
        dexInvokeObservationsArray(d.invokeObservations, level + 1, true)
        dexStringReferencesArray("httpUrls", d.httpUrls, level + 1, true)
        dexStringReferencesArray("httpsUrls", d.httpsUrls, level + 1, true)
        secretCandidatesArray(d.secretCandidates, level + 1, false)
        append(indent(level)).append('}')
    }


    private fun Appendable.dexClassesArray(values: List<DexClassReference>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"classes\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.descriptor }, { it.classIndex }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("classIndex", value.classIndex.toLong(), level + 2, true)
            field("descriptor", value.descriptor, level + 2, true)
            nullableStringField("superDescriptor", value.superDescriptor, level + 2, true)
            numberField("accessFlags", value.accessFlags, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.dexMethodsArray(name: String, values: List<DexMethodReference>, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.declaringClass }, { it.name }, { it.prototype }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("methodIndex", value.methodIndex.toLong(), level + 2, true)
            field("declaringClass", value.declaringClass, level + 2, true)
            field("name", value.name, level + 2, true)
            field("prototype", value.prototype, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.dexNativeMethodsArray(values: List<DexNativeMethodDeclaration>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"nativeMethods\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.declaringClass }, { it.name }, { it.prototype }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("methodIndex", value.methodIndex.toLong(), level + 2, true)
            field("declaringClass", value.declaringClass, level + 2, true)
            field("name", value.name, level + 2, true)
            field("prototype", value.prototype, level + 2, true)
            numberField("accessFlags", value.accessFlags, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.dexCodeMethodsArray(values: List<DexMethodCodeReference>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"codeMethods\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.declaringClass }, { it.name }, { it.prototype }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("methodIndex", value.methodIndex.toLong(), level + 2, true)
            field("declaringClass", value.declaringClass, level + 2, true)
            field("name", value.name, level + 2, true)
            field("prototype", value.prototype, level + 2, true)
            numberField("codeOffset", value.codeOffset, level + 2, true)
            numberField("registersSize", value.registersSize.toLong(), level + 2, true)
            numberField("insSize", value.insSize.toLong(), level + 2, true)
            numberField("outsSize", value.outsSize.toLong(), level + 2, true)
            numberField("triesSize", value.triesSize.toLong(), level + 2, true)
            numberField("instructionUnits", value.instructionUnits.toLong(), level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.dexCallXrefsArray(values: List<DexMethodCallXref>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"callXrefs\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.callerMethodIndex }, { it.instructionOffsetCodeUnits }, { it.calleeMethodIndex }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("callerMethodIndex", value.callerMethodIndex.toLong(), level + 2, true)
            field("callerClass", value.callerClass, level + 2, true)
            field("callerName", value.callerName, level + 2, true)
            numberField("calleeMethodIndex", value.calleeMethodIndex.toLong(), level + 2, true)
            field("calleeClass", value.calleeClass, level + 2, true)
            field("calleeName", value.calleeName, level + 2, true)
            field("calleePrototype", value.calleePrototype, level + 2, true)
            numberField("instructionOffsetCodeUnits", value.instructionOffsetCodeUnits.toLong(), level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.dexStringXrefsArray(values: List<DexStringXref>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"stringXrefs\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.callerMethodIndex }, { it.instructionOffsetCodeUnits }, { it.stringIndex }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("callerMethodIndex", value.callerMethodIndex.toLong(), level + 2, true)
            field("callerClass", value.callerClass, level + 2, true)
            field("callerName", value.callerName, level + 2, true)
            numberField("stringIndex", value.stringIndex.toLong(), level + 2, true)
            field("value", value.value, level + 2, true)
            numberField("instructionOffsetCodeUnits", value.instructionOffsetCodeUnits.toLong(), level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.dexTypeXrefsArray(values: List<DexTypeXref>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"typeXrefs\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.callerMethodIndex }, { it.instructionOffsetCodeUnits }, { it.typeIndex }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("callerMethodIndex", value.callerMethodIndex.toLong(), level + 2, true)
            field("callerClass", value.callerClass, level + 2, true)
            field("callerName", value.callerName, level + 2, true)
            numberField("typeIndex", value.typeIndex.toLong(), level + 2, true)
            field("descriptor", value.descriptor, level + 2, true)
            field("kind", value.kind, level + 2, true)
            numberField("instructionOffsetCodeUnits", value.instructionOffsetCodeUnits.toLong(), level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.dexStringReferencesArray(
        name: String,
        values: List<DexStringReference>,
        level: Int,
        comma: Boolean,
    ) {
        append(indent(level)).append('"').append(name).append("\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.stringIndex }, { it.value }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { i, ref ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", ref.dexEntry, level + 2, true)
            numberField("stringIndex", ref.stringIndex.toLong(), level + 2, true)
            field("value", ref.value, level + 2, false)
            append(indent(level + 1)).append('}')
            if (i != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.secretCandidatesArray(values: List<SecretCandidate>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"secretCandidates\": [")
        val ordered = values.sortedWith(compareBy({ it.kind }, { it.dexEntry }, { it.stringIndex }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { i, candidate ->
            append(indent(level + 1)).append("{\n")
            field("kind", candidate.kind, level + 2, true)
            field("dexEntry", candidate.dexEntry, level + 2, true)
            numberField("stringIndex", candidate.stringIndex.toLong(), level + 2, true)
            field("valueSha256", candidate.valueSha256, level + 2, true)
            field("redactedPreview", candidate.redactedPreview, level + 2, false)
            append(indent(level + 1)).append('}')
            if (i != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }


    private fun Appendable.dexFieldXrefsArray(values: List<DexFieldXref>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"fieldXrefs\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.callerMethodIndex }, { it.instructionOffsetCodeUnits }, { it.fieldIndex }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("callerMethodIndex", value.callerMethodIndex.toLong(), level + 2, true)
            field("callerClass", value.callerClass, level + 2, true)
            field("callerName", value.callerName, level + 2, true)
            numberField("fieldIndex", value.fieldIndex.toLong(), level + 2, true)
            field("declaringClass", value.declaringClass, level + 2, true)
            field("fieldName", value.fieldName, level + 2, true)
            field("fieldType", value.fieldType, level + 2, true)
            field("kind", value.kind, level + 2, true)
            numberField("instructionOffsetCodeUnits", value.instructionOffsetCodeUnits.toLong(), level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.dexBasicBlocksArray(values: List<DexBasicBlock>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"basicBlocks\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.methodIndex }, { it.startCodeUnit }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("methodIndex", value.methodIndex.toLong(), level + 2, true)
            numberField("blockIndex", value.blockIndex.toLong(), level + 2, true)
            numberField("startCodeUnit", value.startCodeUnit.toLong(), level + 2, true)
            numberField("endCodeUnitExclusive", value.endCodeUnitExclusive.toLong(), level + 2, true)
            numberArrayField("successorCodeUnits", value.successorCodeUnits, level + 2, true)
            field("terminalKind", value.terminalKind, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.dexConstantsArray(values: List<DexConstantReference>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"constants\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.methodIndex }, { it.instructionOffsetCodeUnits }, { it.register }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("methodIndex", value.methodIndex.toLong(), level + 2, true)
            numberField("register", value.register.toLong(), level + 2, true)
            field("kind", value.kind, level + 2, true)
            field("value", value.value, level + 2, true)
            numberField("instructionOffsetCodeUnits", value.instructionOffsetCodeUnits.toLong(), level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.dexInvokeObservationsArray(values: List<DexInvokeObservation>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"invokeObservations\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.callerMethodIndex }, { it.instructionOffsetCodeUnits }, { it.calleeMethodIndex }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            numberField("callerMethodIndex", value.callerMethodIndex.toLong(), level + 2, true)
            field("callerClass", value.callerClass, level + 2, true)
            field("callerName", value.callerName, level + 2, true)
            numberField("calleeMethodIndex", value.calleeMethodIndex.toLong(), level + 2, true)
            field("calleeClass", value.calleeClass, level + 2, true)
            field("calleeName", value.calleeName, level + 2, true)
            field("calleePrototype", value.calleePrototype, level + 2, true)
            numberField("instructionOffsetCodeUnits", value.instructionOffsetCodeUnits.toLong(), level + 2, true)
            append(indent(level + 2)).append("\"arguments\": [")
            val args = value.arguments.sortedBy { it.argumentIndex }
            if (args.isNotEmpty()) append('\n')
            args.forEachIndexed { argIndex, arg ->
                append(indent(level + 3)).append("{\n")
                numberField("argumentIndex", arg.argumentIndex.toLong(), level + 4, true)
                numberField("register", arg.register.toLong(), level + 4, true)
                field("kind", arg.kind, level + 4, true)
                field("value", arg.value, level + 4, false)
                append(indent(level + 3)).append('}')
                if (argIndex != args.lastIndex) append(',')
                append('\n')
            }
            if (args.isNotEmpty()) append(indent(level + 2))
            append("]\n")
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.runtimeSummary(value: RuntimeSummary?, level: Int, comma: Boolean) {
        append(indent(level)).append("\"runtimes\": ")
        if (value == null) append("null") else {
            append("{\n")
            append(indent(level + 1)).append("\"profiles\": [")
            val ordered = value.profiles.sortedBy { it.kind }
            if (ordered.isNotEmpty()) append('\n')
            ordered.forEachIndexed { index, profile ->
                append(indent(level + 2)).append("{\n")
                field("kind", profile.kind, level + 3, true)
                field("confidence", profile.confidence, level + 3, true)
                stringArrayField("indicators", profile.indicators.sorted(), level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != ordered.lastIndex) append(',')
                append('\n')
            }
            if (ordered.isNotEmpty()) append(indent(level + 1))
            append("]\n").append(indent(level)).append('}')
        }
        if (comma) append(',')
        append('\n')
    }


    private fun Appendable.runtimeArtifacts(value: RuntimeArtifactSummary?, level: Int, comma: Boolean) {
        append(indent(level)).append("\"runtimeArtifacts\": ")
        if (value == null) append("null") else {
            append("{\n")
            append(indent(level + 1)).append("\"flutter\": ")
            if (value.flutter == null) append("null") else appendFlutter(value.flutter, level + 1)
            append(",\n")
            append(indent(level + 1)).append("\"hermes\": ")
            if (value.hermes == null) append("null") else appendHermes(value.hermes, level + 1)
            append(",\n")
            append(indent(level + 1)).append("\"unityMono\": ")
            if (value.unityMono == null) append("null") else appendUnityMono(value.unityMono, level + 1)
            append(",\n")
            append(indent(level + 1)).append("\"unreal\": ")
            if (value.unreal == null) append("null") else appendUnreal(value.unreal, level + 1)
            append('\n').append(indent(level)).append('}')
        }
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.appendFlutter(value: FlutterRuntimeSummary, level: Int) {
        append("{\n")
        booleanField("detected", value.detected, level + 1, true)
        field("confidence", value.confidence, level + 1, true)
        stringArrayField("flutterLibraries", value.flutterLibraries.sorted(), level + 1, true)
        stringArrayField("appLibraries", value.appLibraries.sorted(), level + 1, true)
        stringArrayField("engineBuildIds", value.engineBuildIds.sorted(), level + 1, true)
        numberField("assetCount", value.assetCount.toLong(), level + 1, true)
        runtimeFilesArray("representativeAssets", value.representativeAssets, level + 1, true)
        stringArrayField("manifestEntries", value.manifestEntries.sorted(), level + 1, true)
        stringArrayField("snapshotEntries", value.snapshotEntries.sorted(), level + 1, true)
        stringArrayField("kernelBlobEntries", value.kernelBlobEntries.sorted(), level + 1, true)
        booleanField("aotLikely", value.aotLikely, level + 1, true)
        append(indent(level + 1)).append("\"artifactFingerprints\": [")
        val fps = value.artifactFingerprints.sortedBy { it.entryName }
        if (fps.isNotEmpty()) append('\n')
        fps.forEachIndexed { index, fp ->
            append(indent(level + 2)).append("{\n")
            field("entryName", fp.entryName, level + 3, true)
            field("kind", fp.kind, level + 3, true)
            numberField("sizeBytes", fp.sizeBytes, level + 3, true)
            field("sha256", fp.sha256, level + 3, false)
            append(indent(level + 2)).append('}')
            if (index != fps.lastIndex) append(',')
            append('\n')
        }
        if (fps.isNotEmpty()) append(indent(level + 1))
        append("],\n")
        booleanField("truncated", value.truncated, level + 1, false)
        append(indent(level)).append('}')
    }

    private fun Appendable.appendHermes(value: HermesRuntimeSummary, level: Int) {
        append("{\n")
        booleanField("detected", value.detected, level + 1, true)
        field("confidence", value.confidence, level + 1, true)
        stringArrayField("hermesLibraries", value.hermesLibraries.sorted(), level + 1, true)
        append(indent(level + 1)).append("\"bytecodeFiles\": [")
        val hbc = value.bytecodeFiles.sortedBy { it.entryName }
        if (hbc.isNotEmpty()) append('\n')
        hbc.forEachIndexed { index, item ->
            appendHermesBytecode(item, level + 2)
            if (index != hbc.lastIndex) append(',')
            append('\n')
        }
        if (hbc.isNotEmpty()) append(indent(level + 1))
        append("],\n")
        runtimeFilesArray("javascriptBundles", value.javascriptBundles, level + 1, true)
        booleanField("truncated", value.truncated, level + 1, false)
        append(indent(level)).append('}')
    }

    private fun Appendable.appendHermesBytecode(value: HermesBytecodeSummary, level: Int) {
        append(indent(level)).append("{\n")
        field("entryName", value.entryName, level + 1, true)
        numberField("sizeBytes", value.sizeBytes, level + 1, true)
        booleanField("magicValid", value.magicValid, level + 1, true)
        numberField("bytecodeVersion", value.bytecodeVersion?.toLong(), level + 1, true)
        numberField("declaredFileLength", value.declaredFileLength, level + 1, true)
        numberField("globalCodeIndex", value.globalCodeIndex, level + 1, true)
        numberField("functionCount", value.functionCount, level + 1, true)
        numberField("stringKindCount", value.stringKindCount, level + 1, true)
        numberField("identifierCount", value.identifierCount, level + 1, true)
        numberField("stringCount", value.stringCount, level + 1, true)
        numberField("overflowStringCount", value.overflowStringCount, level + 1, true)
        numberField("stringStorageSize", value.stringStorageSize, level + 1, true)
        numberField("bigIntCount", value.bigIntCount, level + 1, true)
        numberField("regExpCount", value.regExpCount, level + 1, true)
        numberField("literalValueBufferSize", value.literalValueBufferSize, level + 1, true)
        numberField("objKeyBufferSize", value.objKeyBufferSize, level + 1, true)
        numberField("objShapeTableCount", value.objShapeTableCount, level + 1, true)
        numberField("segmentId", value.segmentId, level + 1, true)
        numberField("cjsModuleCount", value.cjsModuleCount, level + 1, true)
        numberField("functionSourceCount", value.functionSourceCount, level + 1, true)
        numberField("debugInfoOffset", value.debugInfoOffset, level + 1, true)
        nullableBooleanField("staticBuiltins", value.staticBuiltins, level + 1, true)
        numberField("structuredPrefixBytes", value.structuredPrefixBytes, level + 1, true)
        numberField("functionsScanned", value.functionsScanned.toLong(), level + 1, true)
        append(indent(level + 1)).append("\"functions\": [")
        val functions = value.functions.sortedBy { it.index }
        if (functions.isNotEmpty()) append('\n')
        functions.forEachIndexed { index, fn ->
            append(indent(level + 2)).append("{\n")
            numberField("index", fn.index.toLong(), level + 3, true)
            numberField("bytecodeOffset", fn.bytecodeOffset, level + 3, true)
            numberField("bytecodeSizeBytes", fn.bytecodeSizeBytes, level + 3, true)
            numberField("parameterCount", fn.parameterCount?.toLong(), level + 3, true)
            numberField("loopDepth", fn.loopDepth?.toLong(), level + 3, true)
            numberField("functionNameId", fn.functionNameId?.toLong(), level + 3, true)
            numberField("frameSize", fn.frameSize?.toLong(), level + 3, true)
            nullableBooleanField("strictMode", fn.strictMode, level + 3, true)
            nullableBooleanField("hasExceptionHandler", fn.hasExceptionHandler, level + 3, true)
            nullableBooleanField("hasDebugInfo", fn.hasDebugInfo, level + 3, true)
            booleanField("overflowed", fn.overflowed, level + 3, true)
            numberField("largeHeaderOffset", fn.largeHeaderOffset, level + 3, false)
            append(indent(level + 2)).append('}')
            if (index != functions.lastIndex) append(',')
            append('\n')
        }
        if (functions.isNotEmpty()) append(indent(level + 1))
        append("],\n")
        nullableStringField("sourceHashSha1", value.sourceHashSha1, level + 1, true)
        nullableStringField("parseError", value.parseError, level + 1, true)
        booleanField("truncated", value.truncated, level + 1, false)
        append(indent(level)).append('}')
    }

    private fun Appendable.appendUnityMono(value: UnityMonoRuntimeSummary, level: Int) {
        append("{\n")
        booleanField("detected", value.detected, level + 1, true)
        field("confidence", value.confidence, level + 1, true)
        stringArrayField("monoLibraries", value.monoLibraries.sorted(), level + 1, true)
        stringArrayField("unityLibraries", value.unityLibraries.sorted(), level + 1, true)
        append(indent(level + 1)).append("\"assemblies\": [")
        val assemblies = value.assemblies.sortedBy { it.entryName }
        if (assemblies.isNotEmpty()) append('\n')
        assemblies.forEachIndexed { index, item ->
            appendManagedAssembly(item, level + 2)
            if (index != assemblies.lastIndex) append(',')
            append('\n')
        }
        if (assemblies.isNotEmpty()) append(indent(level + 1))
        append("],\n")
        booleanField("truncated", value.truncated, level + 1, false)
        append(indent(level)).append('}')
    }

    private fun Appendable.appendManagedAssembly(value: ManagedAssemblySummary, level: Int) {
        append(indent(level)).append("{\n")
        field("entryName", value.entryName, level + 1, true)
        numberField("sizeBytes", value.sizeBytes, level + 1, true)
        booleanField("peValid", value.peValid, level + 1, true)
        booleanField("cliMetadataPresent", value.cliMetadataPresent, level + 1, true)
        nullableStringField("metadataVersion", value.metadataVersion, level + 1, true)
        nullableStringField("assemblyName", value.assemblyName, level + 1, true)
        nullableStringField("assemblyVersion", value.assemblyVersion, level + 1, true)
        stringArrayField("nameCandidates", value.nameCandidates.sorted(), level + 1, true)
        append(indent(level + 1)).append("\"metadataStreams\": [")
        if (value.metadataStreams.isNotEmpty()) append('\n')
        value.metadataStreams.sortedBy { it.name }.forEachIndexed { index, item ->
            append(indent(level + 2)).append("{\n")
            field("name", item.name, level + 3, true)
            numberField("offset", item.offset, level + 3, true)
            numberField("sizeBytes", item.sizeBytes, level + 3, false)
            append(indent(level + 2)).append('}')
            if (index != value.metadataStreams.lastIndex) append(',')
            append('\n')
        }
        if (value.metadataStreams.isNotEmpty()) append(indent(level + 1))
        append("],\n")
        append(indent(level + 1)).append("\"metadataTables\": [")
        if (value.metadataTables.isNotEmpty()) append('\n')
        value.metadataTables.sortedBy { it.tableId }.forEachIndexed { index, item ->
            append(indent(level + 2)).append("{\n")
            numberField("tableId", item.tableId.toLong(), level + 3, true)
            field("name", item.name, level + 3, true)
            numberField("rowCount", item.rowCount, level + 3, false)
            append(indent(level + 2)).append('}')
            if (index != value.metadataTables.lastIndex) append(',')
            append('\n')
        }
        if (value.metadataTables.isNotEmpty()) append(indent(level + 1))
        append("],\n")
        append(indent(level + 1)).append("\"typeReferences\": [")
        if (value.typeReferences.isNotEmpty()) append('\n')
        value.typeReferences.sortedBy { it.index }.forEachIndexed { index, item ->
            append(indent(level + 2)).append("{\n")
            numberField("index", item.index.toLong(), level + 3, true)
            field("namespace", item.namespace, level + 3, true)
            field("name", item.name, level + 3, true)
            field("fullName", item.fullName, level + 3, true)
            numberField("resolutionScopeToken", item.resolutionScopeToken, level + 3, false)
            append(indent(level + 2)).append('}'); if (index != value.typeReferences.lastIndex) append(','); append('\n')
        }
        if (value.typeReferences.isNotEmpty()) append(indent(level + 1)); append("],\n")
        append(indent(level + 1)).append("\"typeDefinitions\": [")
        if (value.typeDefinitions.isNotEmpty()) append('\n')
        value.typeDefinitions.sortedBy { it.index }.forEachIndexed { index, item ->
            append(indent(level + 2)).append("{\n")
            numberField("index", item.index.toLong(), level + 3, true); field("namespace", item.namespace, level + 3, true)
            field("name", item.name, level + 3, true); field("fullName", item.fullName, level + 3, true)
            numberField("flags", item.flags, level + 3, true); numberField("extendsToken", item.extendsToken, level + 3, true)
            numberField("fieldStart", item.fieldStart.toLong(), level + 3, true); numberField("fieldCount", item.fieldCount.toLong(), level + 3, true)
            numberField("methodStart", item.methodStart.toLong(), level + 3, true); numberField("methodCount", item.methodCount.toLong(), level + 3, false)
            append(indent(level + 2)).append('}'); if (index != value.typeDefinitions.lastIndex) append(','); append('\n')
        }
        if (value.typeDefinitions.isNotEmpty()) append(indent(level + 1)); append("],\n")
        append(indent(level + 1)).append("\"methodDefinitions\": [")
        if (value.methodDefinitions.isNotEmpty()) append('\n')
        value.methodDefinitions.sortedBy { it.index }.forEachIndexed { index, item ->
            append(indent(level + 2)).append("{\n")
            numberField("index", item.index.toLong(), level + 3, true); field("declaringType", item.declaringType, level + 3, true)
            numberField("rva", item.rva, level + 3, true); numberField("implFlags", item.implFlags.toLong(), level + 3, true)
            numberField("flags", item.flags.toLong(), level + 3, true); field("name", item.name, level + 3, true)
            numberField("signatureBlobIndex", item.signatureBlobIndex, level + 3, true); numberField("paramStart", item.paramStart.toLong(), level + 3, false)
            append(indent(level + 2)).append('}'); if (index != value.methodDefinitions.lastIndex) append(','); append('\n')
        }
        if (value.methodDefinitions.isNotEmpty()) append(indent(level + 1)); append("],\n")
        append(indent(level + 1)).append("\"memberReferences\": [")
        if (value.memberReferences.isNotEmpty()) append('\n')
        value.memberReferences.sortedBy { it.index }.forEachIndexed { index, item ->
            append(indent(level + 2)).append("{\n")
            numberField("index", item.index.toLong(), level + 3, true); numberField("parentToken", item.parentToken, level + 3, true)
            field("name", item.name, level + 3, true); numberField("signatureBlobIndex", item.signatureBlobIndex, level + 3, false)
            append(indent(level + 2)).append('}'); if (index != value.memberReferences.lastIndex) append(','); append('\n')
        }
        if (value.memberReferences.isNotEmpty()) append(indent(level + 1)); append("],\n")
        append(indent(level + 1)).append("\"assemblyReferences\": [")
        if (value.assemblyReferences.isNotEmpty()) append('\n')
        value.assemblyReferences.sortedBy { it.index }.forEachIndexed { index, item ->
            append(indent(level + 2)).append("{\n")
            numberField("index", item.index.toLong(), level + 3, true); field("name", item.name, level + 3, true)
            field("version", item.version, level + 3, true); nullableStringField("culture", item.culture, level + 3, true)
            numberField("flags", item.flags, level + 3, false)
            append(indent(level + 2)).append('}'); if (index != value.assemblyReferences.lastIndex) append(','); append('\n')
        }
        if (value.assemblyReferences.isNotEmpty()) append(indent(level + 1)); append("],\n")
        booleanField("reconstructionTruncated", value.reconstructionTruncated, level + 1, true)
        nullableStringField("parseError", value.parseError, level + 1, true)
        booleanField("truncated", value.truncated, level + 1, false)
        append(indent(level)).append('}')
    }

    private fun Appendable.appendUnreal(value: UnrealRuntimeSummary, level: Int) {
        append("{\n")
        booleanField("detected", value.detected, level + 1, true)
        field("confidence", value.confidence, level + 1, true)
        stringArrayField("engineLibraries", value.engineLibraries.sorted(), level + 1, true)
        append(indent(level + 1)).append("\"containers\": [")
        val containers = value.containers.sortedWith(compareBy({ it.kind }, { it.entryName }))
        if (containers.isNotEmpty()) append('\n')
        containers.forEachIndexed { index, item ->
            append(indent(level + 2)).append("{\n")
            field("entryName", item.entryName, level + 3, true)
            field("kind", item.kind, level + 3, true)
            numberField("sizeBytes", item.sizeBytes, level + 3, true)
            nullableStringField("probeSha256", item.probeSha256, level + 3, true)
            numberField("probeBytes", item.probeBytes.toLong(), level + 3, false)
            append(indent(level + 2)).append('}')
            if (index != containers.lastIndex) append(',')
            append('\n')
        }
        if (containers.isNotEmpty()) append(indent(level + 1))
        append("],\n")
        runtimeFilesArray("obbEntries", value.obbEntries, level + 1, true)
        stringArrayField("commandLineEntries", value.commandLineEntries.sorted(), level + 1, true)
        booleanField("truncated", value.truncated, level + 1, false)
        append(indent(level)).append('}')
    }

    private fun Appendable.runtimeFilesArray(name: String, values: List<RuntimeFileReference>, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": [")
        val ordered = values.sortedBy { it.entryName }
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, item ->
            append(indent(level + 1)).append("{\n")
            field("entryName", item.entryName, level + 2, true)
            numberField("sizeBytes", item.sizeBytes, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.supplyChain(value: SupplyChainSummary?, level: Int, comma: Boolean) {
        append(indent(level)).append("\"supplyChain\": ")
        if (value == null) append("null") else {
            append("{\n")
            append(indent(level + 1)).append("\"components\": [")
            val components = value.components.sortedBy { it.id }
            if (components.isNotEmpty()) append('\n')
            components.forEachIndexed { index, item ->
                append(indent(level + 2)).append("{\n")
                field("id", item.id, level + 3, true)
                field("name", item.name, level + 3, true)
                field("ecosystem", item.ecosystem, level + 3, true)
                nullableStringField("version", item.version, level + 3, true)
                nullableStringField("purl", item.purl, level + 3, true)
                field("confidence", item.confidence, level + 3, true)
                nullableStringField("versionEvidence", item.versionEvidence, level + 3, true)
                stringArrayField("evidence", item.evidence.sorted(), level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != components.lastIndex) append(',')
                append('\n')
            }
            if (components.isNotEmpty()) append(indent(level + 1))
            append("],\n")
            stringArrayField("nativeDependencies", value.nativeDependencies.sorted(), level + 1, true)
            append(indent(level + 1)).append("\"advisoryFeed\": ")
            if (value.advisoryFeed == null) {
                append("null,\n")
            } else {
                append("{\n")
                field("schemaVersion", value.advisoryFeed.schemaVersion, level + 2, true)
                field("feedId", value.advisoryFeed.feedId, level + 2, true)
                field("source", value.advisoryFeed.source, level + 2, true)
                field("generatedAt", value.advisoryFeed.generatedAt, level + 2, true)
                field("sha256", value.advisoryFeed.sha256, level + 2, true)
                numberField("advisoryCount", value.advisoryFeed.advisoryCount.toLong(), level + 2, true)
                field("format", value.advisoryFeed.format, level + 2, true)
                nullableStringField("adapterVersion", value.advisoryFeed.adapterVersion, level + 2, true)
                numberField("skippedAdvisoryCount", value.advisoryFeed.skippedAdvisoryCount.toLong(), level + 2, true)
                booleanField("signatureVerified", value.advisoryFeed.signatureVerified, level + 2, true)
                nullableStringField("signingKeyId", value.advisoryFeed.signingKeyId, level + 2, true)
                nullableStringField("signatureAlgorithm", value.advisoryFeed.signatureAlgorithm, level + 2, true)
                nullableStringField("envelopeSha256", value.advisoryFeed.envelopeSha256, level + 2, false)
                append(indent(level + 1)).append("},\n")
            }
            append(indent(level + 1)).append("\"vulnerabilities\": [")
            val vulnerabilities = value.vulnerabilities.sortedWith(compareBy({ it.componentId }, { it.componentVersion }, { it.advisoryId }))
            if (vulnerabilities.isNotEmpty()) append('\n')
            vulnerabilities.forEachIndexed { index, item ->
                append(indent(level + 2)).append("{\n")
                field("advisoryId", item.advisoryId, level + 3, true)
                stringArrayField("aliases", item.aliases.sorted(), level + 3, true)
                field("componentId", item.componentId, level + 3, true)
                field("componentVersion", item.componentVersion, level + 3, true)
                field("severity", item.severity, level + 3, true)
                field("summary", item.summary, level + 3, true)
                field("source", item.source, level + 3, true)
                field("matchBasis", item.matchBasis, level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != vulnerabilities.lastIndex) append(',')
                append('\n')
            }
            if (vulnerabilities.isNotEmpty()) append(indent(level + 1))
            append("],\n")
            booleanField("truncated", value.truncated, level + 1, false)
            append(indent(level)).append('}')
        }
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.numberArrayField(name: String, values: List<Int>, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": [")
        values.forEachIndexed { index, value -> if (index > 0) append(", "); append(value) }
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.longArrayField(name: String, values: List<Long>, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": [")
        values.forEachIndexed { index, value -> if (index > 0) append(", "); append(value) }
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.ghidraAnalyses(values: List<GhidraLibraryAnalysis>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"ghidra\": [")
        val ordered = values.sortedBy { it.libraryEntry }
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("schemaVersion", value.schemaVersion, level + 2, true)
            field("assessmentId", value.assessmentId, level + 2, true)
            field("artifactSha256", value.artifactSha256, level + 2, true)
            field("libraryEntry", value.libraryEntry, level + 2, true)
            field("status", value.status, level + 2, true)

            append(indent(level + 2)).append("\"engine\": {\n")
            field("name", value.engine.name, level + 3, true)
            field("version", value.engine.version, level + 3, true)
            booleanField("pyGhidra", value.engine.pyGhidra, level + 3, true)
            field("analysisProfile", value.engine.analysisProfile, level + 3, false)
            append(indent(level + 2)).append("},\n")

            append(indent(level + 2)).append("\"architecture\": ")
            if (value.architecture == null) {
                append("null,\n")
            } else {
                append("{\n")
                field("processor", value.architecture.processor, level + 3, true)
                numberField("pointerSize", value.architecture.pointerSize.toLong(), level + 3, true)
                field("endian", value.architecture.endian, level + 3, false)
                append(indent(level + 2)).append("},\n")
            }

            append(indent(level + 2)).append("\"coverage\": {\n")
            numberField("functionsDiscovered", value.coverage.functionsDiscovered.toLong(), level + 3, true)
            numberField("functionsReported", value.coverage.functionsReported.toLong(), level + 3, true)
            numberField("cfgBlocksReported", value.coverage.cfgBlocksReported.toLong(), level + 3, true)
            numberField("xrefsReported", value.coverage.xrefsReported.toLong(), level + 3, true)
            numberField("decompilerFunctionsReported", value.coverage.decompilerFunctionsReported.toLong(), level + 3, true)
            booleanField("truncated", value.coverage.truncated, level + 3, false)
            append(indent(level + 2)).append("},\n")

            append(indent(level + 2)).append("\"functions\": [")
            val functions = value.functions.sortedWith(compareBy({ it.rva }, { it.name }))
            if (functions.isNotEmpty()) append('\n')
            functions.forEachIndexed { i, fn ->
                append(indent(level + 3)).append("{\n")
                numberField("rva", fn.rva, level + 4, true)
                field("name", fn.name, level + 4, true)
                field("namespace", fn.namespace, level + 4, true)
                field("signature", fn.signature, level + 4, true)
                numberField("sizeBytes", fn.sizeBytes, level + 4, true)
                booleanField("isThunk", fn.isThunk, level + 4, true)
                nullableStringField("decompilerPreview", fn.decompilerPreview, level + 4, false)
                append(indent(level + 3)).append('}')
                if (i != functions.lastIndex) append(',')
                append('\n')
            }
            if (functions.isNotEmpty()) append(indent(level + 2))
            append("],\n")

            append(indent(level + 2)).append("\"cfg\": [")
            val cfg = value.cfg.sortedBy { it.functionRva }
            if (cfg.isNotEmpty()) append('\n')
            cfg.forEachIndexed { i, graph ->
                append(indent(level + 3)).append("{\n")
                numberField("functionRva", graph.functionRva, level + 4, true)
                append(indent(level + 4)).append("\"blocks\": [")
                val blocks = graph.blocks.sortedBy { it.startRva }
                if (blocks.isNotEmpty()) append('\n')
                blocks.forEachIndexed { bi, block ->
                    append(indent(level + 5)).append("{\n")
                    numberField("startRva", block.startRva, level + 6, true)
                    numberField("endRva", block.endRva, level + 6, true)
                    field("flowType", block.flowType, level + 6, false)
                    append(indent(level + 5)).append('}')
                    if (bi != blocks.lastIndex) append(',')
                    append('\n')
                }
                if (blocks.isNotEmpty()) append(indent(level + 4))
                append("],\n")
                append(indent(level + 4)).append("\"edges\": [")
                val edges = graph.edges.sortedWith(compareBy({ it.fromRva }, { it.toRva }, { it.kind }))
                if (edges.isNotEmpty()) append('\n')
                edges.forEachIndexed { ei, edge ->
                    append(indent(level + 5)).append("{\n")
                    numberField("fromRva", edge.fromRva, level + 6, true)
                    numberField("toRva", edge.toRva, level + 6, true)
                    field("kind", edge.kind, level + 6, false)
                    append(indent(level + 5)).append('}')
                    if (ei != edges.lastIndex) append(',')
                    append('\n')
                }
                if (edges.isNotEmpty()) append(indent(level + 4))
                append("]\n")
                append(indent(level + 3)).append('}')
                if (i != cfg.lastIndex) append(',')
                append('\n')
            }
            if (cfg.isNotEmpty()) append(indent(level + 2))
            append("],\n")

            append(indent(level + 2)).append("\"xrefs\": [")
            val xrefs = value.xrefs.sortedWith(compareBy({ it.fromRva }, { it.toRva }, { it.kind }))
            if (xrefs.isNotEmpty()) append('\n')
            xrefs.forEachIndexed { i, xref ->
                append(indent(level + 3)).append("{\n")
                numberField("fromRva", xref.fromRva, level + 4, true)
                numberField("toRva", xref.toRva, level + 4, true)
                field("kind", xref.kind, level + 4, false)
                append(indent(level + 3)).append('}')
                if (i != xrefs.lastIndex) append(',')
                append('\n')
            }
            if (xrefs.isNotEmpty()) append(indent(level + 2))
            append("],\n")

            append(indent(level + 2)).append("\"jniRegistrations\": [")
            val jni = value.jniRegistrations.sortedWith(compareBy({ it.className }, { it.methodName }, { it.signature }, { it.functionRva }))
            if (jni.isNotEmpty()) append('\n')
            jni.forEachIndexed { i, item ->
                append(indent(level + 3)).append("{\n")
                field("source", item.source, level + 4, true)
                field("className", item.className, level + 4, true)
                field("methodName", item.methodName, level + 4, true)
                field("signature", item.signature, level + 4, true)
                numberField("functionRva", item.functionRva, level + 4, true)
                numberField("tableRva", item.tableRva, level + 4, true)
                numberField("registerNativesCallsiteRva", item.registerNativesCallsiteRva, level + 4, true)
                numberField("findClassCallsiteRva", item.findClassCallsiteRva, level + 4, true)
                nullableStringField("classEvidence", item.classEvidence, level + 4, true)
                field("confidence", item.confidence, level + 4, false)
                append(indent(level + 3)).append('}')
                if (i != jni.lastIndex) append(',')
                append('\n')
            }
            if (jni.isNotEmpty()) append(indent(level + 2))
            append("],\n")

            append(indent(level + 2)).append("\"il2cppRegistrations\": [")
            val il2cpp = value.il2cppRegistrations.sortedWith(compareBy({ it.rva }, { it.kind }, { it.symbolName }))
            if (il2cpp.isNotEmpty()) append('\n')
            il2cpp.forEachIndexed { i, item ->
                append(indent(level + 3)).append("{\n")
                field("kind", item.kind, level + 4, true)
                numberField("rva", item.rva, level + 4, true)
                field("symbolName", item.symbolName, level + 4, true)
                field("evidence", item.evidence, level + 4, true)
                field("confidence", item.confidence, level + 4, false)
                append(indent(level + 3)).append('}')
                if (i != il2cpp.lastIndex) append(',')
                append('\n')
            }
            if (il2cpp.isNotEmpty()) append(indent(level + 2))
            append("],\n")

            append(indent(level + 2)).append("\"il2cppCodegenCalls\": [")
            val codegenCalls = value.il2cppCodegenCalls.sortedBy { it.callsiteRva }
            if (codegenCalls.isNotEmpty()) append('\n')
            codegenCalls.forEachIndexed { i, item ->
                append(indent(level + 3)).append("{\n")
                numberField("callsiteRva", item.callsiteRva, level + 4, true)
                numberField("codeRegistrationRva", item.codeRegistrationRva, level + 4, true)
                numberField("metadataRegistrationRva", item.metadataRegistrationRva, level + 4, true)
                numberField("codegenOptionsRva", item.codegenOptionsRva, level + 4, true)
                field("evidence", item.evidence, level + 4, true)
                field("confidence", item.confidence, level + 4, false)
                append(indent(level + 3)).append('}')
                if (i != codegenCalls.lastIndex) append(',')
                append('\n')
            }
            if (codegenCalls.isNotEmpty()) append(indent(level + 2))
            append("],\n")

            append(indent(level + 2)).append("\"il2cppPointerTables\": [")
            val pointerTables = value.il2cppPointerTables.sortedWith(compareBy({ it.ownerRva }, { it.fieldOffsetBytes }))
            if (pointerTables.isNotEmpty()) append('\n')
            pointerTables.forEachIndexed { i, item ->
                append(indent(level + 3)).append("{\n")
                numberField("ownerRva", item.ownerRva, level + 4, true)
                numberField("fieldOffsetBytes", item.fieldOffsetBytes.toLong(), level + 4, true)
                numberField("entryCount", item.entryCount, level + 4, true)
                numberField("tableRva", item.tableRva, level + 4, true)
                numberField("sampledEntries", item.sampledEntries.toLong(), level + 4, true)
                numberField("executableEntries", item.executableEntries.toLong(), level + 4, true)
                longArrayField("sampleFunctionRvas", item.sampleFunctionRvas.sorted(), level + 4, true)
                field("confidence", item.confidence, level + 4, false)
                append(indent(level + 3)).append('}')
                if (i != pointerTables.lastIndex) append(',')
                append('\n')
            }
            if (pointerTables.isNotEmpty()) append(indent(level + 2))
            append("],\n")

            append(indent(level + 2)).append("\"il2cppCodegenModules\": [")
            val modules = value.il2cppCodegenModules.sortedWith(compareBy({ it.moduleName }, { it.moduleRva }))
            if (modules.isNotEmpty()) append('\n')
            modules.forEachIndexed { i, item ->
                append(indent(level + 3)).append("{\n")
                numberField("ownerCodeRegistrationRva", item.ownerCodeRegistrationRva, level + 4, true)
                numberField("moduleRva", item.moduleRva, level + 4, true)
                field("moduleName", item.moduleName, level + 4, true)
                numberField("methodPointerCount", item.methodPointerCount.toLong(), level + 4, true)
                numberField("methodPointersRva", item.methodPointersRva, level + 4, true)
                append(indent(level + 4)).append("\"sampledMethodPointers\": [")
                val slots = item.sampledMethodPointers.sortedBy { it.slotIndex }
                if (slots.isNotEmpty()) append('\n')
                slots.forEachIndexed { si, slot ->
                    append(indent(level + 5)).append("{\n")
                    numberField("slotIndex", slot.slotIndex.toLong(), level + 6, true)
                    numberField("functionRva", slot.functionRva, level + 6, false)
                    append(indent(level + 5)).append('}')
                    if (si != slots.lastIndex) append(',')
                    append('\n')
                }
                if (slots.isNotEmpty()) append(indent(level + 4))
                append("],\n")
                field("evidence", item.evidence, level + 4, true)
                field("confidence", item.confidence, level + 4, false)
                append(indent(level + 3)).append('}')
                if (i != modules.lastIndex) append(',')
                append('\n')
            }
            if (modules.isNotEmpty()) append(indent(level + 2))
            append("],\n")
            stringArrayField("warnings", value.warnings.sorted(), level + 2, false)

            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.correlations(value: CrossRuntimeCorrelationSummary?, level: Int, comma: Boolean) {
        append(indent(level)).append("\"correlations\": ")
        if (value == null) {
            append("null")
        } else {
            append("{\n")
            numberField("dexNativeMethodsConsidered", value.dexNativeMethodsConsidered.toLong(), level + 1, true)
            numberField("dexNativeMethodsResolved", value.dexNativeMethodsResolved.toLong(), level + 1, true)
            numberField("il2cppMethodsConsidered", value.il2cppMethodsConsidered.toLong(), level + 1, true)
            numberField("il2cppMethodsResolved", value.il2cppMethodsResolved.toLong(), level + 1, true)
            booleanField("truncated", value.truncated, level + 1, true)

            append(indent(level + 1)).append("\"jniNative\": [")
            val jni = value.jniNative.sortedWith(compareBy({ it.dexEntry }, { it.dexMethodIndex }, { it.libraryEntry }, { it.functionRva }))
            if (jni.isNotEmpty()) append('\n')
            jni.forEachIndexed { index, item ->
                append(indent(level + 2)).append("{\n")
                field("dexEntry", item.dexEntry, level + 3, true)
                numberField("dexMethodIndex", item.dexMethodIndex.toLong(), level + 3, true)
                field("declaringClass", item.declaringClass, level + 3, true)
                field("methodName", item.methodName, level + 3, true)
                field("prototype", item.prototype, level + 3, true)
                field("libraryEntry", item.libraryEntry, level + 3, true)
                numberField("functionRva", item.functionRva, level + 3, true)
                nullableStringField("functionName", item.functionName, level + 3, true)
                field("source", item.source, level + 3, true)
                field("confidence", item.confidence, level + 3, true)
                field("evidence", item.evidence, level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != jni.lastIndex) append(',')
                append('\n')
            }
            if (jni.isNotEmpty()) append(indent(level + 1))
            append("],\n")

            append(indent(level + 1)).append("\"il2cppRegistrations\": [")
            val regs = value.il2cppRegistrations.sortedWith(compareBy({ it.libraryEntry }, { it.kind }, { it.ghidraRva }))
            if (regs.isNotEmpty()) append('\n')
            regs.forEachIndexed { index, item ->
                append(indent(level + 2)).append("{\n")
                field("kind", item.kind, level + 3, true)
                field("libraryEntry", item.libraryEntry, level + 3, true)
                field("staticSymbolName", item.staticSymbolName, level + 3, true)
                numberField("staticVirtualAddress", item.staticVirtualAddress, level + 3, true)
                field("ghidraSymbolName", item.ghidraSymbolName, level + 3, true)
                numberField("ghidraRva", item.ghidraRva, level + 3, true)
                field("evidence", item.evidence, level + 3, true)
                field("confidence", item.confidence, level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != regs.lastIndex) append(',')
                append('\n')
            }
            if (regs.isNotEmpty()) append(indent(level + 1))
            append("],\n")

            append(indent(level + 1)).append("\"il2cppMethods\": [")
            val methods = value.il2cppMethods.sortedWith(compareBy({ it.methodIndex }, { it.libraryEntry }, { it.functionRva }))
            if (methods.isNotEmpty()) append('\n')
            methods.forEachIndexed { index, item ->
                append(indent(level + 2)).append("{\n")
                field("metadataEntry", item.metadataEntry, level + 3, true)
                numberField("methodIndex", item.methodIndex.toLong(), level + 3, true)
                field("declaringType", item.declaringType, level + 3, true)
                field("methodName", item.methodName, level + 3, true)
                numberField("token", item.token, level + 3, true)
                field("libraryEntry", item.libraryEntry, level + 3, true)
                numberField("functionRva", item.functionRva, level + 3, true)
                field("functionName", item.functionName, level + 3, true)
                field("evidence", item.evidence, level + 3, true)
                field("confidence", item.confidence, level + 3, false)
                append(indent(level + 2)).append('}')
                if (index != methods.lastIndex) append(',')
                append('\n')
            }
            if (methods.isNotEmpty()) append(indent(level + 1))
            append("]\n")
            append(indent(level)).append('}')
        }
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.appendNative(native: NativeSummary, level: Int) {
        append("{\n")
        numberField("librariesDiscovered", native.librariesDiscovered.toLong(), level + 1, true)
        numberField("librariesScanned", native.librariesScanned.toLong(), level + 1, true)
        numberField("parseErrors", native.parseErrors.toLong(), level + 1, true)
        booleanField("truncated", native.truncated, level + 1, true)
        jniBridgesArray(native.jniBridges, level + 1, true)
        append(indent(level + 1)).append("\"libraries\": [")
        val ordered = native.libraries.sortedBy { it.entryName }
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, library ->
            appendNativeLibrary(library, level + 2)
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level + 1))
        append("]\n")
        append(indent(level)).append('}')
    }


    private fun Appendable.jniBridgesArray(values: List<JniBridgeReference>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"jniBridges\": [")
        val ordered = values.sortedWith(compareBy({ it.dexEntry }, { it.declaringClass }, { it.methodName }, { it.prototype }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("dexEntry", value.dexEntry, level + 2, true)
            field("declaringClass", value.declaringClass, level + 2, true)
            field("methodName", value.methodName, level + 2, true)
            field("prototype", value.prototype, level + 2, true)
            field("resolution", value.resolution, level + 2, true)
            nullableStringField("libraryEntry", value.libraryEntry, level + 2, true)
            nullableStringField("nativeSymbol", value.nativeSymbol, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.appendNativeLibrary(library: NativeLibrarySummary, level: Int) {
        append(indent(level)).append("{\n")
        field("entryName", library.entryName, level + 1, true)
        field("abi", library.abi, level + 1, true)
        field("elfClass", library.elfClass, level + 1, true)
        field("machine", library.machine, level + 1, true)
        field("fileType", library.fileType, level + 1, true)
        numberField("sizeBytes", library.sizeBytes, level + 1, true)
        nullableStringField("buildId", library.buildId, level + 1, true)
        stringArrayField("neededLibraries", library.neededLibraries.sorted(), level + 1, true)
        nativeSymbolsArray("importedSymbols", library.importedSymbols, level + 1, true)
        nativeSymbolsArray("exportedSymbols", library.exportedSymbols, level + 1, true)
        stringArrayField("jniSymbols", library.jniSymbols.sorted(), level + 1, true)
        booleanField("hasJniOnLoad", library.hasJniOnLoad, level + 1, true)
        booleanField("registerNativesIndicator", library.registerNativesIndicator, level + 1, true)
        nullableBooleanField("executableStack", library.executableStack, level + 1, true)
        booleanField("hasGnuRelro", library.hasGnuRelro, level + 1, true)
        booleanField("bindNow", library.bindNow, level + 1, true)
        booleanField("hasStackCanaryImport", library.hasStackCanaryImport, level + 1, true)
        nullableBooleanField("stripped", library.stripped, level + 1, true)
        stringArrayField("httpUrls", library.httpUrls.sorted(), level + 1, true)
        nativeSecretCandidatesArray(library.secretCandidates, level + 1, true)
        nullableStringField("parseError", library.parseError, level + 1, true)
        booleanField("truncated", library.truncated, level + 1, false)
        append(indent(level)).append('}')
    }


    private fun Appendable.nativeSecretCandidatesArray(values: List<NativeSecretCandidate>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"secretCandidates\": [")
        val ordered = values.sortedWith(compareBy({ it.kind }, { it.libraryEntry }, { it.valueSha256 }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, candidate ->
            append(indent(level + 1)).append("{\n")
            field("kind", candidate.kind, level + 2, true)
            field("libraryEntry", candidate.libraryEntry, level + 2, true)
            field("valueSha256", candidate.valueSha256, level + 2, true)
            field("redactedPreview", candidate.redactedPreview, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.nativeSymbolsArray(
        name: String,
        values: List<NativeSymbolReference>,
        level: Int,
        comma: Boolean,
    ) {
        append(indent(level)).append('"').append(name).append("\": [")
        val ordered = values.sortedWith(compareBy({ it.name }, { it.binding }, { it.symbolType }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, symbol ->
            append(indent(level + 1)).append("{\n")
            field("libraryEntry", symbol.libraryEntry, level + 2, true)
            field("name", symbol.name, level + 2, true)
            field("binding", symbol.binding, level + 2, true)
            field("symbolType", symbol.symbolType, level + 2, true)
            booleanField("defined", symbol.defined, level + 2, true)
            numberField("virtualAddress", symbol.virtualAddress, level + 2, true)
            numberField("sizeBytes", symbol.sizeBytes, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.appendIl2Cpp(value: Il2CppSummary, level: Int) {
        append("{\n")
        booleanField("detected", value.detected, level + 1, true)
        field("confidence", value.confidence, level + 1, true)
        numberField("parseErrors", value.parseErrors.toLong(), level + 1, true)
        booleanField("truncated", value.truncated, level + 1, true)
        stringArrayField("libil2cppLibraries", value.libil2cppLibraries.sorted(), level + 1, true)
        stringArrayField("il2cppApiSymbols", value.il2cppApiSymbols.sorted(), level + 1, true)
        stringArrayField("registrationIndicators", value.registrationIndicators.sorted(), level + 1, true)
        il2cppRegistrationCandidatesArray(value.registrationCandidates, level + 1, true)
        append(indent(level + 1)).append("\"metadata\": ")
        if (value.metadata == null) append("null\n") else appendIl2CppMetadata(value.metadata, level + 1)
        append(indent(level)).append('}')
    }

    private fun Appendable.il2cppRegistrationCandidatesArray(values: List<Il2CppRegistrationCandidate>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"registrationCandidates\": [")
        val ordered = values.sortedWith(compareBy({ it.kind }, { it.libraryEntry }, { it.symbolName }))
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("kind", value.kind, level + 2, true)
            field("libraryEntry", value.libraryEntry, level + 2, true)
            field("symbolName", value.symbolName, level + 2, true)
            numberField("virtualAddress", value.virtualAddress, level + 2, true)
            numberField("sizeBytes", value.sizeBytes, level + 2, true)
            booleanField("validatedDefinedSymbol", value.validatedDefinedSymbol, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.appendIl2CppMetadata(value: Il2CppMetadataSummary, level: Int) {
        append("{\n")
        field("entryName", value.entryName, level + 1, true)
        numberField("sizeBytes", value.sizeBytes, level + 1, true)
        booleanField("magicValid", value.magicValid, level + 1, true)
        numberField("metadataVersion", value.metadataVersion?.toLong(), level + 1, true)
        numberField("headerPairsScanned", value.headerPairsScanned.toLong(), level + 1, true)
        stringArrayField("assemblyNameCandidates", value.assemblyNameCandidates.sorted(), level + 1, true)
        stringArrayField("managedNameCandidates", value.managedNameCandidates.sorted(), level + 1, true)
        stringArrayField("unityVersionCandidates", value.unityVersionCandidates.sorted(), level + 1, true)
        nullableStringField("layoutProfile", value.layoutProfile, level + 1, true)
        il2cppTableRangesArray(value.tableRanges, level + 1, true)
        il2cppTypesArray(value.typeDefinitions, level + 1, true)
        il2cppMethodsArray(value.methodDefinitions, level + 1, true)
        booleanField("reconstructionTruncated", value.reconstructionTruncated, level + 1, true)
        nullableStringField("parseError", value.parseError, level + 1, true)
        booleanField("truncated", value.truncated, level + 1, false)
        append(indent(level)).append("}\n")
    }

    private fun Appendable.il2cppTableRangesArray(values: List<Il2CppTableRange>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"tableRanges\": [")
        val ordered = values.sortedBy { it.name }
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            field("name", value.name, level + 2, true)
            numberField("offset", value.offset, level + 2, true)
            numberField("sizeBytes", value.sizeBytes, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.il2cppTypesArray(values: List<Il2CppTypeDefinitionSummary>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"typeDefinitions\": [")
        val ordered = values.sortedBy { it.index }
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            numberField("index", value.index.toLong(), level + 2, true)
            field("namespace", value.namespace, level + 2, true)
            field("name", value.name, level + 2, true)
            field("fullName", value.fullName, level + 2, true)
            numberField("methodStart", value.methodStart.toLong(), level + 2, true)
            numberField("methodCount", value.methodCount.toLong(), level + 2, true)
            numberField("fieldStart", value.fieldStart.toLong(), level + 2, true)
            numberField("fieldCount", value.fieldCount.toLong(), level + 2, true)
            numberField("token", value.token, level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.il2cppMethodsArray(values: List<Il2CppMethodDefinitionSummary>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"methodDefinitions\": [")
        val ordered = values.sortedBy { it.index }
        if (ordered.isNotEmpty()) append('\n')
        ordered.forEachIndexed { index, value ->
            append(indent(level + 1)).append("{\n")
            numberField("index", value.index.toLong(), level + 2, true)
            numberField("declaringTypeIndex", value.declaringTypeIndex.toLong(), level + 2, true)
            field("declaringType", value.declaringType, level + 2, true)
            field("name", value.name, level + 2, true)
            numberField("parameterCount", value.parameterCount.toLong(), level + 2, true)
            numberField("token", value.token, level + 2, true)
            numberField("flags", value.flags.toLong(), level + 2, false)
            append(indent(level + 1)).append('}')
            if (index != ordered.lastIndex) append(',')
            append('\n')
        }
        if (ordered.isNotEmpty()) append(indent(level))
        append(']'); if (comma) append(','); append('\n')
    }

    private fun Appendable.appendFinding(f: Finding, level: Int) {
        append(indent(level)).append("{\n")
        field("id", f.id, level + 1, true)
        field("title", f.title, level + 1, true)
        field("severity", f.severity.name, level + 1, true)
        field("confidence", f.confidence.name, level + 1, true)
        field("category", f.category, level + 1, true)
        field("description", f.description, level + 1, true)
        booleanField("requiresManualReview", f.requiresManualReview, level + 1, true)
        field("remediation", f.remediation, level + 1, true)
        evidenceArray(f.evidence, level + 1, true)
        referencesArray(f.references, level + 1, false)
        append(indent(level)).append('}')
    }

    private fun Appendable.evidenceArray(values: List<Evidence>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"evidence\": [")
        if (values.isNotEmpty()) append('\n')
        values.forEachIndexed { i, e ->
            append(indent(level + 1)).append("{\n")
            field("source", e.source, level + 2, true)
            field("location", e.location, level + 2, true)
            field("value", e.value, level + 2, false)
            append(indent(level + 1)).append('}')
            if (i != values.lastIndex) append(',')
            append('\n')
        }
        if (values.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.referencesArray(values: List<SecurityReference>, level: Int, comma: Boolean) {
        append(indent(level)).append("\"references\": [")
        if (values.isNotEmpty()) append('\n')
        values.forEachIndexed { i, r ->
            append(indent(level + 1)).append("{\n")
            field("standard", r.standard, level + 2, true)
            field("id", r.id, level + 2, false)
            append(indent(level + 1)).append('}')
            if (i != values.lastIndex) append(',')
            append('\n')
        }
        if (values.isNotEmpty()) append(indent(level))
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.stringArrayField(name: String, values: List<String>, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": [")
        values.forEachIndexed { index, value ->
            if (index > 0) append(", ")
            append('"')
            appendEscaped(value)
            append('"')
        }
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.field(name: String, value: String, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": \"")
        appendEscaped(value)
        append('"')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.nullableStringField(name: String, value: String?, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": ")
        if (value == null) {
            append("null")
        } else {
            append('"')
            appendEscaped(value)
            append('"')
        }
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.numberField(name: String, value: Long?, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": ").append(value?.toString() ?: "null")
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.booleanField(name: String, value: Boolean, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": ").append(value)
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.nullableBooleanField(name: String, value: Boolean?, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": ").append(value?.toString() ?: "null")
        if (comma) append(',')
        append('\n')
    }

    private fun indent(level: Int) = "  ".repeat(level)

    private fun Appendable.appendEscaped(input: String) {
        input.forEach { ch ->
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (ch.code < 0x20) {
                    append("\\u")
                    append(HEX[(ch.code ushr 12) and 0xf])
                    append(HEX[(ch.code ushr 8) and 0xf])
                    append(HEX[(ch.code ushr 4) and 0xf])
                    append(HEX[ch.code and 0xf])
                } else {
                    append(ch)
                }
            }
        }
    }

    private const val HEX = "0123456789abcdef"
}
