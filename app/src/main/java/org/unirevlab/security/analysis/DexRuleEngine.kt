package org.unirevlab.security.analysis

import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.DexStringReference
import org.unirevlab.security.model.Evidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.SecurityReference
import org.unirevlab.security.model.Severity

object DexRuleEngine {
    fun evaluate(dex: DexSummary): List<Finding> = buildList {
        val actionableHttpUrls = dex.httpUrls.filter { isActionableCleartextUrl(it.value) }
        if (actionableHttpUrls.isNotEmpty()) add(hardcodedHttpFinding(actionableHttpUrls))
        if (dex.secretCandidates.isNotEmpty()) add(secretCandidateReview(dex))

        val dynamicLoading = ArrayList<org.unirevlab.security.model.DexMethodCallXref>(minOf(50, dex.callXrefs.size))
        val processExecution = ArrayList<org.unirevlab.security.model.DexMethodCallXref>(minOf(50, dex.callXrefs.size))
        val webViewSensitive = ArrayList<org.unirevlab.security.model.DexMethodCallXref>(minOf(50, dex.callXrefs.size))
        val installerSource = ArrayList<org.unirevlab.security.model.DexMethodCallXref>(minOf(50, dex.callXrefs.size))
        for (xref in dex.callXrefs) {
            if (dynamicLoading.size < 50 && isDynamicLoadingCall(xref)) dynamicLoading += xref
            if (processExecution.size < 50 && isProcessExecutionCall(xref)) processExecution += xref
            if (webViewSensitive.size < 50 && isWebViewSensitiveCall(xref)) webViewSensitive += xref
            if (installerSource.size < 50 && isInstallerSourceCall(xref)) installerSource += xref
            if (
                dynamicLoading.size >= 50 && processExecution.size >= 50 &&
                webViewSensitive.size >= 50 && installerSource.size >= 50
            ) break
        }
        if (dynamicLoading.isNotEmpty()) add(dynamicLoadingReview(dynamicLoading))
        if (processExecution.isNotEmpty()) add(processExecutionReview(processExecution))
        if (webViewSensitive.isNotEmpty()) add(webViewReview(webViewSensitive))
        if (installerSource.isNotEmpty()) add(installerSourceReview(installerSource))

        val riskyWebViewObservations = ArrayList<org.unirevlab.security.model.DexInvokeObservation>(minOf(50, dex.invokeObservations.size))
        for (observation in dex.invokeObservations) {
            if (isKnownRiskyWebViewObservation(observation)) {
                riskyWebViewObservations += observation
                if (riskyWebViewObservations.size >= 50) break
            }
        }
        if (riskyWebViewObservations.isNotEmpty()) add(webViewKnownArgumentFinding(riskyWebViewObservations))
        if (dex.truncated || dex.parseErrors > 0) add(partialDexAnalysisFinding(dex))
    }

    private fun hardcodedHttpFinding(urls: List<DexStringReference>) = Finding(
        id = "DEX-HARDCODED-HTTP-URL",
        title = "Hardcoded HTTP URL strings are present in DEX",
        severity = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        category = "NETWORK",
        description = "The DEX string table contains one or more hardcoded cleartext HTTP URLs. String presence is strong static evidence of an embedded endpoint but code-level reachability still needs confirmation for precise impact.",
        evidence = urls.take(50).map {
            Evidence(it.dexEntry, "string_id[${it.stringIndex}]", it.value)
        },
        remediation = "Use HTTPS endpoints and remove obsolete cleartext URLs from production code/resources. Trace each string to its callers and confirm that no runtime path transmits sensitive data over cleartext transport.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0233"),
            SecurityReference("OWASP MASVS", "MASVS-NETWORK"),
        ),
        requiresManualReview = true,
    )

    private fun secretCandidateReview(dex: DexSummary) = Finding(
        id = "DEX-POTENTIAL-HARDCODED-SECRET",
        title = "Potential credential or private-key material is embedded in DEX strings",
        severity = Severity.MEDIUM,
        confidence = Confidence.MEDIUM,
        category = "STORAGE",
        description = "Pattern-based scanning found strings resembling credential identifiers, tokens, or private-key material. The report intentionally stores only a fingerprint and redacted preview; every candidate must be validated in code context before it is treated as a vulnerability.",
        evidence = dex.secretCandidates.take(50).map {
            Evidence(
                it.dexEntry,
                "string_id[${it.stringIndex}]",
                "kind=${it.kind}; sha256=${it.valueSha256}; preview=${it.redactedPreview}",
            )
        },
        remediation = "Determine whether each candidate is live and security-sensitive. Remove reusable secrets from application packages, rotate exposed credentials, move server-side secrets to trusted backend systems, and use platform keystores for device-bound key material where appropriate.",
        references = listOf(
            SecurityReference("OWASP MASWE", "MASWE-0004"),
            SecurityReference("OWASP MASTG", "MASTG-TECH-0019"),
        ),
        requiresManualReview = true,
    )

    private fun isDynamicLoadingCall(x: org.unirevlab.security.model.DexMethodCallXref): Boolean =
        x.calleeName == "<init>" && when (x.calleeClass) {
            "Ldalvik/system/DexClassLoader;", "Ldalvik/system/InMemoryDexClassLoader;" -> true
            "Ldalvik/system/PathClassLoader;" -> !x.callerClass.startsWith("Lcom/google/android/gms/dynamite/")
            else -> false
        }

    private fun isProcessExecutionCall(x: org.unirevlab.security.model.DexMethodCallXref): Boolean =
        (x.calleeClass == "Ljava/lang/Runtime;" && x.calleeName == "exec") ||
            (x.calleeClass == "Ljava/lang/ProcessBuilder;" && (x.calleeName == "start" || x.calleeName == "<init>"))

    private fun isWebViewSensitiveCall(x: org.unirevlab.security.model.DexMethodCallXref): Boolean =
        (x.calleeClass == "Landroid/webkit/WebView;" && x.calleeName in setOf("addJavascriptInterface", "setWebContentsDebuggingEnabled")) ||
            (x.calleeClass == "Landroid/webkit/WebSettings;" && x.calleeName in setOf(
                "setJavaScriptEnabled", "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs", "setMixedContentMode"
            ))

    private fun isInstallerSourceCall(x: org.unirevlab.security.model.DexMethodCallXref): Boolean =
        (x.calleeClass == "Landroid/content/pm/PackageManager;" && x.calleeName in setOf(
            "getInstallerPackageName", "getInstallSourceInfo"
        )) ||
            (x.calleeClass == "Landroid/content/pm/InstallSourceInfo;" && x.calleeName in setOf(
                "getInstallingPackageName", "getInitiatingPackageName", "getOriginatingPackageName"
            ))

    private fun isKnownRiskyWebViewObservation(x: org.unirevlab.security.model.DexInvokeObservation): Boolean {
        val boolTrue = x.arguments.any { it.kind in setOf("INT", "NULL_OR_INT") && it.value == "1" }
        return boolTrue && (
            (x.calleeClass == "Landroid/webkit/WebView;" && x.calleeName == "setWebContentsDebuggingEnabled") ||
            (x.calleeClass == "Landroid/webkit/WebSettings;" && x.calleeName in setOf("setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs"))
        )
    }

    private fun webViewKnownArgumentFinding(observations: List<org.unirevlab.security.model.DexInvokeObservation>) = Finding(
        id = "DEX-WEBVIEW-KNOWN-RISKY-ARGUMENT",
        title = "Risk-sensitive WebView option is enabled by a statically known value",
        severity = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        category = "PLATFORM",
        description = "Bounded intra-block value propagation recovered a constant true argument for a WebView/WebSettings option that can expand the attack surface. This is stronger evidence than an API-reference-only finding, but origin and reachability still require review.",
        evidence = observations.map { obs ->
            val args = obs.arguments.joinToString { "arg${it.argumentIndex}=v${it.register}:${it.kind}:${it.value}" }
            Evidence(obs.dexEntry, "${obs.callerClass}->${obs.callerName}+${obs.instructionOffsetCodeUnits}", "${obs.calleeClass}->${obs.calleeName}${obs.calleePrototype}; $args")
        },
        remediation = "Disable WebView debugging in production, avoid universal/file-origin access unless strictly necessary, restrict navigable origins, and review JavaScript bridges and file access together with the affected call site.",
        references = listOf(SecurityReference("OWASP MASVS", "MASVS-PLATFORM")),
        requiresManualReview = true,
    )

    private fun dynamicLoadingReview(xrefs: List<org.unirevlab.security.model.DexMethodCallXref>) = Finding(
        id = "DEX-DYNAMIC-CODE-LOADING",
        title = "Dynamic code or native-library loading paths are present",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.HIGH,
        category = "CODE",
        description = "Bytecode xrefs show calls related to runtime DEX/class-loader or native-library loading. This is not inherently vulnerable, but the source, integrity, and trust boundary of dynamically loaded code require review.",
        evidence = xrefs.map {
            Evidence(it.dexEntry, "${it.callerClass}->${it.callerName}+${it.instructionOffsetCodeUnits}", "${it.calleeClass}->${it.calleeName}${it.calleePrototype}")
        },
        remediation = "Verify that dynamically loaded code comes only from trusted, integrity-checked locations; avoid loading executable content from writable/untrusted storage and include these paths in update/supply-chain review.",
        requiresManualReview = true,
    )

    private fun processExecutionReview(xrefs: List<org.unirevlab.security.model.DexMethodCallXref>) = Finding(
        id = "DEX-PROCESS-EXECUTION-SURFACE",
        title = "Process execution APIs are referenced",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.HIGH,
        category = "CODE",
        description = "Bytecode xrefs reference Runtime.exec or ProcessBuilder. Presence alone is not a vulnerability; externally influenced command construction is the security-relevant condition.",
        evidence = xrefs.map {
            Evidence(it.dexEntry, "${it.callerClass}->${it.callerName}+${it.instructionOffsetCodeUnits}", "${it.calleeClass}->${it.calleeName}${it.calleePrototype}")
        },
        remediation = "Trace all inputs reaching process execution, use fixed argument lists rather than shell concatenation, and remove execution paths that are unnecessary for production Android builds.",
        requiresManualReview = true,
    )

    private fun webViewReview(xrefs: List<org.unirevlab.security.model.DexMethodCallXref>) = Finding(
        id = "DEX-WEBVIEW-SENSITIVE-API",
        title = "Security-sensitive WebView configuration APIs are referenced",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.HIGH,
        category = "PLATFORM",
        description = "Bytecode xrefs reference WebView or WebSettings APIs whose security depends on arguments, loaded origins, and JavaScript bridge exposure. The xref stage intentionally does not infer vulnerability without value/data-flow analysis.",
        evidence = xrefs.map {
            Evidence(it.dexEntry, "${it.callerClass}->${it.callerName}+${it.instructionOffsetCodeUnits}", "${it.calleeClass}->${it.calleeName}${it.calleePrototype}")
        },
        remediation = "Review argument values and data flow for each call, restrict WebView navigation to trusted origins, minimize JavaScript/native bridges, and disable debugging or permissive file-origin settings in production.",
        requiresManualReview = true,
    )

    private fun installerSourceReview(xrefs: List<org.unirevlab.security.model.DexMethodCallXref>) = Finding(
        id = "DEX-INSTALL-SOURCE-CHECK",
        title = "Installation-source APIs are referenced",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.HIGH,
        category = "RESILIENCE",
        description = "Bytecode xrefs show Android PackageManager/InstallSourceInfo calls that can distinguish Play Store, sideload, enterprise, or other installation sources. This is not a vulnerability by itself, but it can be part of integrity, anti-tamper, licensing, or distribution policy logic and should be included in resilience review.",
        evidence = xrefs.map {
            Evidence(it.dexEntry, "${it.callerClass}->${it.callerName}+${it.instructionOffsetCodeUnits}", "${it.calleeClass}->${it.calleeName}${it.calleePrototype}")
        },
        remediation = "Document why installation source affects behavior and ensure source checks are not treated as the sole authorization or entitlement boundary. For high-value decisions, enforce trust on a backend or through platform attestation rather than relying only on a client-side installer identifier.",
        references = listOf(SecurityReference("OWASP MASVS", "MASVS-RESILIENCE")),
        requiresManualReview = true,
    )

    private fun partialDexAnalysisFinding(dex: DexSummary) = Finding(
        id = "ANALYSIS-DEX-PARTIAL",
        title = "DEX analysis is partial",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.CONFIRMED,
        category = "ANALYSIS",
        description = "At least one DEX parser or bounded code/xref collection reached a defensive limit. The evidence below states string coverage separately, so a complete string count is not misreported as a truncated string scan.",
        evidence = listOf(
            Evidence(
                "analysis",
                "DEX",
                "files=${dex.dexFilesScanned}/${dex.dexFilesDiscovered}; strings=${dex.stringsScanned}/${dex.stringsDeclared}; parseErrors=${dex.parseErrors}; " +
                    "boundedCollections=codeMethods:${dex.codeMethods.size},callXrefs:${dex.callXrefs.size},stringXrefs:${dex.stringXrefs.size}," +
                    "typeXrefs:${dex.typeXrefs.size},fieldXrefs:${dex.fieldXrefs.size},basicBlocks:${dex.basicBlocks.size}," +
                    "constants:${dex.constants.size},invokeObservations:${dex.invokeObservations.size}",
            ),
        ),
        remediation = "Run the artifact in a self-hosted worker profile with appropriately increased resource limits after validating available memory/disk capacity, or inspect the remaining DEX files manually.",
        requiresManualReview = false,
    )

    private fun isActionableCleartextUrl(raw: String): Boolean {
        val value = raw.trim()
        if (!value.startsWith("http://", ignoreCase = true)) return false
        val lower = value.lowercase()
        if (CLEAR_TEXT_REFERENCE_PREFIXES.any(lower::startsWith)) return false
        if ('%' in value || '{' in value || '}' in value) return false
        return true
    }

    private val CLEAR_TEXT_REFERENCE_PREFIXES = listOf(
        "http://schemas.android.com/",
        "http://www.w3.org/",
        "http://xml.org/",
        "http://www.omg.org/",
        "http://purl.org/",
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
    )
}
