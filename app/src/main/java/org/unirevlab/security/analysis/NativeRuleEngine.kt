package org.unirevlab.security.analysis

import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.Evidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.SecurityReference
import org.unirevlab.security.model.Severity

object NativeRuleEngine {
    fun evaluate(native: NativeSummary): List<Finding> = buildList {
        val execStack = ArrayList<String>(50)
        val noRelro = ArrayList<String>(50)
        val lazyBindingEntries = ArrayList<String>(50)
        val noCanaryEvidence = ArrayList<String>(50)
        val nonStandard = ArrayList<String>(50)
        val http = ArrayList<Pair<String, String>>(50)
        val secretCandidates = ArrayList<org.unirevlab.security.model.NativeSecretCandidate>(50)
        val processExec = LinkedHashSet<Triple<String, String, String>>()
        val dynamicLoad = LinkedHashSet<Pair<String, String>>()
        val jniEvidence = ArrayList<String>(50)

        for (lib in native.libraries) {
            if (lib.parseError != null) continue
            if (lib.executableStack == true && execStack.size < 50) execStack += lib.entryName
            if (!lib.hasGnuRelro && noRelro.size < 50) noRelro += lib.entryName
            if (lib.hasGnuRelro && !lib.bindNow && lazyBindingEntries.size < 50) lazyBindingEntries += lib.entryName
            if (!lib.hasStackCanaryImport && noCanaryEvidence.size < 50) noCanaryEvidence += lib.entryName
            if (!ArchiveClassifier.isStandardNativeLibraryPath(lib.entryName) && nonStandard.size < 50) nonStandard += lib.entryName

            if (http.size < 50) {
                for (url in lib.httpUrls) {
                    if (!isActionableCleartextUrl(url)) continue
                    http += lib.entryName to url
                    if (http.size >= 50) break
                }
            }
            if (secretCandidates.size < 50) {
                for (candidate in lib.secretCandidates) {
                    secretCandidates += candidate
                    if (secretCandidates.size >= 50) break
                }
            }
            if (processExec.size < 50 || dynamicLoad.size < 50) {
                for (symbol in lib.importedSymbols) {
                    val normalized = symbol.name.substringBefore('@')
                    if (processExec.size < 50 && normalized in PROCESS_EXECUTION_IMPORTS) {
                        processExec += Triple(lib.entryName, normalized, symbol.symbolType)
                    }
                    if (dynamicLoad.size < 50 && normalized in DYNAMIC_LOADING_IMPORTS) {
                        dynamicLoad += lib.entryName to normalized
                    }
                    if (processExec.size >= 50 && dynamicLoad.size >= 50) break
                }
            }
            if (jniEvidence.size < 50 && (lib.hasJniOnLoad || lib.jniSymbols.isNotEmpty() || lib.registerNativesIndicator)) {
                jniEvidence += "${lib.entryName}: JNI_OnLoad=${lib.hasJniOnLoad}; staticSymbols=${lib.jniSymbols.size}; RegisterNativesIndicator=${lib.registerNativesIndicator}"
            }
        }

        if (execStack.isNotEmpty()) add(executableStack(execStack))
        if (noRelro.isNotEmpty()) add(missingRelro(noRelro))
        if (lazyBindingEntries.isNotEmpty()) add(lazyBinding(lazyBindingEntries))
        if (noCanaryEvidence.isNotEmpty()) add(stackCanaryReview(noCanaryEvidence))
        if (nonStandard.isNotEmpty()) add(nonStandardNativeLocation(nonStandard))
        if (http.isNotEmpty()) add(hardcodedHttp(http))
        if (secretCandidates.isNotEmpty()) add(nativeSecretReview(secretCandidates))
        if (processExec.isNotEmpty()) add(processExecutionApis(processExec.toList()))
        if (dynamicLoad.isNotEmpty()) add(dynamicLoadingApis(dynamicLoad.toList()))

        if (jniEvidence.size < 50) {
            for (bridge in native.jniBridges) {
                jniEvidence += "${bridge.declaringClass}->${bridge.methodName}${bridge.prototype}: ${bridge.resolution}" +
                    (bridge.libraryEntry?.let { lib -> "; library=$lib" } ?: "") +
                    (bridge.nativeSymbol?.let { symbol -> "; symbol=$symbol" } ?: "")
                if (jniEvidence.size >= 50) break
            }
        }
        if (jniEvidence.isNotEmpty()) add(jniInventory(jniEvidence))
        if (native.truncated || native.parseErrors > 0) add(partial(native))
    }

    private fun executableStack(entries: List<String>) = Finding(
        id = "NATIVE-EXECUTABLE-STACK",
        title = "Native library requests an executable process stack",
        severity = Severity.HIGH,
        confidence = Confidence.CONFIRMED,
        category = "NATIVE_HARDENING",
        description = "One or more ELF PT_GNU_STACK program headers contain the execute flag. An executable stack weakens exploit mitigations and is normally unnecessary for Android native code.",
        evidence = entries.take(50).map { Evidence(it, "PT_GNU_STACK", "PF_X=true") },
        remediation = "Rebuild the native library without an executable stack, identify any assembly object that lacks a non-executable stack note, and verify the final ELF program headers in release CI.",
        references = listOf(SecurityReference("CWE", "CWE-119")),
    )

    private fun missingRelro(entries: List<String>) = Finding(
        id = "NATIVE-RELRO-MISSING",
        title = "Native library lacks a GNU RELRO segment",
        severity = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        category = "NATIVE_HARDENING",
        description = "The ELF does not contain PT_GNU_RELRO. RELRO makes selected relocation-related memory read-only after startup and reduces the writable control-data surface.",
        evidence = entries.take(50).map { Evidence(it, "program_headers", "PT_GNU_RELRO=false") },
        remediation = "Enable linker RELRO for production native libraries and verify the final artifact rather than relying only on build-system flags.",
        requiresManualReview = true,
    )

    private fun lazyBinding(entries: List<String>) = Finding(
        id = "NATIVE-BIND-NOW-MISSING",
        title = "Native library uses RELRO without immediate symbol binding",
        severity = Severity.LOW,
        confidence = Confidence.HIGH,
        category = "NATIVE_HARDENING",
        description = "PT_GNU_RELRO is present but DT_BIND_NOW/DF_BIND_NOW/DF_1_NOW was not observed. This generally corresponds to partial rather than full RELRO.",
        evidence = entries.take(50).map { Evidence(it, ".dynamic", "BIND_NOW=false") },
        remediation = "Consider full RELRO for production builds by enabling immediate binding and confirm compatibility/performance in the target application.",
        requiresManualReview = true,
    )

    private fun stackCanaryReview(entries: List<String>) = Finding(
        id = "NATIVE-STACK-CANARY-REVIEW",
        title = "No stack-canary runtime import was observed",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.LOW,
        category = "NATIVE_HARDENING",
        description = "The dynamic symbol table did not reference __stack_chk_fail or __stack_chk_guard. Absence of these imports is not proof that every function lacks stack protection, so this is a review signal rather than a confirmed vulnerability.",
        evidence = entries.take(50).map { Evidence(it, ".dynsym", "stack_chk_import=false") },
        remediation = "Review compiler hardening flags and inspect representative functions or build metadata. Enable stack protection where appropriate for native code handling untrusted data.",
        requiresManualReview = true,
    )


    private fun nonStandardNativeLocation(entries: List<String>) = Finding(
        id = "NATIVE-NONSTANDARD-LOCATION",
        title = "Native shared object is packaged outside the standard APK lib/<abi> path",
        severity = Severity.LOW,
        confidence = Confidence.CONFIRMED,
        category = "NATIVE",
        description = "One or more .so files are packaged outside the conventional lib/<abi>/ directory. This can be legitimate, but it is also used by applications that extract or dynamically load native payloads at runtime and therefore deserves code-path review.",
        evidence = entries.take(50).map { Evidence(it, "archive_path", it) },
        remediation = "Confirm why the library is stored outside lib/<abi>/, trace the extraction/loading path, verify integrity/signature checks for dynamically loaded code, and remove obsolete embedded payloads.",
        requiresManualReview = true,
    )


    private fun nativeSecretReview(candidates: List<org.unirevlab.security.model.NativeSecretCandidate>) = Finding(
        id = "NATIVE-POTENTIAL-HARDCODED-SECRET",
        title = "Potential credential or private-key material is embedded in a native library",
        severity = Severity.MEDIUM,
        confidence = Confidence.MEDIUM,
        category = "STORAGE",
        description = "High-signal pattern matching found printable native data resembling credential identifiers, tokens, or private-key material. Raw candidate values are intentionally not persisted.",
        evidence = candidates.take(50).map {
            Evidence(it.libraryEntry, "ASCII_STRING", "kind=${it.kind}; sha256=${it.valueSha256}; preview=${it.redactedPreview}")
        },
        remediation = "Validate each candidate in code/data context. Remove reusable secrets from client binaries, rotate exposed credentials, and keep server-side secrets outside distributed application packages.",
        references = listOf(SecurityReference("OWASP MASWE", "MASWE-0004")),
        requiresManualReview = true,
    )

    private fun processExecutionApis(entries: List<Triple<String, String, String>>) = Finding(
        id = "NATIVE-PROCESS-EXECUTION-API-REVIEW",
        title = "Native code imports process or shell execution APIs",
        severity = Severity.LOW,
        confidence = Confidence.CONFIRMED,
        category = "CODE",
        description = "One or more native libraries import APIs capable of starting processes or shell commands. Import presence alone is not a vulnerability; untrusted data flow into these calls is the relevant risk.",
        evidence = entries.distinct().take(50).map { Evidence(it.first, ".dynsym import", "${it.second} (${it.third})") },
        remediation = "Trace callers and argument construction. Avoid shell interpretation where possible, use fixed argument vectors, and ensure externally influenced values cannot become executable command content.",
        requiresManualReview = true,
    )

    private fun dynamicLoadingApis(entries: List<Pair<String, String>>) = Finding(
        id = "NATIVE-DYNAMIC-LOADING-API-REVIEW",
        title = "Native code imports dynamic library loading or symbol-resolution APIs",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.CONFIRMED,
        category = "CODE",
        description = "Native code imports dlopen/android_dlopen_ext/dlsym-style functionality. This may be entirely legitimate, but it is important when reviewing runtime-loaded code, plugins, unpacked libraries, and integrity controls.",
        evidence = entries.distinct().take(50).map { Evidence(it.first, ".dynsym import", it.second) },
        remediation = "Trace library paths and symbol names, verify that loaded code is trusted and integrity-checked, and correlate with any .so files packaged outside lib/<abi>/.",
        requiresManualReview = true,
    )

    private fun hardcodedHttp(entries: List<Pair<String, String>>) = Finding(
        id = "NATIVE-HARDCODED-HTTP-URL",
        title = "Hardcoded cleartext HTTP URL is present in native code/data",
        severity = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        category = "NETWORK",
        description = "Printable native-library data contains one or more hardcoded HTTP URLs. Reachability and actual transport behavior still require code-level or dynamic confirmation.",
        evidence = entries.take(50).map { Evidence(it.first, "ASCII_STRING", it.second) },
        remediation = "Remove obsolete cleartext endpoints, use HTTPS for production traffic, and trace each string through native xrefs or runtime tests before assigning final impact.",
        references = listOf(
            SecurityReference("OWASP MASTG", "MASTG-TEST-0233"),
            SecurityReference("OWASP MASVS", "MASVS-NETWORK"),
        ),
        requiresManualReview = true,
    )

    private fun jniInventory(entries: List<String>) = Finding(
        id = "NATIVE-JNI-ATTACK-SURFACE",
        title = "JNI/native application attack surface detected",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.HIGH,
        category = "NATIVE",
        description = "Native libraries expose or appear to register JNI entry points. These boundaries should be included in manual data-flow, memory-safety, and input-validation review.",
        evidence = entries.take(50).map { Evidence("native", "JNI", it) },
        remediation = "Map Java/Kotlin native declarations to their native implementations, validate all data crossing the JNI boundary, and prioritize parsers, crypto, deserialization, and externally influenced buffers for native review/fuzzing.",
        requiresManualReview = true,
    )

    private fun partial(native: NativeSummary) = Finding(
        id = "ANALYSIS-NATIVE-PARTIAL",
        title = "Native analysis is partial",
        severity = Severity.INFORMATIONAL,
        confidence = Confidence.CONFIRMED,
        category = "ANALYSIS",
        description = "At least one discovered native library, symbol table, or string table was not exhaustively analyzed. This is an analyzer coverage limitation, not an application vulnerability.",
        evidence = listOf(Evidence("analysis", "native", "librariesScanned=${native.librariesScanned}; librariesDiscovered=${native.librariesDiscovered}; unscanned=${(native.librariesDiscovered - native.librariesScanned).coerceAtLeast(0)}; parseErrors=${native.parseErrors}; boundedOutput=${native.truncated}")),
        remediation = "Use the isolated self-hosted worker profile with explicitly increased resource limits for large artifacts, and manually inspect libraries that failed parsing.",
    )

    private fun isActionableCleartextUrl(raw: String): Boolean {
        val value = raw.trim()
        if (!value.startsWith("http://", ignoreCase = true)) return false
        val lower = value.lowercase()
        if (CLEAR_TEXT_REFERENCE_PREFIXES.any(lower::startsWith)) return false
        if ('%' in value || '{' in value || '}' in value) return false
        return true
    }

    private val PROCESS_EXECUTION_IMPORTS = setOf(
        "system", "popen", "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe", "posix_spawn", "posix_spawnp",
    )
    private val DYNAMIC_LOADING_IMPORTS = setOf("dlopen", "android_dlopen_ext", "dlsym")
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
