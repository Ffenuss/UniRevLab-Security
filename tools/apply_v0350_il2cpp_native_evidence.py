#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RISK = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppMonetizationRiskEngine.kt"
MAPPING = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppSemanticMappingEngine.kt"
DUMP = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppManagedDumpExporter.kt"
PAIR = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppPairAssessmentEngine.kt"
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/Il2CppPairWorkspaceScreen.kt"
MODELS = ROOT / "app/src/main/java/org/unirevlab/security/model/CrossRuntimeCorrelationModels.kt"
BUILD = ROOT / "app/build.gradle.kts"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def patch_risk() -> None:
    text = RISK.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''        val nativeByMethod = report.correlations?.il2cppMethods.orEmpty()\n            .groupBy { it.methodIndex }\n        val candidates = LinkedHashMap<String, Candidate>()\n''',
        '''        val nativeEvidence = Il2CppNativeEvidenceEngine.analyze(report)\n        val nativeEvidenceByMethod = nativeEvidence.methods.associateBy { it.methodIndex }\n        val candidates = LinkedHashMap<String, Candidate>()\n''',
        "risk native evidence index",
    )
    text = replace_once(
        text,
        '''                val native = nativeByMethod[method.index].orEmpty()\n                    .firstOrNull { it.functionName.isNotBlank() }\n''',
        '''                val native = nativeEvidenceByMethod[method.index]?.takeIf { evidence ->\n                    evidence.verdict != Il2CppNativeEvidenceEngine.Verdict.CONFLICTING &&\n                        !evidence.nativeFunctionName.isNullOrBlank()\n                }\n''',
        "risk exact method native selection",
    )
    text = replace_once(
        text,
        '''                    native?.let {\n                        add("Correlated to recovered native function identity: ${it.functionName} (${it.confidence})")\n                    }\n''',
        '''                    native?.let {\n                        add("Validated native identity: ${it.nativeFunctionName} · ${it.verdict} · ${it.sourceEvidence} (${it.sourceConfidence})")\n                        it.evidence.take(2).forEach(::add)\n                    }\n''',
        "risk exact method native evidence",
    )
    text = replace_once(
        text,
        '''                val native = method?.let { current ->\n                    nativeByMethod[current.index].orEmpty().firstOrNull { it.functionName.isNotBlank() }\n                }\n''',
        '''                val native = method?.let { current ->\n                    nativeEvidenceByMethod[current.index]?.takeIf { evidence ->\n                        evidence.verdict != Il2CppNativeEvidenceEngine.Verdict.CONFLICTING &&\n                            !evidence.nativeFunctionName.isNullOrBlank()\n                    }\n                }\n''',
        "risk contextual native selection",
    )
    text = text.replace("nativeFunctionName = native?.functionName,", "nativeFunctionName = native?.nativeFunctionName,")
    text = replace_once(
        text,
        '''                        evidence = mapping.evidence + listOf(\n                            "Contextual analyst alias: ${mapping.alias}",\n                            "This candidate is inferred from enclosing metadata context and does not prove a live premium value or authorization result.",\n                        ),\n''',
        '''                        evidence = mapping.evidence + native?.evidence.orEmpty().take(3) + listOf(\n                            "Contextual analyst alias: ${mapping.alias}",\n                            "This candidate is inferred from enclosing metadata context and does not prove a live premium value or authorization result.",\n                        ),\n''',
        "risk contextual evidence",
    )
    RISK.write_text(text, encoding="utf-8")


def patch_mapping() -> None:
    text = MAPPING.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''        val methodsByType = metadata.methodDefinitions.groupBy { it.declaringTypeIndex }\n''',
        '''        val nativeEvidenceByMethod = Il2CppNativeEvidenceEngine.analyze(report).methods.associateBy { it.methodIndex }\n        val methodsByType = metadata.methodDefinitions.groupBy { it.declaringTypeIndex }\n''',
        "mapping native evidence index",
    )
    text = replace_once(
        text,
        '''                            evidence = listOf(\n                                "Semantic marker is present in the exact managed method identity from global-metadata.dat.",\n                                "methodIndex=${method.index}, params=${method.parameterCount}, token=0x${method.token.toString(16)}",\n                            ),\n''',
        '''                            evidence = buildList {\n                                add("Semantic marker is present in the exact managed method identity from global-metadata.dat.")\n                                add("methodIndex=${method.index}, params=${method.parameterCount}, token=0x${method.token.toString(16)}")\n                                nativeEvidenceByMethod[method.index]?.let { native ->\n                                    add("Native correlation ${native.verdict}: ${native.nativeFunctionName ?: "<unnamed>"} · ${native.sourceEvidence ?: "unknown source"} (${native.sourceConfidence ?: "unknown"}).")\n                                    native.evidence.take(2).forEach(::add)\n                                }\n                            },\n''',
        "mapping exact method native evidence",
    )
    text = replace_once(
        text,
        '''                obfuscated -> add(contextualOrStructural("METHOD", method.index, identity, context))\n''',
        '''                obfuscated -> add(\n                    contextualOrStructural(\n                        "METHOD",\n                        method.index,\n                        identity,\n                        context,\n                        nativeEvidenceByMethod[method.index]?.let(::nativeEvidenceLines).orEmpty(),\n                    ),\n                )\n''',
        "mapping contextual method native evidence",
    )
    text = replace_once(
        text,
        '''        identity: String,\n        context: TypeContext?,\n    ): Entry {\n''',
        '''        identity: String,\n        context: TypeContext?,\n        extraEvidence: List<String> = emptyList(),\n    ): Entry {\n''',
        "mapping contextual helper signature",
    )
    text = replace_once(
        text,
        '''                    evidence.take(4).forEach { add("Context evidence: $it") }\n                    add("Treat this as a review candidate, not as a recovered original identifier or confirmed runtime value.")\n''',
        '''                    evidence.take(4).forEach { add("Context evidence: $it") }\n                    extraEvidence.take(4).forEach(::add)\n                    add("Treat this as a review candidate, not as a recovered original identifier or confirmed runtime value.")\n''',
        "mapping contextual helper evidence",
    )
    text = replace_once(
        text,
        '''            evidence = listOf(\n                "Short/opaque managed name suggests obfuscation.",\n                "No unique semantic category could be inferred from metadata context; a stable structural analyst alias was assigned.",\n            ),\n''',
        '''            evidence = buildList {\n                add("Short/opaque managed name suggests obfuscation.")\n                add("No unique semantic category could be inferred from metadata context; a stable structural analyst alias was assigned.")\n                extraEvidence.take(4).forEach(::add)\n            },\n''',
        "mapping structural native evidence",
    )
    helper_anchor = '''    private fun semanticCategories(value: String): Set<String> {\n'''
    helper = '''    private fun nativeEvidenceLines(value: Il2CppNativeEvidenceEngine.MethodEvidence): List<String> = buildList {\n        add("Native correlation ${value.verdict}: ${value.nativeFunctionName ?: "<unnamed>"} · ${value.sourceEvidence ?: "unknown source"} (${value.sourceConfidence ?: "unknown"}).")\n        value.evidence.take(2).forEach(::add)\n    }\n\n    private fun semanticCategories(value: String): Set<String> {\n'''
    text = replace_once(text, helper_anchor, helper, "mapping native evidence helper")
    MAPPING.write_text(text, encoding="utf-8")


def patch_dump() -> None:
    text = DUMP.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''        val analystMapping = Il2CppSemanticMappingEngine.analyze(report)\n        val correlations = report.correlations?.il2cppMethods.orEmpty().groupBy { it.methodIndex }\n''',
        '''        val nativeEvidence = Il2CppNativeEvidenceEngine.analyze(report)\n        val nativeEvidenceByMethod = nativeEvidence.methods.associateBy { it.methodIndex }\n        val analystMapping = Il2CppSemanticMappingEngine.analyze(report)\n''',
        "dump native evidence index",
    )
    text = replace_once(
        text,
        '''                        correlations[method.index].orEmpty().firstOrNull { it.functionName.isNotBlank() }?.let { correlation ->\n                            append(" native=").append(sanitize(correlation.functionName))\n                            append(" confidence=").append(sanitize(correlation.confidence))\n                        }\n''',
        '''                        nativeEvidenceByMethod[method.index]?.takeIf { evidence ->\n                            evidence.verdict != Il2CppNativeEvidenceEngine.Verdict.CONFLICTING &&\n                                !evidence.nativeFunctionName.isNullOrBlank()\n                        }?.let { correlation ->\n                            append(" native=").append(sanitize(correlation.nativeFunctionName.orEmpty()))\n                            append(" nativeVerdict=").append(correlation.verdict)\n                            append(" nativeEvidence=").append(sanitize(correlation.sourceEvidence.orEmpty()))\n                            append(" nativeConfidence=").append(sanitize(correlation.sourceConfidence.orEmpty()))\n                        }\n''',
        "dump validated native correlation",
    )
    text = replace_once(
        text,
        '''            appendLine("# Native correlations list names only; no patch offsets are emitted.")\n''',
        '''            appendLine("# Native correlations are identity/token validated before display; no patch offsets are emitted.")\n            appendLine("# native_evidence_available=${nativeEvidence.correlationDataAvailable} verified=${nativeEvidence.verified} supported=${nativeEvidence.supported} weak=${nativeEvidence.weak} conflicting=${nativeEvidence.conflicting}")\n''',
        "dump native evidence header",
    )
    DUMP.write_text(text, encoding="utf-8")


def patch_pair() -> None:
    text = PAIR.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''        val risk: Il2CppMonetizationRiskEngine.Result,\n        val mapping: Il2CppSemanticMappingEngine.Result,\n''',
        '''        val risk: Il2CppMonetizationRiskEngine.Result,\n        val mapping: Il2CppSemanticMappingEngine.Result,\n        val nativeEvidence: Il2CppNativeEvidenceEngine.Result,\n''',
        "pair native evidence result",
    )
    text = replace_once(
        text,
        '''        val mapping = Il2CppSemanticMappingEngine.analyze(report)\n        val risk = Il2CppMonetizationRiskEngine.analyze(report)\n''',
        '''        val nativeEvidence = Il2CppNativeEvidenceEngine.analyze(report)\n        val mapping = Il2CppSemanticMappingEngine.analyze(report)\n        val risk = Il2CppMonetizationRiskEngine.analyze(report)\n''',
        "pair native evidence computation",
    )
    text = replace_once(
        text,
        '''            if (mapping.contextualMappings > 0) add("${mapping.contextualMappings} obfuscated symbols received contextual semantic aliases for review.")\n            add("Pair matching is assumed from the supplied files unless independent build/provenance evidence is available.")\n''',
        '''            if (mapping.contextualMappings > 0) add("${mapping.contextualMappings} obfuscated symbols received contextual semantic aliases for review.")\n            if (!nativeEvidence.correlationDataAvailable) add("Pair-only scan has no external Ghidra correlation dataset; native identity verification becomes available in the full APK audit.")\n            if (nativeEvidence.conflicting > 0) add("${nativeEvidence.conflicting} IL2CPP method correlation(s) conflict with canonical metadata identity/token evidence and were not trusted.")\n            add("Pair matching is assumed from the supplied files unless independent build/provenance evidence is available.")\n''',
        "pair native evidence warnings",
    )
    text = replace_once(
        text,
        '''            risk = risk,\n            mapping = mapping,\n            managedDump = Il2CppManagedDumpExporter.export(report),\n''',
        '''            risk = risk,\n            mapping = mapping,\n            nativeEvidence = nativeEvidence,\n            managedDump = Il2CppManagedDumpExporter.export(report),\n''',
        "pair native evidence assignment",
    )
    PAIR.write_text(text, encoding="utf-8")


def patch_ui() -> None:
    text = UI.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''            Text("Native correlations ${risk.nativeCorrelations} · coverage ${if (risk.coverageComplete) "COMPLETE" else "PARTIAL"}")\n            Text("Obfuscation ${current.mapping.obfuscationScore}/100 · suspected ${current.mapping.suspectedSymbols} · mapped ${current.mapping.mappedSymbols}")\n''',
        '''            Text("Native correlations ${risk.nativeCorrelations} · coverage ${if (risk.coverageComplete) "COMPLETE" else "PARTIAL"}")\n            Text("Native evidence: verified ${current.nativeEvidence.verified} · supported ${current.nativeEvidence.supported} · weak ${current.nativeEvidence.weak} · conflicting ${current.nativeEvidence.conflicting}")\n            if (!current.nativeEvidence.correlationDataAvailable) {\n                Text("Ghidra/native correlation dataset: not available in pair-only mode", style = MaterialTheme.typography.bodySmall)\n            }\n            Text("Obfuscation ${current.mapping.obfuscationScore}/100 · suspected ${current.mapping.suspectedSymbols} · mapped ${current.mapping.mappedSymbols}")\n''',
        "pair UI native evidence metrics",
    )
    UI.write_text(text, encoding="utf-8")


def patch_models() -> None:
    text = MODELS.read_text(encoding="utf-8")
    text = text.replace(
        "No mapping is emitted from ordering assumptions alone. A result requires either an explicit\n * metadata token literal in a recovered function identity or a unique type+method identity match.",
        "No mapping is emitted from ordering assumptions alone. A result requires evidence such as a\n * validated codegen-module token slot, explicit metadata-token identity, or unique type+method match.",
        1,
    )
    MODELS.write_text(text, encoding="utf-8")


def patch_build() -> None:
    text = BUILD.read_text(encoding="utf-8")
    text = text.replace("versionCode = 45", "versionCode = 46")
    text = text.replace('versionName = "0.34.0-preview-il2cpp-semantic"', 'versionName = "0.35.0-preview-il2cpp-native-evidence"')
    if "versionCode = 46" not in text or 'versionName = "0.35.0-preview-il2cpp-native-evidence"' not in text:
        raise RuntimeError("v0.35 version update failed")
    BUILD.write_text(text, encoding="utf-8")


def main() -> None:
    patch_risk()
    patch_mapping()
    patch_dump()
    patch_pair()
    patch_ui()
    patch_models()
    patch_build()
    print("v0.35.0 IL2CPP native evidence integration applied")


if __name__ == "__main__":
    main()
