#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RISK = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppMonetizationRiskEngine.kt"
PAIR = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppPairAssessmentEngine.kt"
DUMP = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppManagedDumpExporter.kt"
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/Il2CppPairWorkspaceScreen.kt"
BUILD = ROOT / "app/build.gradle.kts"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def patch_risk() -> None:
    text = RISK.read_text(encoding="utf-8")
    anchor = '''        val ordered = candidates.values.sortedWith(\n'''
    contextual = '''        val semanticMapping = Il2CppSemanticMappingEngine.analyze(\n            report = report,\n            maxEntries = maxCandidates.coerceAtLeast(0) * 4,\n        )\n        semanticMapping.entries.asSequence()\n            .filter { it.basis == Il2CppSemanticMappingEngine.Basis.CONTEXTUAL && it.semanticCategory != null }\n            .forEach { mapping ->\n                val category = runCatching { Category.valueOf(mapping.semanticCategory!!) }.getOrNull() ?: return@forEach\n                val method = if (mapping.kind == "METHOD") metadata.methodDefinitions.firstOrNull { it.index == mapping.symbolIndex } else null\n                val field = if (mapping.kind == "FIELD") metadata.fieldDefinitions.firstOrNull { it.index == mapping.symbolIndex } else null\n                val type = if (mapping.kind == "TYPE") metadata.typeDefinitions.firstOrNull { it.index == mapping.symbolIndex } else null\n                val native = method?.let { current ->\n                    nativeByMethod[current.index].orEmpty().firstOrNull { it.functionName.isNotBlank() }\n                }\n                add(\n                    Candidate(\n                        kind = "CONTEXT_${mapping.kind}",\n                        managedIdentity = mapping.originalIdentity,\n                        category = category,\n                        confidence = when (mapping.confidence) {\n                            Il2CppSemanticMappingEngine.Confidence.HIGH -> Confidence.HIGH\n                            Il2CppSemanticMappingEngine.Confidence.MEDIUM -> Confidence.MEDIUM\n                            Il2CppSemanticMappingEngine.Confidence.LOW -> Confidence.LOW\n                        },\n                        metadataToken = method?.token ?: field?.token ?: type?.token,\n                        methodIndex = method?.index,\n                        declaringType = method?.declaringType ?: field?.declaringType ?: type?.fullName,\n                        nativeFunctionName = native?.functionName,\n                        evidence = mapping.evidence + listOf(\n                            "Contextual analyst alias: ${mapping.alias}",\n                            "This candidate is inferred from enclosing metadata context and does not prove a live premium value or authorization result.",\n                        ),\n                    ),\n                )\n            }\n\n        val ordered = candidates.values.sortedWith(\n'''
    text = replace_once(text, anchor, contextual, "contextual IL2CPP candidates")
    RISK.write_text(text, encoding="utf-8")


def patch_pair() -> None:
    text = PAIR.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''        val risk: Il2CppMonetizationRiskEngine.Result,\n        val managedDump: String,\n''',
        '''        val risk: Il2CppMonetizationRiskEngine.Result,\n        val mapping: Il2CppSemanticMappingEngine.Result,\n        val managedDump: String,\n''',
        "pair result mapping field",
    )
    text = replace_once(
        text,
        '''        val risk = Il2CppMonetizationRiskEngine.analyze(report)\n        val warnings = buildList {\n''',
        '''        val mapping = Il2CppSemanticMappingEngine.analyze(report)\n        val risk = Il2CppMonetizationRiskEngine.analyze(report)\n        val warnings = buildList {\n''',
        "pair semantic mapping computation",
    )
    text = replace_once(
        text,
        '''            if (pair.il2cpp.metadata?.metadataVersion !in 27..31) add("Structured type/method/field reconstruction is currently optimized for metadata versions 27-31.")\n            add("Pair matching is assumed from the supplied files unless independent build/provenance evidence is available.")\n''',
        '''            if (pair.il2cpp.metadata?.metadataVersion !in 27..31) add("Structured type/method/field reconstruction is currently optimized for metadata versions 27-31.")\n            if (mapping.likelyObfuscated) add("Managed metadata appears obfuscated (score ${mapping.obfuscationScore}/100); contextual aliases are analyst hypotheses, not recovered source names.")\n            if (mapping.contextualMappings > 0) add("${mapping.contextualMappings} obfuscated symbols received contextual semantic aliases for review.")\n            add("Pair matching is assumed from the supplied files unless independent build/provenance evidence is available.")\n''',
        "pair mapping warnings",
    )
    text = replace_once(
        text,
        '''            risk = risk,\n            managedDump = Il2CppManagedDumpExporter.export(report),\n''',
        '''            risk = risk,\n            mapping = mapping,\n            managedDump = Il2CppManagedDumpExporter.export(report),\n''',
        "pair result mapping assignment",
    )
    PAIR.write_text(text, encoding="utf-8")


def patch_dump() -> None:
    text = DUMP.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''        val correlations = report.correlations?.il2cppMethods.orEmpty().groupBy { it.methodIndex }\n''',
        '''        val analystMapping = Il2CppSemanticMappingEngine.analyze(report)\n        val correlations = report.correlations?.il2cppMethods.orEmpty().groupBy { it.methodIndex }\n''',
        "dump mapping computation",
    )
    text = replace_once(
        text,
        '''            if (emittedMethods < metadata.methodDefinitions.size) {\n                appendLine("# methods_truncated=true emitted=$emittedMethods")\n            }\n''',
        '''            if (emittedMethods < metadata.methodDefinitions.size) {\n                appendLine("# methods_truncated=true emitted=$emittedMethods")\n            }\n            appendLine()\n            appendLine("# ---- IL2CPP ANALYST MAPPING ----")\n            append(analystMapping.mappingText)\n''',
        "dump mapping section",
    )
    DUMP.write_text(text, encoding="utf-8")


def patch_ui() -> None:
    text = UI.read_text(encoding="utf-8")
    text = text.replace(
        "восстанавливает managed types/methods/fields, строит безопасный dump и выделяет premium / entitlement / subscription / IAP / receipt-validation attack surface.",
        "восстанавливает managed types/methods/fields, оценивает обфускацию, строит analyst mapping и выделяет premium / entitlement / subscription / IAP / receipt-validation attack surface.",
        1,
    )
    text = replace_once(
        text,
        '''                if (filtered.size > 150) {\n                    Text("На экране показаны первые 150; полный managed dump сохраняется отдельно.", style = MaterialTheme.typography.bodySmall)\n                }\n''',
        '''                if (filtered.size > 150) {\n                    Text("На экране показаны первые 150; полный managed dump сохраняется отдельно.", style = MaterialTheme.typography.bodySmall)\n                }\n\n                HorizontalDivider()\n                Text("IL2CPP analyst mapping", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)\n                Text(\n                    "Aliases помогают навигации по обфусцированной metadata. CONTEXTUAL — гипотеза по контексту типа; STRUCTURAL — нейтральное имя без семантического утверждения.",\n                    style = MaterialTheme.typography.bodySmall,\n                )\n                val mapped = current.mapping.entries.filter { entry ->\n                    query.isBlank() || entry.originalIdentity.contains(query, ignoreCase = true) ||\n                        entry.alias.contains(query, ignoreCase = true) ||\n                        entry.semanticCategory?.contains(query, ignoreCase = true) == true ||\n                        entry.basis.name.contains(query, ignoreCase = true)\n                }\n                Text("Mapping entries: ${mapped.size}/${current.mapping.entries.size}", fontWeight = FontWeight.SemiBold)\n                mapped.take(120).forEach { entry ->\n                    PairInfoCard(\n                        "${entry.basis} · ${entry.confidence} · ${entry.kind} #${entry.symbolIndex}\\n${entry.originalIdentity}\\n→ ${entry.alias}${entry.semanticCategory?.let { " · $it" } ?: ""}",\n                    )\n                }\n                if (mapped.size > 120) {\n                    Text("Показаны первые 120 mapping entries; полный mapping включён в сохранённый managed dump.", style = MaterialTheme.typography.bodySmall)\n                }\n''',
        "UI mapping list",
    )
    text = replace_once(
        text,
        '''            Text("Native correlations ${risk.nativeCorrelations} · coverage ${if (risk.coverageComplete) "COMPLETE" else "PARTIAL"}")\n            Text("Pair SHA-256 ${current.aggregateSha256.take(24)}…", style = MaterialTheme.typography.bodySmall)\n''',
        '''            Text("Native correlations ${risk.nativeCorrelations} · coverage ${if (risk.coverageComplete) "COMPLETE" else "PARTIAL"}")\n            Text("Obfuscation ${current.mapping.obfuscationScore}/100 · suspected ${current.mapping.suspectedSymbols} · mapped ${current.mapping.mappedSymbols}")\n            Text("Semantic ${current.mapping.semanticMappings} · contextual ${current.mapping.contextualMappings} · structural ${current.mapping.structuralMappings}", style = MaterialTheme.typography.bodySmall)\n            Text("Pair SHA-256 ${current.aggregateSha256.take(24)}…", style = MaterialTheme.typography.bodySmall)\n''',
        "UI mapping metrics",
    )
    UI.write_text(text, encoding="utf-8")


def patch_build() -> None:
    text = BUILD.read_text(encoding="utf-8")
    text = text.replace("versionCode = 44", "versionCode = 45")
    text = text.replace('versionName = "0.33.0-preview-il2cpp-pair"', 'versionName = "0.34.0-preview-il2cpp-semantic"')
    if "versionCode = 45" not in text or 'versionName = "0.34.0-preview-il2cpp-semantic"' not in text:
        raise RuntimeError("v0.34 version update failed")
    BUILD.write_text(text, encoding="utf-8")


def main() -> None:
    patch_risk()
    patch_pair()
    patch_dump()
    patch_ui()
    patch_build()
    print("v0.34.0 IL2CPP semantic analyst mapping applied")


if __name__ == "__main__":
    main()
