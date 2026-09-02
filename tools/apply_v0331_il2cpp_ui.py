#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"
MAIN = ROOT / "app/src/main/java/org/unirevlab/security/MainActivity.kt"
INSPECTOR = ROOT / "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def patch_product() -> None:
    text = PRODUCT.read_text(encoding="utf-8")

    old_param = '''    onOpenProjects: () -> Unit,\n    onCancelAnalysis: () -> Unit,\n'''
    new_param = '''    onOpenProjects: () -> Unit,\n    onOpenIl2CppPair: () -> Unit,\n    onCancelAnalysis: () -> Unit,\n'''
    text = replace_once(text, old_param, new_param, "ToolsHome IL2CPP callback")

    audit_anchor = '''            FullAuditHero(\n                report = report,\n                analysisState = analysisState,\n                isInspecting = isInspecting,\n                onAnalyzeFile = onAnalyzeFile,\n                onAnalyzeInstalled = onAnalyzeInstalled,\n                onCancel = onCancelAnalysis,\n            )\n\n'''
    audit_with_pair = audit_anchor + '''            Card(\n                shape = RoundedCornerShape(20.dp),\n                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),\n            ) {\n                Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {\n                    Text("IL2CPP Dump / Metadata", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)\n                    Text(\n                        "Есть отдельно global-metadata.dat + libil2cpp.so? Откройте pair workspace без предварительного APK-аудита: managed dump, types/methods/fields и monetization attack surface.",\n                        style = MaterialTheme.typography.bodySmall,\n                    )\n                    OutlinedButton(onClick = onOpenIl2CppPair, enabled = !isInspecting, modifier = Modifier.fillMaxWidth()) {\n                        Text("Открыть IL2CPP pair workspace")\n                    }\n                }\n            }\n\n'''
    text = replace_once(text, audit_anchor, audit_with_pair, "IL2CPP pair home card")

    old_runtime = '''@Composable\nprivate fun RuntimeToolPanel(report: StaticAnalysisReport) {\n    val profiles = report.runtimes?.profiles.orEmpty()\n    MetricCard("Runtime profiles", profiles.size.toString())\n    profiles.forEach { InfoCard("${it.kind} · ${it.confidence}\\n${it.indicators.take(8).joinToString()}") }\n    report.il2cpp?.let { MetricCard("IL2CPP", "detected=${it.detected} · confidence=${it.confidence} · libs=${it.libil2cppLibraries.size}") }\n    report.runtimeArtifacts?.flutter?.let { MetricCard("Flutter", "detected=${it.detected} · confidence=${it.confidence}") }\n    report.runtimeArtifacts?.hermes?.let { MetricCard("Hermes", "detected=${it.detected} · confidence=${it.confidence} · bytecode=${it.bytecodeFiles.size}") }\n    report.runtimeArtifacts?.unityMono?.let { MetricCard("Unity Mono", "detected=${it.detected} · confidence=${it.confidence} · assemblies=${it.assemblies.size}") }\n    report.runtimeArtifacts?.unreal?.let { MetricCard("Unreal", "detected=${it.detected} · confidence=${it.confidence} · containers=${it.containers.size}") }\n}\n'''
    new_runtime = '''@Composable\nprivate fun RuntimeToolPanel(report: StaticAnalysisReport) {\n    val profiles = report.runtimes?.profiles.orEmpty()\n    MetricCard("Runtime profiles", profiles.size.toString())\n    profiles.forEach { InfoCard("${it.kind} · ${it.confidence}\\n${it.indicators.take(8).joinToString()}") }\n    report.il2cpp?.let { il2cpp ->\n        MetricCard("IL2CPP", "detected=${il2cpp.detected} · confidence=${il2cpp.confidence} · libs=${il2cpp.libil2cppLibraries.size}")\n        il2cpp.metadata?.let { metadata ->\n            MetricCard("IL2CPP managed metadata", "v${metadata.metadataVersion ?: "?"} · types ${metadata.typeDefinitions.size} · methods ${metadata.methodDefinitions.size} · fields ${metadata.fieldDefinitions.size}")\n        }\n        val risk = remember(report.artifact.sha256, report.correlations?.il2cppMethods?.size) {\n            org.unirevlab.security.analysis.Il2CppMonetizationRiskEngine.analyze(report)\n        }\n        MetricCard(\n            "Monetization attack surface",\n            "${risk.posture} · candidates ${risk.candidates.size} · client-state ${risk.clientStateCandidates} · validation ${risk.validationCandidates}",\n        )\n        risk.candidates.take(40).forEach { candidate ->\n            InfoCard(\n                "${candidate.category} · ${candidate.kind} · ${candidate.confidence}\\n${candidate.managedIdentity}" +\n                    (candidate.nativeFunctionName?.let { "\\nNative correlation: $it" } ?: "") +\n                    (candidate.metadataToken?.let { "\\nmetadata token 0x${it.toString(16)}" } ?: ""),\n            )\n        }\n        risk.recommendations.take(5).forEach { InfoCard("Hardening: $it") }\n    }\n    report.runtimeArtifacts?.flutter?.let { MetricCard("Flutter", "detected=${it.detected} · confidence=${it.confidence}") }\n    report.runtimeArtifacts?.hermes?.let { MetricCard("Hermes", "detected=${it.detected} · confidence=${it.confidence} · bytecode=${it.bytecodeFiles.size}") }\n    report.runtimeArtifacts?.unityMono?.let { MetricCard("Unity Mono", "detected=${it.detected} · confidence=${it.confidence} · assemblies=${it.assemblies.size}") }\n    report.runtimeArtifacts?.unreal?.let { MetricCard("Unreal", "detected=${it.detected} · confidence=${it.confidence} · containers=${it.containers.size}") }\n}\n'''
    text = replace_once(text, old_runtime, new_runtime, "Runtime IL2CPP risk panel")
    PRODUCT.write_text(text, encoding="utf-8")


def patch_main() -> None:
    text = MAIN.read_text(encoding="utf-8")
    if "import org.unirevlab.security.ui.Il2CppPairWorkspaceScreen" not in text:
        anchor = "import org.unirevlab.security.ui.InstalledAppsScreen\n"
        if anchor not in text:
            raise RuntimeError("MainActivity: UI import anchor missing")
        text = text.replace(anchor, anchor + "import org.unirevlab.security.ui.Il2CppPairWorkspaceScreen\n", 1)

    text = text.replace(
        "private enum class Route { AGREEMENT, SCOPE, HOME, TOOL, DASHBOARD, PROJECTS, INSTALLED_APPS, HELP, PATCH_LAB }",
        "private enum class Route { AGREEMENT, SCOPE, HOME, TOOL, DASHBOARD, PROJECTS, IL2CPP_PAIR, INSTALLED_APPS, HELP, PATCH_LAB }",
        1,
    )

    text = text.replace(
        "route in setOf(Route.TOOL, Route.DASHBOARD, Route.PROJECTS, Route.INSTALLED_APPS, Route.HELP, Route.PATCH_LAB)",
        "route in setOf(Route.TOOL, Route.DASHBOARD, Route.PROJECTS, Route.IL2CPP_PAIR, Route.INSTALLED_APPS, Route.HELP, Route.PATCH_LAB)",
        1,
    )

    tools_anchor = '''            onOpenHelp = { route = Route.HELP },\n            onOpenProjects = { route = Route.PROJECTS },\n            onCancelAnalysis = { AnalysisManager.cancel() },\n'''
    tools_new = '''            onOpenHelp = { route = Route.HELP },\n            onOpenProjects = { route = Route.PROJECTS },\n            onOpenIl2CppPair = { route = Route.IL2CPP_PAIR },\n            onCancelAnalysis = { AnalysisManager.cancel() },\n'''
    text = replace_once(text, tools_anchor, tools_new, "Main ToolsHome IL2CPP callback")

    route_anchor = '''        Route.HELP -> HelpScreen(onBack = { route = Route.HOME })\n'''
    route_new = '''        Route.IL2CPP_PAIR -> Il2CppPairWorkspaceScreen(\n            scope = scope ?: AssessmentScope(\n                projectName = "IL2CPP dump review",\n                organization = "Local authorized assessment",\n                purpose = "Defensive IL2CPP dump analysis",\n                confirmsAuthority = true,\n            ),\n            onBack = { route = if (scope == null) Route.SCOPE else Route.HOME },\n        )\n        Route.HELP -> HelpScreen(onBack = { route = Route.HOME })\n'''
    text = replace_once(text, route_anchor, route_new, "Main IL2CPP route")
    MAIN.write_text(text, encoding="utf-8")


def patch_engine_version() -> None:
    text = INSPECTOR.read_text(encoding="utf-8")
    old = 'const val ENGINE_VERSION = "0.25.8-dev-apkset-sources"'
    new = 'const val ENGINE_VERSION = "0.33.0-il2cpp-fields"'
    if old in text:
        text = text.replace(old, new, 1)
    elif new not in text:
        raise RuntimeError("LocalArtifactInspector ENGINE_VERSION anchor missing")
    INSPECTOR.write_text(text, encoding="utf-8")


def main() -> None:
    patch_product()
    patch_main()
    patch_engine_version()
    print("v0.33 IL2CPP pair workspace UI applied")


if __name__ == "__main__":
    main()
