#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "app/src/main/java/org/unirevlab/security/MainActivity.kt"
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def patch_main() -> None:
    text = MAIN.read_text(encoding="utf-8")
    original = text

    if "import org.unirevlab.security.data.AssessmentHistoryStore\n" not in text:
        text = text.replace(
            "import org.unirevlab.security.data.AgreementStore\n",
            "import org.unirevlab.security.data.AgreementStore\nimport org.unirevlab.security.data.AssessmentHistoryStore\n",
            1,
        )
    if "import org.unirevlab.security.model.BaselineComparison\n" not in text:
        text = text.replace(
            "import org.unirevlab.security.model.AssessmentDiff\n",
            "import org.unirevlab.security.model.AssessmentDiff\nimport org.unirevlab.security.model.BaselineComparison\n",
            1,
        )
    if "import org.unirevlab.security.ui.ProjectHistoryScreen\n" not in text:
        text = text.replace(
            "import org.unirevlab.security.ui.ProductToolScreen\n",
            "import org.unirevlab.security.ui.ProductToolScreen\nimport org.unirevlab.security.ui.ProjectHistoryScreen\n",
            1,
        )

    text = text.replace(
        "private enum class Route { AGREEMENT, SCOPE, HOME, TOOL, DASHBOARD, INSTALLED_APPS, HELP, PATCH_LAB }",
        "private enum class Route { AGREEMENT, SCOPE, HOME, TOOL, DASHBOARD, PROJECTS, INSTALLED_APPS, HELP, PATCH_LAB }",
    )

    text = replace_once(
        text,
        "    val installedRepository = remember { InstalledAppRepository(context.applicationContext) }\n",
        "    val installedRepository = remember { InstalledAppRepository(context.applicationContext) }\n"
        "    val historyStore = remember { AssessmentHistoryStore(context.applicationContext) }\n",
        "history store init",
    )

    text = replace_once(
        text,
        "    var comparison by remember { mutableStateOf<AssessmentDiff?>(null) }\n",
        "    var comparison by remember { mutableStateOf<AssessmentDiff?>(null) }\n"
        "    var historyEntries by remember { mutableStateOf(historyStore.list()) }\n"
        "    var baselineEntryIds by remember { mutableStateOf(historyStore.baselineEntryIds()) }\n"
        "    var baselineComparison by remember { mutableStateOf<BaselineComparison?>(null) }\n",
        "history state",
    )

    completion_old = """                scope = next.assessment
                preparedReportExport?.file?.let { runCatching { it.delete() } }
                preparedReportExport = null
                reportExportStatus = null
                report = next
                error = null
"""
    completion_new = """                scope = next.assessment
                val savedHistory = withContext(Dispatchers.IO) {
                    historyStore.record(next)
                    Triple(historyStore.list(), historyStore.baselineEntryIds(), historyStore.compare(next))
                }
                historyEntries = savedHistory.first
                baselineEntryIds = savedHistory.second
                baselineComparison = savedHistory.third
                preparedReportExport?.file?.let { runCatching { it.delete() } }
                preparedReportExport = null
                reportExportStatus = null
                report = next
                error = null
"""
    text = replace_once(text, completion_old, completion_new, "record completed assessment")

    refresh_anchor = """    fun reloadInstalledApps() {
        coroutineScope.launch {
            installedAppsLoading = true
"""
    refresh_block = """    fun refreshHistoryState() {
        historyEntries = historyStore.list()
        baselineEntryIds = historyStore.baselineEntryIds()
        baselineComparison = report?.let { historyStore.compare(it) }
    }

    fun reloadInstalledApps() {
        coroutineScope.launch {
            installedAppsLoading = true
"""
    text = replace_once(text, refresh_anchor, refresh_block, "history refresh helper")

    text = text.replace(
        "enabled = route in setOf(Route.TOOL, Route.DASHBOARD, Route.INSTALLED_APPS, Route.HELP, Route.PATCH_LAB),",
        "enabled = route in setOf(Route.TOOL, Route.DASHBOARD, Route.PROJECTS, Route.INSTALLED_APPS, Route.HELP, Route.PATCH_LAB),",
    )

    text = replace_once(
        text,
        "            error = error,\n            onAnalyzeFile = {",
        "            error = error,\n            baselineComparison = baselineComparison,\n            onAnalyzeFile = {",
        "home baseline argument",
    )
    text = replace_once(
        text,
        "            onOpenHelp = { route = Route.HELP },\n            onCancelAnalysis = { AnalysisManager.cancel() },",
        "            onOpenHelp = { route = Route.HELP },\n            onOpenProjects = { route = Route.PROJECTS },\n            onCancelAnalysis = { AnalysisManager.cancel() },",
        "home history navigation",
    )

    scope_reset = """            comparison = null
            selectedTool = null
            route = Route.HOME
"""
    scope_reset_new = """            comparison = null
            baselineComparison = null
            selectedTool = null
            route = Route.HOME
"""
    text = replace_once(text, scope_reset, scope_reset_new, "scope baseline reset")

    text = text.replace(
        "                    comparison = null\n                    selectedTool = null",
        "                    comparison = null\n                    baselineComparison = null\n                    selectedTool = null",
    )
    text = text.replace(
        "                    comparison = null\n                    coordinatorSyncStatus = null",
        "                    comparison = null\n                    baselineComparison = null\n                    coordinatorSyncStatus = null",
    )

    projects_route = """        Route.PROJECTS -> ProjectHistoryScreen(
            entries = historyEntries,
            baselineEntryIds = baselineEntryIds,
            currentReport = report,
            currentComparison = baselineComparison,
            onBack = { route = Route.HOME },
            onSetBaseline = { entryId ->
                val result = runCatching { historyStore.setBaseline(entryId) }
                error = result.exceptionOrNull()?.message
                if (result.isSuccess) refreshHistoryState()
            },
            onClearBaseline = { packageName ->
                val result = runCatching { historyStore.clearBaseline(packageName) }
                error = result.exceptionOrNull()?.message
                if (result.isSuccess) refreshHistoryState()
            },
            onDelete = { entryId ->
                val result = runCatching { historyStore.remove(entryId) }
                error = result.exceptionOrNull()?.message
                if (result.isSuccess) refreshHistoryState()
            },
        )
"""
    if "Route.PROJECTS -> ProjectHistoryScreen(" not in text:
        marker = "        Route.HELP -> HelpScreen(onBack = { route = Route.HOME })\n"
        if marker not in text:
            raise RuntimeError("projects route: HELP marker not found")
        text = text.replace(marker, projects_route + marker, 1)

    if text != original:
        MAIN.write_text(text, encoding="utf-8")


def patch_ui() -> None:
    text = UI.read_text(encoding="utf-8")
    original = text

    if "import org.unirevlab.security.model.BaselineComparison\n" not in text:
        text = text.replace(
            "import org.unirevlab.security.model.AssessmentScope\n",
            "import org.unirevlab.security.model.AssessmentScope\nimport org.unirevlab.security.model.BaselineComparison\nimport org.unirevlab.security.model.BaselineVerdict\n",
            1,
        )

    text = replace_once(
        text,
        "    error: String?,\n    onAnalyzeFile: () -> Unit,",
        "    error: String?,\n    baselineComparison: BaselineComparison?,\n    onAnalyzeFile: () -> Unit,",
        "home baseline parameter",
    )
    text = replace_once(
        text,
        "    onOpenHelp: () -> Unit,\n    onCancelAnalysis: () -> Unit,",
        "    onOpenHelp: () -> Unit,\n    onOpenProjects: () -> Unit,\n    onCancelAnalysis: () -> Unit,",
        "home projects callback",
    )

    text = replace_once(
        text,
        "            report?.let { current ->\n                LatestAssessmentCard(current)\n                ProtectionSnapshot(current)\n            }",
        "            report?.let { current ->\n                LatestAssessmentCard(current)\n                BaselineSnapshot(baselineComparison)\n                ProtectionSnapshot(current)\n            }",
        "home baseline snapshot",
    )

    text = replace_once(
        text,
        "            HorizontalDivider()\n            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {",
        "            HorizontalDivider()\n            OutlinedButton(onClick = onOpenProjects, modifier = Modifier.fillMaxWidth()) { Text(\"Проекты / История / Baseline\") }\n            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {",
        "history button",
    )

    baseline_panel = r'''@Composable
private fun BaselineSnapshot(comparison: BaselineComparison?) {
    val verdict = comparison?.verdict ?: BaselineVerdict.NO_BASELINE
    val container = when (verdict) {
        BaselineVerdict.SAME_ARTIFACT -> MaterialTheme.colorScheme.primaryContainer
        BaselineVerdict.MODIFIED -> MaterialTheme.colorScheme.tertiaryContainer
        BaselineVerdict.SIGNER_CHANGED -> MaterialTheme.colorScheme.errorContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
    }
    Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = container)) {
        Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Trusted Baseline", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                when (verdict) {
                    BaselineVerdict.NO_BASELINE -> "Baseline не выбран — статус изменения остаётся UNKNOWN."
                    BaselineVerdict.SAME_ARTIFACT -> "SHA-256 совпадает: текущий APK идентичен trusted baseline."
                    BaselineVerdict.MODIFIED -> "SHA-256 отличается: текущий APK изменён относительно trusted baseline."
                    BaselineVerdict.SIGNER_CHANGED -> "APK изменён, и сертификат подписания не совпадает с baseline."
                    BaselineVerdict.NOT_COMPARABLE -> "Baseline относится к другому package и не используется."
                    BaselineVerdict.INCOMPLETE_IDENTITY -> "Недостаточно package identity для надёжного сравнения."
                },
                style = MaterialTheme.typography.bodySmall,
            )
            comparison?.baseline?.let { baseline ->
                Text("${baseline.artifactDisplayName} · ${baseline.artifactSha256.take(16)}…", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
'''
    if "private fun BaselineSnapshot(comparison: BaselineComparison?)" not in text:
        marker = "@Composable\nprivate fun ProtectionSnapshot(report: StaticAnalysisReport) {"
        if marker not in text:
            raise RuntimeError("baseline snapshot: ProtectionSnapshot marker not found")
        text = text.replace(marker, baseline_panel + "\n" + marker, 1)

    if text != original:
        UI.write_text(text, encoding="utf-8")


def main() -> None:
    patch_main()
    patch_ui()
    print("v0.29.0 projects/history + trusted baseline migration applied")


if __name__ == "__main__":
    main()
