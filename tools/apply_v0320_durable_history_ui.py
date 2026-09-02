#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "app/src/main/java/org/unirevlab/security/MainActivity.kt"
BUILD = ROOT / "app/build.gradle.kts"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def patch_main() -> None:
    text = MAIN.read_text(encoding="utf-8")

    old_init = '''    val historyStore = remember { AssessmentHistoryStore(context.applicationContext) }
    remember(context.applicationContext) { AnalysisManager.apply { initialize(context.applicationContext) } }
    val analysisState by AnalysisManager.state.collectAsState()
    val analysisActive = analysisState is AnalysisRunState.Running || analysisState is AnalysisRunState.Cancelling
    var route by remember { mutableStateOf(if (agreementStore.isAccepted()) Route.SCOPE else Route.AGREEMENT) }
'''
    new_init = '''    val historyStore = remember { AssessmentHistoryStore(context.applicationContext) }
    val initialHistory = remember { historyStore.list() }
    remember(context.applicationContext) { AnalysisManager.apply { initialize(context.applicationContext) } }
    val analysisState by AnalysisManager.state.collectAsState()
    val analysisActive = analysisState is AnalysisRunState.Running || analysisState is AnalysisRunState.Cancelling
    var route by remember {
        mutableStateOf(
            when {
                !agreementStore.isAccepted() -> Route.AGREEMENT
                initialHistory.isNotEmpty() -> Route.PROJECTS
                else -> Route.SCOPE
            },
        )
    }
'''
    text = replace_once(text, old_init, new_init, "history-aware startup")
    text = text.replace(
        "    var historyEntries by remember { mutableStateOf(historyStore.list()) }\n",
        "    var historyEntries by remember { mutableStateOf(initialHistory) }\n",
        1,
    )

    old_completed = '''                scope = next.assessment
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
'''
    new_completed = '''                scope = next.assessment
                val savedHistory = withContext(Dispatchers.IO) {
                    Triple(historyStore.list(), historyStore.baselineEntryIds(), historyStore.compare(next))
                }
                historyEntries = savedHistory.first
                baselineEntryIds = savedHistory.second
                baselineComparison = savedHistory.third
                preparedReportExport?.file?.let { runCatching { it.delete() } }
                preparedReportExport = null
                reportExportStatus = null
                report = next
                error = state.historyPersistError?.let { "Анализ завершён, но полный отчёт не удалось сохранить в историю: $it" }
'''
    text = replace_once(text, old_completed, new_completed, "manager-owned history persistence")

    old_back = '''    BackHandler(
        enabled = route in setOf(Route.TOOL, Route.DASHBOARD, Route.PROJECTS, Route.INSTALLED_APPS, Route.HELP, Route.PATCH_LAB),
    ) {
        route = Route.HOME
    }
'''
    new_back = '''    BackHandler(
        enabled = route in setOf(Route.TOOL, Route.DASHBOARD, Route.PROJECTS, Route.INSTALLED_APPS, Route.HELP, Route.PATCH_LAB),
    ) {
        route = if (route == Route.PROJECTS && scope == null) Route.SCOPE else Route.HOME
    }
'''
    text = replace_once(text, old_back, new_back, "history back navigation")

    old_projects = '''        Route.PROJECTS -> ProjectHistoryScreen(
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
'''
    new_projects = '''        Route.PROJECTS -> ProjectHistoryScreen(
            entries = historyEntries,
            baselineEntryIds = baselineEntryIds,
            currentReport = report,
            currentComparison = baselineComparison,
            isLoadingReport = isInspecting,
            onBack = { route = if (scope == null) Route.SCOPE else Route.HOME },
            onOpen = { entryId ->
                if (!isInspecting) {
                    coroutineScope.launch {
                        isInspecting = true
                        error = null
                        val result = runCatching {
                            withContext(Dispatchers.IO) {
                                val loaded = historyStore.loadReport(entryId)
                                loaded to historyStore.compare(loaded)
                            }
                        }
                        result.getOrNull()?.let { (loaded, loadedBaseline) ->
                            scope = loaded.assessment
                            report = loaded
                            previousReport = null
                            comparison = null
                            baselineComparison = loadedBaseline
                            selectedTool = null
                            patchFinding = null
                            lastArtifactUri = null
                            lastInstalledApp = null
                            preparedReportExport?.file?.let { runCatching { it.delete() } }
                            preparedReportExport = null
                            reportExportStatus = null
                            route = Route.HOME
                        }
                        result.exceptionOrNull()?.let { failure ->
                            error = "Не удалось открыть сохранённый анализ: ${failure.message ?: failure.javaClass.simpleName}"
                        }
                        isInspecting = false
                    }
                }
            },
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
'''
    text = replace_once(text, old_projects, new_projects, "reopen history report")

    MAIN.write_text(text, encoding="utf-8")


def patch_build() -> None:
    text = BUILD.read_text(encoding="utf-8")
    for old_code in ("versionCode = 41", "versionCode = 42"):
        text = text.replace(old_code, "versionCode = 43")
    for old_name in (
        'versionName = "0.30.0-preview-full-mapping"',
        'versionName = "0.31.0-preview-semantic-recovery"',
    ):
        text = text.replace(old_name, 'versionName = "0.32.0-preview-durable-history"')
    if 'versionCode = 43' not in text or 'versionName = "0.32.0-preview-durable-history"' not in text:
        raise RuntimeError("v0.32 version update failed")
    BUILD.write_text(text, encoding="utf-8")


def main() -> None:
    patch_main()
    patch_build()
    print("v0.32.0 durable history UI/reopen migration applied")


if __name__ == "__main__":
    main()
