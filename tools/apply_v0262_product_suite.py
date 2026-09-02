#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "app/src/main/java/org/unirevlab/security/MainActivity.kt"
AUTOMOD = ROOT / "app/src/main/java/org/unirevlab/security/analysis/AutoModEngine.kt"
AUTOMOD_PANEL = ROOT / "app/src/main/java/org/unirevlab/security/ui/AutoModPanel.kt"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"{label}: expected source block not found")
    return text.replace(old, new, 1)


def insert_after(text: str, anchor: str, addition: str, label: str) -> str:
    if addition.strip() in text:
        return text
    if anchor not in text:
        raise RuntimeError(f"{label}: anchor not found")
    return text.replace(anchor, anchor + addition, 1)


def patch_main_activity() -> bool:
    text = MAIN.read_text(encoding="utf-8")
    original = text

    text = insert_after(
        text,
        "import androidx.activity.compose.rememberLauncherForActivityResult\n",
        "import androidx.activity.compose.BackHandler\n",
        "MainActivity BackHandler import",
    )
    text = insert_after(
        text,
        "import org.unirevlab.security.ui.PatchLabScreen\n",
        "import org.unirevlab.security.ui.ProductTool\n"
        "import org.unirevlab.security.ui.ProductToolScreen\n"
        "import org.unirevlab.security.ui.ToolsHomeScreen\n",
        "MainActivity product UI imports",
    )
    text = replace_once(
        text,
        "private enum class Route { AGREEMENT, SCOPE, DASHBOARD, INSTALLED_APPS, HELP, PATCH_LAB }",
        "private enum class Route { AGREEMENT, SCOPE, HOME, TOOL, DASHBOARD, INSTALLED_APPS, HELP, PATCH_LAB }",
        "MainActivity routes",
    )
    text = insert_after(
        text,
        "    var patchFinding by remember { mutableStateOf<Finding?>(null) }\n",
        "    var selectedTool by remember { mutableStateOf<ProductTool?>(null) }\n",
        "MainActivity selected tool state",
    )

    marker = "    LaunchedEffect(analysisState) {"
    end_marker = "    fun reloadInstalledApps() {"
    if marker in text and end_marker in text:
        start = text.index(marker)
        end = text.index(end_marker, start)
        segment = text[start:end]
        segment_new = segment.replace("route = Route.DASHBOARD", "route = Route.HOME")
        text = text[:start] + segment_new + text[end:]

    text = replace_once(
        text,
        "        Route.SCOPE -> AssessmentScreen { created ->\n"
        "            scope = created\n"
        "            report = null\n"
        "            previousReport = null\n"
        "            comparison = null\n"
        "            route = Route.DASHBOARD\n"
        "        }",
        "        Route.SCOPE -> AssessmentScreen { created ->\n"
        "            scope = created\n"
        "            report = null\n"
        "            previousReport = null\n"
        "            comparison = null\n"
        "            selectedTool = null\n"
        "            route = Route.HOME\n"
        "        }",
        "Assessment -> product home",
    )

    back_handler = (
        "    BackHandler(\n"
        "        enabled = route in setOf(Route.TOOL, Route.DASHBOARD, Route.INSTALLED_APPS, Route.HELP, Route.PATCH_LAB),\n"
        "    ) {\n"
        "        route = Route.HOME\n"
        "    }\n\n"
    )
    if "enabled = route in setOf(Route.TOOL" not in text:
        text = replace_once(text, "    when (route) {\n", back_handler + "    when (route) {\n", "Back navigation to tools home")

    home_cases = '''        Route.HOME -> ToolsHomeScreen(
            scope = requireNotNull(scope),
            report = report,
            analysisState = analysisState,
            isInspecting = isInspecting || analysisActive,
            error = error,
            onAnalyzeFile = {
                picker.launch(arrayOf(
                    "application/vnd.android.package-archive",
                    "application/zip",
                    "application/octet-stream",
                ))
            },
            onAnalyzeInstalled = {
                route = Route.INSTALLED_APPS
                if (installedApps.isEmpty()) reloadInstalledApps()
            },
            onOpenTool = { tool ->
                selectedTool = tool
                route = Route.TOOL
            },
            onOpenFullReport = { route = Route.DASHBOARD },
            onOpenPatchLab = {
                patchFinding = null
                route = Route.PATCH_LAB
            },
            onOpenHelp = { route = Route.HELP },
            onCancelAnalysis = { AnalysisManager.cancel() },
            onNewAssessment = {
                if (!analysisActive) {
                    scope = null
                    report = null
                    previousReport = null
                    comparison = null
                    selectedTool = null
                    coordinatorSyncStatus = null
                    preparedReportExport?.file?.let { runCatching { it.delete() } }
                    preparedReportExport = null
                    reportExportStatus = null
                    route = Route.SCOPE
                }
            },
        )
        Route.TOOL -> {
            val current = report
            val tool = selectedTool
            if (current != null && tool != null) {
                ProductToolScreen(
                    report = current,
                    tool = tool,
                    onBack = { route = Route.HOME },
                    onOpenPatchLab = {
                        patchFinding = null
                        route = Route.PATCH_LAB
                    },
                    onOpenFullReport = { route = Route.DASHBOARD },
                )
            } else {
                LaunchedEffect(Unit) { route = Route.HOME }
            }
        }
'''
    if "Route.HOME -> ToolsHomeScreen(" not in text:
        text = replace_once(
            text,
            "        Route.DASHBOARD -> DashboardScreen(\n",
            home_cases + "        Route.DASHBOARD -> DashboardScreen(\n",
            "Product home route cases",
        )

    text = text.replace(
        "        Route.HELP -> HelpScreen(onBack = { route = Route.DASHBOARD })",
        "        Route.HELP -> HelpScreen(onBack = { route = Route.HOME })",
    )
    text = text.replace(
        "            if (currentReport == null) {\n                route = Route.DASHBOARD",
        "            if (currentReport == null) {\n                route = Route.HOME",
    )
    text = text.replace("onBack = { route = Route.DASHBOARD },", "onBack = { route = Route.HOME },")
    text = text.replace(
        "                        route = Route.DASHBOARD\n                        requestAnalysisNotificationPermission()",
        "                        route = Route.HOME\n                        requestAnalysisNotificationPermission()",
    )
    text = text.replace(
        "            onSelect = { app ->\n                route = Route.DASHBOARD",
        "            onSelect = { app ->\n                route = Route.HOME",
    )

    if text != original:
        MAIN.write_text(text, encoding="utf-8")
        return True
    return False


def patch_automod() -> bool:
    text = AUTOMOD.read_text(encoding="utf-8")
    original = text

    guard = (
        "        val genericMethod = methodName.lowercase(Locale.ROOT) in GENERIC_METHOD_NAMES || methodName.length <= 2\n"
        "        if (genericMethod && category in BEHAVIOR_MUTATION_CATEGORIES) return null\n"
    )
    text = insert_after(
        text,
        "        val evidenceBacked = evidenceTokens.isNotEmpty() && baseScore >= 42\n",
        guard,
        "AutoMod ambiguous method guard",
    )
    text = text.replace(
        "val signal = ENTITLEMENT_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }",
        "val signal = ENTITLEMENT_BOOLEAN_MARKERS.any { marker -> marker in methodTokens || methodCompact.contains(marker) }",
    )
    text = text.replace(
        "val signal = FEATURE_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }",
        "val signal = FEATURE_BOOLEAN_MARKERS.any { marker -> marker in methodTokens || methodCompact.contains(marker) }",
    )
    text = text.replace(
        "val signal = INTEGRITY_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }",
        "val signal = INTEGRITY_BOOLEAN_MARKERS.any { marker -> marker in methodTokens || methodCompact.contains(marker) }",
    )
    text = text.replace(
        "val signal = LOCAL_BOOLEAN_MARKERS.any { marker -> marker in tokens || compact.contains(marker) }",
        "val signal = LOCAL_BOOLEAN_MARKERS.any { marker -> marker in methodTokens || methodCompact.contains(marker) }",
    )
    text = text.replace(
        "            val selected = LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> term in methodTokens }\n"
        "                ?: LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> term in evidenceTokens }\n"
        "                ?: return null",
        "            val selected = LOCAL_INT_VALUES.entries.firstOrNull { (term, _) -> termInMethod(term, methodTokens, methodCompact) }\n"
        "                ?: return null",
    )

    constants = (
        "    private val GENERIC_METHOD_NAMES = setOf(\n"
        "        \"equals\", \"hashcode\", \"tostring\", \"compareto\", \"clone\", \"invoke\", \"apply\", \"accept\",\n"
        "        \"get\", \"set\", \"run\", \"call\", \"test\", \"create\", \"newinstance\",\n"
        "    )\n"
        "    private val BEHAVIOR_MUTATION_CATEGORIES = setOf(\"ENTITLEMENT_TRUST\", \"LOCAL_STATE\", \"FEATURE_CONFIG\", \"INTEGRITY\")\n"
    )
    if "private val GENERIC_METHOD_NAMES" not in text:
        text = replace_once(
            text,
            "    private val CATEGORY_PRIORITY = listOf(\"ENTITLEMENT_TRUST\", \"LOCAL_STATE\", \"FEATURE_CONFIG\", \"INTEGRITY\")\n",
            constants + "    private val CATEGORY_PRIORITY = listOf(\"ENTITLEMENT_TRUST\", \"LOCAL_STATE\", \"FEATURE_CONFIG\", \"INTEGRITY\")\n",
            "AutoMod generic method constants",
        )

    if text != original:
        AUTOMOD.write_text(text, encoding="utf-8")
        return True
    return False


def patch_automod_panel() -> bool:
    text = AUTOMOD_PANEL.read_text(encoding="utf-8")
    original = text
    text = text.replace(
        '"${action.category} · confidence ${action.confidence}"',
        '"${autoModCategoryLabel(action.category)} · уверенность ${action.confidence}%"',
    )
    text = text.replace(
        "                                Text(action.target, style = MaterialTheme.typography.bodySmall)\n",
        "                                Text(\"Метод: ${action.target}\", style = MaterialTheme.typography.bodySmall)\n",
    )
    helper = '''
private fun autoModCategoryLabel(category: String): String = when (category) {
    "ENTITLEMENT_TRUST" -> "Premium / entitlement gate"
    "FEATURE_CONFIG" -> "Feature flag / config gate"
    "INTEGRITY" -> "Integrity / environment check"
    "LOCAL_STATE" -> "Local state"
    "AUTH_SESSION" -> "Authentication / session"
    else -> category.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() }
}
'''
    if "private fun autoModCategoryLabel" not in text:
        text = text.rstrip() + "\n" + helper
    if text != original:
        AUTOMOD_PANEL.write_text(text, encoding="utf-8")
        return True
    return False


def main() -> None:
    changed = []
    if patch_main_activity(): changed.append(str(MAIN.relative_to(ROOT)))
    if patch_automod(): changed.append(str(AUTOMOD.relative_to(ROOT)))
    if patch_automod_panel(): changed.append(str(AUTOMOD_PANEL.relative_to(ROOT)))
    if changed:
        print("v0.26.2 product suite applied:")
        for item in changed:
            print(f"  - {item}")
    else:
        print("v0.26.2 product suite already present")


if __name__ == "__main__":
    main()
