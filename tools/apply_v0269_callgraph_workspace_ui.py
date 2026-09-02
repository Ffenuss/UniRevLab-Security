#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "app/src/main/java/org/unirevlab/security/ui/ProductToolsScreen.kt"

OLD = '''@Composable
private fun ReverseEngineeringToolPanel(report: StaticAnalysisReport, onOpenFullReport: () -> Unit) {
    val dex = report.dex
    MetricCard("DEX call xrefs", dex?.callXrefs?.size?.toString() ?: "0")
    MetricCard("Basic blocks", dex?.basicBlocks?.size?.toString() ?: "0")
    MetricCard("Ghidra libraries", report.ghidra.size.toString())
    MetricCard("Cross-runtime correlations", report.correlations?.links?.size?.toString() ?: "0")
    InfoCard("Полный RE Browser, поиск xrefs, CallGraph и импорт Ghidra остаются в техническом отчёте. В следующем UI-шаге RE Browser будет вынесен в собственный полноэкранный workspace.")
    Button(onClick = onOpenFullReport, modifier = Modifier.fillMaxWidth()) { Text("Открыть RE Browser в полном отчёте") }
}
'''

NEW = '''@Composable
private fun ReverseEngineeringToolPanel(report: StaticAnalysisReport, onOpenFullReport: () -> Unit) {
    CallGraphWorkspacePanel(report, onOpenFullReport)
}
'''


def main() -> None:
    text = UI.read_text(encoding="utf-8")
    if NEW in text:
        print("v0.26.9 Call Graph workspace already present")
        return
    if OLD not in text:
        raise RuntimeError("RE workspace source block not found")
    UI.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    print("v0.26.9 Call Graph workspace applied")


if __name__ == "__main__":
    main()
