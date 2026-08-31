#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if new in text:
        print(f"already patched: {rel}")
        return
    if old not in text:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing:\n{old[:800]}")
    write(rel, text.replace(old, new, 1))
    print(f"patched: {rel}")


# Dependencies and app version.
gradle_rel = "app/build.gradle.kts"
gradle = read(gradle_rel)
if 'versionName = "0.23.0-dev-patch-lab"' not in gradle:
    gradle = gradle.replace(
        'versionCode = 24\n        versionName = "0.22.6-dev-stream-export"',
        'versionCode = 25\n        versionName = "0.23.0-dev-patch-lab"',
        1,
    )
for dep in [
    '    implementation("org.smali:baksmali:2.5.2")\n',
    '    implementation("org.smali:smali:2.5.2")\n',
    '    implementation("com.android.tools.build:apksig:2.3.0")\n',
]:
    if dep.strip() not in gradle:
        marker = '    implementation("androidx.compose.ui:ui-tooling-preview")\n'
        if marker not in gradle:
            raise SystemExit("build.gradle dependency marker changed")
        gradle = gradle.replace(marker, marker + dep, 1)
write(gradle_rel, gradle)
print(f"patched: {gradle_rel}")


# FileProvider and package install permission for the explicitly rebuilt test APK.
manifest_rel = "app/src/main/AndroidManifest.xml"
manifest = read(manifest_rel)
if 'android.permission.REQUEST_INSTALL_PACKAGES' not in manifest:
    manifest = manifest.replace(
        '    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />\n',
        '    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />\n'
        '    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />\n',
        1,
    )
if '.fileprovider' not in manifest:
    marker = '''        <service\n            android:name=".analysis.AnalysisForegroundService"\n'''
    provider = '''        <provider\n            android:name="androidx.core.content.FileProvider"\n            android:authorities="${applicationId}.fileprovider"\n            android:exported="false"\n            android:grantUriPermissions="true">\n            <meta-data\n                android:name="android.support.FILE_PROVIDER_PATHS"\n                android:resource="@xml/file_paths" />\n        </provider>\n\n'''
    if marker not in manifest:
        raise SystemExit("manifest service marker changed")
    manifest = manifest.replace(marker, provider + marker, 1)
write(manifest_rel, manifest)
print(f"patched: {manifest_rel}")

file_paths_rel = "app/src/main/res/xml/file_paths.xml"
file_paths = '''<?xml version="1.0" encoding="utf-8"?>\n<paths xmlns:android="http://schemas.android.com/apk/res/android">\n    <cache-path name="patchlab" path="patchlab/" />\n</paths>\n'''
if not (ROOT / file_paths_rel).exists():
    write(file_paths_rel, file_paths)
    print(f"created: {file_paths_rel}")


# Main navigation and artifact source handoff.
main_rel = "app/src/main/java/org/unirevlab/security/MainActivity.kt"
main = read(main_rel)
if 'import androidx.core.content.FileProvider\n' not in main:
    main = main.replace('import androidx.core.content.ContextCompat\n', 'import androidx.core.content.ContextCompat\nimport androidx.core.content.FileProvider\n', 1)
if 'import org.unirevlab.security.model.Finding\n' not in main:
    main = main.replace('import org.unirevlab.security.model.AssessmentDiff\n', 'import org.unirevlab.security.model.AssessmentDiff\nimport org.unirevlab.security.model.Finding\n', 1)
if 'import org.unirevlab.security.ui.PatchLabScreen\n' not in main:
    main = main.replace('import org.unirevlab.security.ui.HelpScreen\n', 'import org.unirevlab.security.ui.HelpScreen\nimport org.unirevlab.security.ui.PatchLabScreen\n', 1)
main = main.replace(
    'private enum class Route { AGREEMENT, SCOPE, DASHBOARD, INSTALLED_APPS, HELP }',
    'private enum class Route { AGREEMENT, SCOPE, DASHBOARD, INSTALLED_APPS, HELP, PATCH_LAB }',
)
if 'var patchFinding by remember' not in main:
    marker = '    var coordinatorSyncStatus by remember { mutableStateOf<String?>(null) }\n'
    addition = (
        '    var patchFinding by remember { mutableStateOf<Finding?>(null) }\n'
        '    var lastArtifactUri by remember { mutableStateOf<android.net.Uri?>(null) }\n'
    )
    if marker not in main:
        raise SystemExit("MainActivity state marker changed")
    main = main.replace(marker, marker + addition, 1)
if 'lastArtifactUri = uri\n            requestAnalysisNotificationPermission()' not in main:
    marker = '            requestAnalysisNotificationPermission()\n            AnalysisManager.startFile(uri, requireNotNull(scope))\n'
    replacement = '            lastArtifactUri = uri\n            requestAnalysisNotificationPermission()\n            AnalysisManager.startFile(uri, requireNotNull(scope))\n'
    if marker not in main:
        raise SystemExit("MainActivity file picker marker changed")
    main = main.replace(marker, replacement, 1)
if 'onOpenPatchLab = {' not in main:
    marker = '            onOpenHelp = { route = Route.HELP },\n'
    replacement = (
        '            onOpenHelp = { route = Route.HELP },\n'
        '            onOpenPatchLab = { finding ->\n'
        '                patchFinding = finding\n'
        '                route = Route.PATCH_LAB\n'
        '            },\n'
    )
    if marker not in main:
        raise SystemExit("Dashboard callback marker changed")
    main = main.replace(marker, replacement, 1)
if 'Route.PATCH_LAB -> PatchLabScreen' not in main:
    marker = '        Route.HELP -> HelpScreen(onBack = { route = Route.DASHBOARD })\n'
    addition = '''        Route.PATCH_LAB -> {\n            val currentReport = report\n            if (currentReport == null) {\n                route = Route.DASHBOARD\n            } else {\n                PatchLabScreen(\n                    report = currentReport,\n                    initialFinding = patchFinding,\n                    initialSourceUri = lastArtifactUri,\n                    onBack = { route = Route.DASHBOARD },\n                    onAnalyzeBuilt = { file ->\n                        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)\n                        patchFinding = null\n                        route = Route.DASHBOARD\n                        requestAnalysisNotificationPermission()\n                        AnalysisManager.startFile(uri, requireNotNull(scope))\n                    },\n                )\n            }\n        }\n'''
    if marker not in main:
        raise SystemExit("Route HELP marker changed")
    main = main.replace(marker, marker + addition, 1)
if 'lastArtifactUri = null\n                requestAnalysisNotificationPermission()' not in main:
    marker = '                route = Route.DASHBOARD\n                requestAnalysisNotificationPermission()\n                AnalysisManager.startInstalled(app, requireNotNull(scope))\n'
    replacement = '                route = Route.DASHBOARD\n                lastArtifactUri = null\n                requestAnalysisNotificationPermission()\n                AnalysisManager.startInstalled(app, requireNotNull(scope))\n'
    if marker not in main:
        raise SystemExit("installed app marker changed")
    main = main.replace(marker, replacement, 1)
write(main_rel, main)
print(f"patched: {main_rel}")


# Dashboard entry points from tools and each Finding.
dash_rel = "app/src/main/java/org/unirevlab/security/ui/DashboardScreen.kt"
dash = read(dash_rel)
if 'onOpenPatchLab: (Finding?) -> Unit,' not in dash:
    marker = '    onOpenHelp: () -> Unit,\n'
    if marker not in dash:
        raise SystemExit("Dashboard signature marker changed")
    dash = dash.replace(marker, marker + '    onOpenPatchLab: (Finding?) -> Unit,\n', 1)
dash = dash.replace('                    ResultSection.FINDINGS -> FindingsSection(report.findings)\n',
                    '                    ResultSection.FINDINGS -> FindingsSection(report.findings, onOpenPatchLab)\n', 1)
if 'Text("Patch / Hook Lab — тестовые правки и пересборка")' not in dash:
    marker = '''                Text("Дополнительные инструменты", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)\n'''
    addition = '''                Text("Дополнительные инструменты", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)\n                Button(onClick = { onOpenPatchLab(null) }, enabled = !isInspecting, modifier = Modifier.fillMaxWidth()) {\n                    Text("Patch / Hook Lab — тестовые правки и пересборка")\n                }\n'''
    if marker not in dash:
        raise SystemExit("Dashboard tools marker changed")
    dash = dash.replace(marker, addition, 1)
if 'private fun FindingsSection(findings: List<Finding>, onOpenPatchLab: (Finding?) -> Unit)' not in dash:
    dash = dash.replace(
        'private fun FindingsSection(findings: List<Finding>) {\n',
        'private fun FindingsSection(findings: List<Finding>, onOpenPatchLab: (Finding?) -> Unit) {\n',
        1,
    )
    marker = '''                Text("Исправление: ${finding.remediation}")\n                if (finding.requiresManualReview) {\n'''
    replacement = '''                Text("Исправление: ${finding.remediation}")\n                Button(onClick = { onOpenPatchLab(finding) }, modifier = Modifier.fillMaxWidth()) {\n                    Text("Тестировать здесь → Patch / Hook Lab")\n                }\n                if (finding.requiresManualReview) {\n'''
    if marker not in dash:
        raise SystemExit("Finding remediation marker changed")
    dash = dash.replace(marker, replacement, 1)
write(dash_rel, dash)
print(f"patched: {dash_rel}")

print("v0.23.0 Patch / Hook Lab integration patch complete")
