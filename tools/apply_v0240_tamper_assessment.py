from pathlib import Path

ROOT = Path('.')


def replace_once(path: str, old: str, new: str):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if new in text:
        return
    if old not in text:
        raise SystemExit(f'patch state mismatch: {path}: anchor not found')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')


def copy_template(template: str, destination: str):
    src = ROOT / template
    dst = ROOT / destination
    if not src.is_file():
        raise SystemExit(f'missing template: {template}')
    dst.parent.mkdir(parents=True, exist_ok=True)
    content = src.read_text(encoding='utf-8')
    if not dst.exists() or dst.read_text(encoding='utf-8') != content:
        dst.write_text(content, encoding='utf-8')

build = ROOT / 'app/build.gradle.kts'
text = build.read_text(encoding='utf-8')
if 'versionName = "0.24.0-dev-tamper-assessment"' in text:
    print('v0.24.0 tamper assessment already integrated')
    raise SystemExit(0)
if 'versionName = "0.23.2-dev-report-export"' not in text:
    raise SystemExit('v0.24.0 expects verified v0.23.2 source')
text = text.replace('versionCode = 27', 'versionCode = 28', 1)
text = text.replace('versionName = "0.23.2-dev-report-export"', 'versionName = "0.24.0-dev-tamper-assessment"', 1)
build.write_text(text, encoding='utf-8')

copy_template('tools/v0240/ApkMutationDiffEngine.kt.txt', 'app/src/main/java/org/unirevlab/security/analysis/ApkMutationDiffEngine.kt')
copy_template('tools/v0240/TamperAssessmentEngine.kt.txt', 'app/src/main/java/org/unirevlab/security/analysis/TamperAssessmentEngine.kt')
copy_template('tools/v0240/TamperAssessmentPanel.kt.txt', 'app/src/main/java/org/unirevlab/security/ui/TamperAssessmentPanel.kt')
copy_template('tools/v0240/ApkMutationDiffEngineTest.kt.txt', 'app/src/test/java/org/unirevlab/security/analysis/ApkMutationDiffEngineTest.kt')
copy_template('tools/v0240/TamperAssessmentEngineTest.kt.txt', 'app/src/test/java/org/unirevlab/security/analysis/TamperAssessmentEngineTest.kt')

engine = 'app/src/main/java/org/unirevlab/security/analysis/PatchLabEngine.kt'
replace_once(
    engine,
    '''        val modifiedDexEntries: MutableSet<String> = linkedSetOf(),\n        val replacements: MutableMap<String, File> = linkedMapOf(),\n    )''',
    '''        val modifiedDexEntries: MutableSet<String> = linkedSetOf(),\n        val replacements: MutableMap<String, File> = linkedMapOf(),\n        val smaliBaselines: MutableMap<String, String> = linkedMapOf(),\n        val smaliEdits: MutableMap<String, String> = linkedMapOf(),\n        val textBaselines: MutableMap<String, String> = linkedMapOf(),\n        val textEdits: MutableMap<String, String> = linkedMapOf(),\n    )''',
)
replace_once(
    engine,
    '''        val changedEntries: List<String>,\n        val signerLabel: String = "UniRevLab Patch Lab Test",\n    )''',
    '''        val changedEntries: List<String>,\n        val apkDiff: ApkMutationDiffEngine.ApkDiffReport,\n        val codeDiffs: List<ApkMutationDiffEngine.CodeDiff>,\n        val signerLabel: String = "UniRevLab Patch Lab Test",\n    )''',
)
replace_once(
    engine,
    '''        require(dex.isNotEmpty()) { "В APK не найдено DEX-файлов" }\n        return Workspace(''',
    '''        return Workspace(''',
)
replace_once(
    engine,
    '''        val file = classFile(workspace, dexEntry, classDescriptor)\n        require(file.parentFile?.isDirectory == true || file.parentFile?.mkdirs() == true) { "Не удалось создать каталог Smali" }\n        file.writeText(text, Charsets.UTF_8)\n        workspace.modifiedDexEntries += dexEntry''',
    '''        val file = classFile(workspace, dexEntry, classDescriptor)\n        require(file.parentFile?.isDirectory == true || file.parentFile?.mkdirs() == true) { "Не удалось создать каталог Smali" }\n        val key = "$dexEntry|$classDescriptor"\n        if (key !in workspace.smaliBaselines && file.isFile) workspace.smaliBaselines[key] = file.readText(Charsets.UTF_8)\n        file.writeText(text, Charsets.UTF_8)\n        workspace.smaliEdits[key] = text\n        workspace.modifiedDexEntries += dexEntry''',
)
replace_once(
    engine,
    '''        val hookLabel = escapeSmaliString("${findingId ?: "manual"}: $methodName$prototype")\n        val hook = buildString {''',
    '''        val hookLabel = escapeSmaliString("${findingId ?: "manual"}: $methodName$prototype")\n        require(!block.contains(hookLabel)) { "Этот trace hook уже добавлен в метод" }\n        val hook = buildString {''',
)
replace_once(
    engine,
    '''    fun build(workspace: Workspace): BuildResult {''',
    '''    fun loadArchiveText(workspace: Workspace, entryName: String): String {\n        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }\n        val bytes = workspace.replacements[entryName]?.readBytes() ?: ZipFile(workspace.originalApk).use { zip ->\n            val entry = requireNotNull(zip.getEntry(entryName)) { "Файл не найден в APK: $entryName" }\n            require(entry.size < 0L || entry.size <= MAX_EDITABLE_TEXT_BYTES) { "Файл слишком большой для текстового редактора" }\n            zip.getInputStream(entry).use { input ->\n                val out = java.io.ByteArrayOutputStream()\n                val buffer = ByteArray(32 * 1024)\n                var total = 0L\n                while (true) {\n                    val read = input.read(buffer)\n                    if (read < 0) break\n                    if (read == 0) continue\n                    total += read\n                    require(total <= MAX_EDITABLE_TEXT_BYTES) { "Файл слишком большой для текстового редактора" }\n                    out.write(buffer, 0, read)\n                }\n                out.toByteArray()\n            }\n        }\n        require(bytes.none { it == 0.toByte() }) { "Entry выглядит как бинарный файл, текстовое редактирование отключено" }\n        val text = bytes.toString(Charsets.UTF_8)\n        require('\\uFFFD' !in text) { "Entry не является корректным UTF-8 текстом" }\n        return text\n    }\n\n    fun saveArchiveText(workspace: Workspace, entryName: String, text: String) {\n        require(entryName in workspace.archiveEntries) { "Файл не найден в APK: $entryName" }\n        val bytes = text.toByteArray(Charsets.UTF_8)\n        require(bytes.size <= MAX_EDITABLE_TEXT_BYTES) { "Текстовый entry слишком большой" }\n        if (entryName !in workspace.textBaselines) workspace.textBaselines[entryName] = loadArchiveText(workspace, entryName)\n        val stored = File(workspace.root, "replacements/${sha256Text(entryName)}.txt").apply { parentFile?.mkdirs() }\n        stored.writeBytes(bytes)\n        workspace.replacements[entryName] = stored\n        workspace.textEdits[entryName] = text\n    }\n\n    fun build(workspace: Workspace): BuildResult {''',
)
replace_once(
    engine,
    '''        require(signed.length() > 0L) { "Подписанный APK пуст" }\n        return BuildResult(\n            signedApk = signed,\n            sha256 = sha256(signed),\n            changedEntries = (workspace.modifiedDexEntries + workspace.replacements.keys).sorted(),\n        )\n    }\n\n    private fun repack''',
    '''        require(signed.length() > 0L) { "Подписанный APK пуст" }\n        val changedEntries = (workspace.modifiedDexEntries + workspace.replacements.keys).sorted()\n        val apkDiff = ApkMutationDiffEngine.compare(workspace.originalApk, signed, changedEntries)\n        require(apkDiff.unexpectedContentChanges.isEmpty()) {\n            "Пересборка изменила неожиданные entry: ${apkDiff.unexpectedContentChanges.take(8).joinToString()}"\n        }\n        val codeDiffs = buildList {\n            workspace.smaliBaselines.forEach { (key, before) ->\n                val after = workspace.smaliEdits[key] ?: return@forEach\n                if (before != after) add(ApkMutationDiffEngine.diffText("SMALI", key, before, after))\n            }\n            workspace.textBaselines.forEach { (entry, before) ->\n                val after = workspace.textEdits[entry] ?: return@forEach\n                if (before != after) add(ApkMutationDiffEngine.diffText("TEXT_ENTRY", entry, before, after))\n            }\n        }\n        return BuildResult(\n            signedApk = signed,\n            sha256 = sha256(signed),\n            changedEntries = changedEntries,\n            apkDiff = apkDiff,\n            codeDiffs = codeDiffs,\n        )\n    }\n\n    private fun repack''',
)

screen = 'app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt'
replace_once(
    screen,
    '''import org.unirevlab.security.analysis.PatchLabEngine\n''',
    '''import org.unirevlab.security.analysis.PatchLabEngine\nimport org.unirevlab.security.analysis.TamperAssessmentEngine\n''',
)
replace_once(
    screen,
    '''    fun buildApk() {''',
    '''    fun openTamperTarget(item: TamperAssessmentEngine.SearchResult) {\n        val ws = workspace ?: return\n        val dex = item.dexEntry ?: return\n        val cls = item.classDescriptor ?: return\n        scope.launch {\n            busy = true\n            error = null\n            status = "Открываем найденную цель: $cls…"\n            val result = runCatching {\n                withContext(Dispatchers.IO) {\n                    val list = PatchLabEngine.disassembleDex(ws, dex)\n                    val text = PatchLabEngine.loadClass(ws, dex, cls)\n                    list to text\n                }\n            }\n            result.getOrNull()?.let { (list, text) ->\n                selectedDex = dex\n                classes = list\n                selectedClass = cls\n                selectedMethodName = item.methodName\n                selectedPrototype = item.prototype\n                smaliText = text\n                originalSmaliText = text\n                status = "Открыта найденная цель: ${item.location}"\n            }\n            error = result.exceptionOrNull()?.message\n            busy = false\n        }\n    }\n\n    fun applyGeneratedTraceHook(proposal: TamperAssessmentEngine.HookProposal) {\n        val ws = workspace ?: return\n        scope.launch {\n            busy = true\n            error = null\n            built = null\n            status = "Генерируем trace hook: ${proposal.classDescriptor}->${proposal.methodName}${proposal.prototype}…"\n            val result = runCatching {\n                withContext(Dispatchers.IO) {\n                    val list = PatchLabEngine.disassembleDex(ws, proposal.dexEntry)\n                    val before = PatchLabEngine.loadClass(ws, proposal.dexEntry, proposal.classDescriptor)\n                    val after = PatchLabEngine.addEntryLogHook(before, proposal.methodName, proposal.prototype, "auto:${proposal.category}")\n                    PatchLabEngine.saveClass(ws, proposal.dexEntry, proposal.classDescriptor, after)\n                    list to after\n                }\n            }\n            result.getOrNull()?.let { (list, after) ->\n                selectedDex = proposal.dexEntry\n                classes = list\n                selectedClass = proposal.classDescriptor\n                selectedMethodName = proposal.methodName\n                selectedPrototype = proposal.prototype\n                smaliText = after\n                originalSmaliText = after\n                status = "Trace hook сгенерирован и сохранён. Он только логирует вход в метод."\n            }\n            error = result.exceptionOrNull()?.message\n            busy = false\n        }\n    }\n\n    fun buildApk() {''',
)
replace_once(
    screen,
    '''                Text("SHA-256 исходника: ${ws.artifactSha256}", style = MaterialTheme.typography.bodySmall)\n                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {''',
    '''                Text("SHA-256 исходника: ${ws.artifactSha256}", style = MaterialTheme.typography.bodySmall)\n                TamperAssessmentPanel(\n                    report = report,\n                    workspace = ws,\n                    busy = busy,\n                    onOpenTarget = ::openTamperTarget,\n                    onApplyHook = ::applyGeneratedTraceHook,\n                    onStatus = { status = it },\n                    onError = { error = it },\n                )\n                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {''',
)
replace_once(
    screen,
    '''                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {\n                        OutlinedButton(\n                            onClick = {\n                                val name = selectedMethodName\n                                val proto = selectedPrototype\n                                if (name != null && proto != null) {\n                                    runCatching { PatchLabEngine.addEntryLogHook(smaliText, name, proto, initialFinding?.id) }\n                                        .onSuccess { smaliText = it; error = null; status = "Добавлен test Log hook в $name$proto" }\n                                        .onFailure { error = it.message }\n                                }\n                            },\n                            enabled = selectedMethodName != null && selectedPrototype != null && !busy,\n                            modifier = Modifier.weight(1f),\n                        ) { Text("+ Log hook") }\n                        OutlinedButton(\n                            onClick = {\n                                val name = selectedMethodName\n                                val proto = selectedPrototype\n                                if (name != null && proto != null) {\n                                    runCatching { PatchLabEngine.forceBooleanReturn(smaliText, name, proto, false) }\n                                        .onSuccess { smaliText = it; error = null; status = "Добавлен test return=false в $name$proto" }\n                                        .onFailure { error = it.message }\n                                }\n                            },\n                            enabled = selectedPrototype?.endsWith(")Z") == true && !busy,\n                            modifier = Modifier.weight(1f),\n                        ) { Text("return false") }\n                    }''',
    '''                    OutlinedButton(\n                        onClick = {\n                            val name = selectedMethodName\n                            val proto = selectedPrototype\n                            if (name != null && proto != null) {\n                                runCatching { PatchLabEngine.addEntryLogHook(smaliText, name, proto, initialFinding?.id) }\n                                    .onSuccess { smaliText = it; error = null; status = "Добавлен trace-only Log hook в $name$proto" }\n                                    .onFailure { error = it.message }\n                            }\n                        },\n                        enabled = selectedMethodName != null && selectedPrototype != null && !busy,\n                        modifier = Modifier.fillMaxWidth(),\n                    ) { Text("+ Trace Log hook") }''',
)
replace_once(
    screen,
    '''                if (ws.nativeEntries.isNotEmpty()) {\n                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))) {''',
    '''                run {\n                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))) {''',
)
replace_once(
    screen,
    '''                    OutlinedButton(\n                        onClick = {\n                            val name = report.artifact.displayName.substringBeforeLast('.').replace(Regex("[^A-Za-z0-9._-]"), "_").take(72)\n                            exportPicker.launch("${name}-unirevlab-patched.apk")\n                        },''',
    '''                    PatchBuildAuditPanel(report = report, workspace = ws, result = result)\n                    OutlinedButton(\n                        onClick = {\n                            val name = report.artifact.displayName.substringBeforeLast('.').replace(Regex("[^A-Za-z0-9._-]"), "_").take(72)\n                            exportPicker.launch("${name}-unirevlab-patched.apk")\n                        },''',
)

print('Applied v0.24.0 defensive tamper assessment integration')
