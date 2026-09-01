from pathlib import Path
import re

root = Path('.')
build = root / 'app/build.gradle.kts'
screen = root / 'app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt'
pickers = root / 'app/src/main/java/org/unirevlab/security/ui/PatchLabPickerDialogs.kt'

build_text = build.read_text()
if 'versionName = "0.25.7-dev-full-pickers"' not in build_text:
    if 'versionCode = 35' not in build_text or 'versionName = "0.25.6-dev-runtime-state-lab"' not in build_text:
        raise SystemExit('Expected v0.25.6 base version not found')
    build_text = build_text.replace('versionCode = 35', 'versionCode = 36', 1)
    build_text = build_text.replace(
        'versionName = "0.25.6-dev-runtime-state-lab"',
        'versionName = "0.25.7-dev-full-pickers"',
        1,
    )
    build.write_text(build_text)

text = screen.read_text()

# The Compose version used by the app exposes RowScope/ColumnScope.weight as a member extension;
# an explicit import is not needed and has failed compilation in this project before.
picker_text = pickers.read_text().replace('import androidx.compose.foundation.layout.weight\n', '')
pickers.write_text(picker_text)

text = text.replace('import androidx.compose.foundation.horizontalScroll\n', '')
text = text.replace('    var classQuery by remember { mutableStateOf("") }\n', '')

state_anchor = '    var busy by remember { mutableStateOf(false) }\n'
state_block = state_anchor + '''    var showDexPicker by remember { mutableStateOf(false) }\n    var showClassPicker by remember { mutableStateOf(false) }\n    var showMethodPicker by remember { mutableStateOf(false) }\n    var showArchivePicker by remember { mutableStateOf(false) }\n'''
if 'var showDexPicker by remember' not in text:
    if state_anchor not in text:
        raise SystemExit('busy state anchor not found')
    text = text.replace(state_anchor, state_block, 1)

old_dex = re.compile(r'''\s*Row\(Modifier\.fillMaxWidth\(\)\.horizontalScroll\(rememberScrollState\(\)\), horizontalArrangement = Arrangement\.spacedBy\(8\.dp\)\) \{\n\s*ws\.dexEntries\.forEach \{ dex ->\n\s*if \(dex == selectedDex\) Button\(onClick = \{ selectedDex = dex; classes = emptyList\(\); smaliText = "" \}\) \{ Text\(dex\) \}\n\s*else OutlinedButton\(onClick = \{ selectedDex = dex; classes = emptyList\(\); smaliText = "" \}\) \{ Text\(dex\) \}\n\s*\}\n\s*\}\n''')
new_dex = '''\n                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))) {\n                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {\n                        Text("DEX", fontWeight = FontWeight.SemiBold)\n                        Text(selectedDex ?: "DEX не выбран", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)\n                        OutlinedButton(\n                            onClick = { showDexPicker = true },\n                            enabled = ws.dexEntries.isNotEmpty() && !busy,\n                            modifier = Modifier.fillMaxWidth(),\n                        ) { Text("Выбрать DEX (${ws.dexEntries.size})") }\n                    }\n                }\n'''
text, count = old_dex.subn(new_dex, text, count=1)
if count != 1 and 'Выбрать DEX (${ws.dexEntries.size})' not in text:
    raise SystemExit(f'DEX selector replacement failed: {count}')

classes_pattern = re.compile(r'''\n\s*if \(classes\.isNotEmpty\(\)\) \{\n\s*OutlinedTextField\(\n\s*value = classQuery,.*?\n\s*Button\(onClick = ::loadCurrentClass, enabled = selectedClass != null && !busy, modifier = Modifier\.fillMaxWidth\(\)\) \{\n\s*Text\("Открыть Smali-класс"\)\n\s*\}\n\s*\}\n''', re.S)
new_classes = '''\n                if (classes.isNotEmpty()) {\n                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))) {\n                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {\n                            Text("Класс", fontWeight = FontWeight.SemiBold)\n                            Text(selectedClass ?: "Класс не выбран", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)\n                            OutlinedButton(\n                                onClick = { showClassPicker = true },\n                                enabled = !busy,\n                                modifier = Modifier.fillMaxWidth(),\n                            ) { Text("Выбрать класс (${classes.size})") }\n                            Button(onClick = ::loadCurrentClass, enabled = selectedClass != null && !busy, modifier = Modifier.fillMaxWidth()) {\n                                Text("Открыть Smali-класс")\n                            }\n                        }\n                    }\n                }\n'''
text, count = classes_pattern.subn(new_classes, text, count=1)
if count != 1 and 'Выбрать класс (${classes.size})' not in text:
    raise SystemExit(f'class selector replacement failed: {count}')

text = text.replace(
    'report.dex?.methods.orEmpty().filter { it.dexEntry == selectedDex && it.declaringClass == selectedClass }.take(160)',
    'report.dex?.methods.orEmpty().filter { it.dexEntry == selectedDex && it.declaringClass == selectedClass }',
)

methods_pattern = re.compile(r'''\n\s*if \(classMethods\.isNotEmpty\(\)\) \{\n\s*Text\("Методы из RE-индекса".*?\n\s*\}\n\s*\}\n''', re.S)
new_methods = '''\n                if (classMethods.isNotEmpty()) {\n                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))) {\n                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {\n                            Text("Метод из RE-индекса", fontWeight = FontWeight.SemiBold)\n                            Text(\n                                selectedMethodName?.let { it + selectedPrototype.orEmpty() } ?: "Метод не выбран",\n                                style = MaterialTheme.typography.bodySmall,\n                                fontFamily = FontFamily.Monospace,\n                            )\n                            OutlinedButton(\n                                onClick = { showMethodPicker = true },\n                                enabled = !busy,\n                                modifier = Modifier.fillMaxWidth(),\n                            ) { Text("Выбрать метод (${classMethods.size})") }\n                        }\n                    }\n                }\n'''
text, count = methods_pattern.subn(new_methods, text, count=1)
if count != 1 and 'Выбрать метод (${classMethods.size})' not in text:
    raise SystemExit(f'method selector replacement failed: {count}')

native_pattern = re.compile(r'''\n\s*ws\.nativeEntries\.take\(20\)\.forEach \{ entry ->\n\s*OutlinedButton\(\n\s*onClick = \{ selectedReplacementEntry = entry \},\n\s*modifier = Modifier\.fillMaxWidth\(\),\n\s*\) \{\n\s*Text\(if \(entry == selectedReplacementEntry\) "✓ \$entry" else entry\)\n\s*\}\n\s*\}\n''')
new_native = '''\n                            Text(\n                                selectedReplacementEntry ?: "Файл внутри APK не выбран",\n                                style = MaterialTheme.typography.bodySmall,\n                                fontFamily = FontFamily.Monospace,\n                            )\n                            OutlinedButton(\n                                onClick = { showArchivePicker = true },\n                                enabled = ws.archiveEntries.isNotEmpty() && !busy,\n                                modifier = Modifier.fillMaxWidth(),\n                            ) { Text("Выбрать entry (${ws.archiveEntries.size})") }\n'''
text, count = native_pattern.subn(new_native, text, count=1)
if count != 1 and 'Выбрать entry (${ws.archiveEntries.size})' not in text:
    raise SystemExit(f'native/archive selector replacement failed: {count}')

# Insert full-screen virtualized pickers before the Smali editor section. They render every
# matching item without artificial take(...) caps while LazyColumn only composes visible rows.
dialog_anchor = '                if (smaliText.isNotBlank()) {\n'
dialogs = '''                if (showDexPicker) {\n                    PatchStringPickerDialog(\n                        title = "DEX-файлы",\n                        items = ws.dexEntries,\n                        selected = selectedDex,\n                        searchLabel = "Поиск DEX",\n                        onDismiss = { showDexPicker = false },\n                        onSelect = { dex ->\n                            selectedDex = dex\n                            classes = emptyList()\n                            selectedClass = null\n                            selectedMethodName = null\n                            selectedPrototype = null\n                            smaliText = ""\n                            originalSmaliText = ""\n                            showDexPicker = false\n                        },\n                    )\n                }\n                if (showClassPicker && classes.isNotEmpty()) {\n                    PatchStringPickerDialog(\n                        title = "Классы DEX",\n                        items = classes,\n                        selected = selectedClass,\n                        searchLabel = "Поиск класса",\n                        onDismiss = { showClassPicker = false },\n                        onSelect = { cls ->\n                            selectedClass = cls\n                            val firstMethod = report.dex?.methods?.firstOrNull { it.dexEntry == selectedDex && it.declaringClass == cls }\n                            selectedMethodName = firstMethod?.name\n                            selectedPrototype = firstMethod?.prototype\n                            smaliText = ""\n                            originalSmaliText = ""\n                            showClassPicker = false\n                        },\n                    )\n                }\n                if (showMethodPicker && classMethods.isNotEmpty()) {\n                    PatchMethodPickerDialog(\n                        methods = classMethods.map { PatchMethodChoice(it.name, it.prototype) },\n                        selectedName = selectedMethodName,\n                        selectedPrototype = selectedPrototype,\n                        onDismiss = { showMethodPicker = false },\n                        onSelect = { method ->\n                            selectedMethodName = method.name\n                            selectedPrototype = method.prototype\n                            showMethodPicker = false\n                        },\n                    )\n                }\n                if (showArchivePicker) {\n                    PatchStringPickerDialog(\n                        title = "Файлы внутри APK",\n                        items = ws.archiveEntries,\n                        selected = selectedReplacementEntry,\n                        searchLabel = "Поиск пути / entry",\n                        onDismiss = { showArchivePicker = false },\n                        onSelect = { entry ->\n                            selectedReplacementEntry = entry\n                            showArchivePicker = false\n                        },\n                    )\n                }\n\n'''
if 'title = "DEX-файлы"' not in text:
    if dialog_anchor not in text:
        raise SystemExit('dialog insertion anchor not found')
    text = text.replace(dialog_anchor, dialogs + dialog_anchor, 1)

# Guard against regressions in the old inline capped selectors.
for forbidden in ('classes.take(24)', 'classes.take(25)', '.take(80)', '.take(160)', 'nativeEntries.take(20)'):
    if forbidden in text:
        raise SystemExit(f'old capped selector remains: {forbidden}')

screen.write_text(text)
