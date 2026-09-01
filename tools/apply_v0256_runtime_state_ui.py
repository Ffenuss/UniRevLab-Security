from pathlib import Path

patch_lab = Path('app/src/main/java/org/unirevlab/security/ui/PatchLabScreen.kt')
text = patch_lab.read_text()

old = '''                TamperAssessmentPanel(
                    report = report,
                    workspace = ws,
                    busy = busy,
                    onOpenTarget = ::openTamperTarget,
                    onApplyHook = ::applyGeneratedTraceHook,
                    onStatus = { status = it },
                    onError = { error = it },
                )'''
new = old.replace('TamperAssessmentPanel(', 'TamperAssessmentPanelV2(')
if old in text:
    text = text.replace(old, new, 1)
elif 'TamperAssessmentPanelV2(' not in text:
    raise SystemExit('TamperAssessmentPanel call not found')

auto = '''                AutoModPanel(
                    report = report,
                    workspace = ws,
                    busy = busy,
                    onAnalyzeBuilt = onAnalyzeBuilt,
                    onStatus = { status = it },
                    onError = { error = it },
                )'''
runtime = auto + '''
                RuntimeStateLabPanel(
                    busy = busy,
                    onStatus = { status = it },
                    onError = { error = it },
                )'''
if 'RuntimeStateLabPanel(' not in text:
    if auto not in text:
        raise SystemExit('AutoModPanel block not found')
    text = text.replace(auto, runtime, 1)

patch_lab.write_text(text)

# Compose 2026 exposes Modifier.weight as RowScope/ColumnScope extension. Importing the
# implementation symbol resolves to an internal parent-data property and fails Kotlin 2.3.
for ui_name in ('RuntimeStateLabPanel.kt', 'TamperAssessmentPanelV2.kt'):
    ui = Path('app/src/main/java/org/unirevlab/security/ui') / ui_name
    value = ui.read_text()
    value = value.replace('import androidx.compose.foundation.layout.weight\n', '')
    ui.write_text(value)

# Kotlin 2.3 in this project resolves Regex.replaceFirst(String, lambda) to the String
# replacement overload. Use an explicit MatchResult + replaceRange so XML editing remains exact.
engine = Path('app/src/main/java/org/unirevlab/security/analysis/RuntimeStateLabEngine.kt')
value = engine.read_text()
old_attr = '''        if (attrRegex.containsMatchIn(text)) {
            val coerced = coerceText(raw, hit.valueType)
            updated = attrRegex.replaceFirst(text) { m -> m.groupValues[1] + escapeXml(coerced) + m.groupValues[3] }
        }'''
new_attr = '''        val attrMatch = attrRegex.find(text)
        if (attrMatch != null) {
            val coerced = coerceText(raw, hit.valueType)
            val replacement = attrMatch.groupValues[1] + escapeXml(coerced) + attrMatch.groupValues[3]
            updated = text.replaceRange(attrMatch.range, replacement)
        }'''
if old_attr not in value and 'val attrMatch = attrRegex.find(text)' not in value:
    raise SystemExit('RuntimeState attr replacement block not found')
value = value.replace(old_attr, new_attr, 1)
old_string = '''            require(stringRegex.containsMatchIn(text)) { "Ключ ${locator.name} не найден при сохранении" }
            updated = stringRegex.replaceFirst(text) { m -> m.groupValues[1] + escapeXml(raw) + m.groupValues[3] }'''
new_string = '''            val stringMatch = requireNotNull(stringRegex.find(text)) { "Ключ ${locator.name} не найден при сохранении" }
            val replacement = stringMatch.groupValues[1] + escapeXml(raw) + stringMatch.groupValues[3]
            updated = text.replaceRange(stringMatch.range, replacement)'''
if old_string not in value and 'val stringMatch = requireNotNull(stringRegex.find(text))' not in value:
    raise SystemExit('RuntimeState string replacement block not found')
value = value.replace(old_string, new_string, 1)
engine.write_text(value)
