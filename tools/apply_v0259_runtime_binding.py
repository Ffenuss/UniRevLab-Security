from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = 'app/src/main/java/org/unirevlab/security/ui/RuntimeStateLabPanel.kt'
p = ROOT / path
text = p.read_text(encoding='utf-8')

old_explanation = '''            Text(
                "Ищет key/value в выбранной папке данных: SharedPreferences XML, JSON, properties/INI/text и SQLite. " +
                    "Совпадение идёт и по имени ключа, и по текущему значению. * показывает все распознанные значения. " +
                    "Перед первой записью создаётся backup.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Android не разрешает одному обычному приложению читать /data/data другого приложения. " +
                    "Выберите экспорт/backup заказчика, debug-директорию или другую папку, к которой Android выдал доступ. Sandbox не обходится.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
'''
new_explanation = '''            Text(
                "Ищет key/value в локальных данных цели: SharedPreferences XML, JSON, properties/INI/text и SQLite. " +
                    "Совпадение идёт и по имени ключа, и по текущему значению. * показывает все распознанные значения. " +
                    "Перед первой записью создаётся backup.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Для установленной цели используйте её snapshot/backup или debug-директорию, если Android не дал прямой доступ к private sandbox. " +
                    "Импортированный APK сам по себе не содержит runtime-сохранения пользователя.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
'''

if new_explanation not in text:
    if old_explanation not in text:
        raise SystemExit('runtime explanation: neither old nor migrated block found')
    text = text.replace(old_explanation, new_explanation, 1)

old_button = '''            ) { Text(if (treeUri == null) "Выбрать папку локальных данных" else "Выбрать другую папку данных") }
'''
new_button = '''            ) { Text(if (treeUri == null) "Подключить snapshot / папку данных" else "Выбрать другой snapshot / папку") }
'''
if new_button not in text:
    if old_button not in text:
        raise SystemExit('runtime source button: neither old nor migrated button found')
    text = text.replace(old_button, new_button, 1)

p.write_text(text, encoding='utf-8')
print('v0.25.9 runtime binding UX applied/already present')
