from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path, old, new, label):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'{label}: anchor not found in {path}')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')

path = 'app/src/main/java/org/unirevlab/security/ui/RuntimeStateLabPanel.kt'

replace_once(path,
'''            Text(
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
''',
'''            Text(
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
''', 'runtime explanation')

replace_once(path,
'''            ) { Text(if (treeUri == null) "Выбрать папку локальных данных" else "Выбрать другую папку данных") }
''',
'''            ) { Text(if (treeUri == null) "Подключить snapshot / папку данных" else "Выбрать другой snapshot / папку") }
''', 'runtime source button')

print('v0.25.9 runtime binding UX applied')
