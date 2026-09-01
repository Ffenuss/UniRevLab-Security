from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path, old, new, label):
    p = ROOT / path
    text = p.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'{label}: anchor not found in {path}')
    p.write_text(text.replace(old, new, 1), encoding='utf-8')

# Clarify Runtime State source behavior: imported APK has no live sandbox data; installed target uses
# the selected app identity and offers snapshot/backup import instead of an unexplained folder picker.
path = 'app/src/main/java/org/unirevlab/security/ui/RuntimeStateLabPanel.kt'
replace_once(path,
'''        Text(
            "Ищет key/value в выбранной папке данных: SharedPreferences XML, JSON, properties/INI/text и SQLite. Совпадение идёт по имени ключа, и по текущему значению. * показывает всё распознанное значение. Перед первой записью создаётся backup.",
''',
'''        Text(
            "Ищет key/value в локальных данных цели: SharedPreferences XML, JSON, properties/INI/text и SQLite. Совпадение идёт по имени ключа и текущему значению; * показывает всё распознанное состояние. Для установленной цели используйте её snapshot/backup, если Android не даёт прямого доступа к private sandbox. Перед первой записью создаётся backup.",
''', 'runtime explanation')
replace_once(path,
'''            Text("Выбрать папку локальных данных")
''',
'''            Text("Подключить snapshot / папку данных")
''', 'runtime source button')
print('v0.25.9 runtime binding UX applied')
