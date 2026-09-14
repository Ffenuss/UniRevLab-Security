# ModKit Android 0.9.0-dev17 — large Rodroid result stability

## Исправлено

- После успешного Rodroid-анализа большой отчёт больше не сериализуется целиком в гигантскую Python-строку: полный `analysis.json` пишется потоково.
- Android получает компактный `analysis.summary.json`, а не десятки тысяч `candidates`/`discoveries` в одном `JSONObject`.
- Полный каталог строк UI сохраняется в `analysis.ui.jsonl` и читается постранично/асинхронно.
- Поиск по 20–30 тысячам методов больше не выполняется синхронно в UI-потоке и отменяет устаревшие поисковые проходы.
- Повторный импорт исходных файлов очищает и старый file-backed индекс.
- Сохранение полного анализа/дампа и экспорт выбранных патчей продолжают использовать полный `analysis.json`; функциональность не урезана.

## Проверки

- Python regression suite: 240/240.
- `modkit selftest`: OK.
- `modkit runtime-check`: built-in generic runtime v2, strict C++17: OK.
- Android: `versionCode 24`, `versionName 0.9.0-dev17`.
- Python package/banner: `0.9.0.dev17` / `0.9.0-dev17`.

Статический анализ не доказывает runtime-эффект конкретной функции игры; Menu Builder по-прежнему требует структурно подтверждённые RVA/ABI и fail-closed проверки.
