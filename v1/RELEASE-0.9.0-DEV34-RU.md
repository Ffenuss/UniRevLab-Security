# ModKit 0.9.0-dev34

Dev34 продолжает архитектурную разгрузку RE pipeline без ослабления доказательной модели.

## Что изменено

- Per-artifact DEX/ELF/config scanner вынесен из `rewworkspace/correlate.py` в `rewworkspace/artifact_scan.py`.
- Небольшие byte-backed DEX/XML/JSON/TXT артефакты могут сканироваться максимум двумя worker-потоками.
- Native `.so`, mmap-backed и крупные артефакты остаются синхронными, поэтому dev33 bounded-memory модель не отменяется.
- Для `analysis.methods.jsonl` добавлен дисковый `analysis.methods.jsonl.search.idx`.
- Search index использует FNV-1a 64-bit token hashes и `metadataMethodId`; исходная JSONL-строка остаётся источником истины.
- Android UI сначала сужает полный metadata-каталог через индекс, затем заново применяет существующий `matchRank` к исходным строкам.
- Если индекс отсутствует, повреждён, запрос слишком широкий или не индексируется точно, UI автоматически использует прежний linear fallback.
- Поиск в UI получил debounce 250 мс, чтобы не запускать новую задачу на каждый промежуточный символ.

## Инварианты

- Статическое совпадение не становится runtime-confirmed.
- Search index не меняет `selectable`, runtime status или Menu eligibility.
- Probe/Menu fail-closed gates не ослаблены.
- В generic RE cache по-прежнему нет runtime/probe truth.
- Внешняя схема RE-отчёта остаётся `modkit-re-1.2`.
