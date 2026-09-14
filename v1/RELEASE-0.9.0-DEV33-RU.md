# ModKit 0.9.0-dev33 — архитектура и производительность RE pipeline

Dev33 — технический этап после dev32. Он не ослабляет Discovery/Probe/Menu gates и не меняет смысл статических доказательств. Цель — уменьшить peak RSS и повторную работу на крупных APK-set/IL2CPP targets, одновременно разнести часть orchestration из монолитного `mobile/engine.py`.

## Typed report contract

Добавлен `modkit.reworkspace.schema` с отдельным typed contract `modkit-re-report-typed-1`. Внешний RE JSON schema сохранён как `modkit-re-1.2` для обратной совместимости. Нормализуются обязательные контейнеры inventory/findings/nativeRelations, но evidence strength и runtime status никогда не повышаются автоматически.

## Streaming APK-set

`correlate_apk` больше не читает целый вложенный APK в один `bytes`-объект. Nested APK потоково копируется в `SpooledTemporaryFile`; маленькие наборы остаются в памяти, крупные автоматически переходят на временный файл. SHA-256 считается в том же проходе, дубликаты split APK по-прежнему отбрасываются до анализа.

Крупные `.so` (от 8 MiB) внутри APK/APK-set анализируются через read-only mmap временного файла. Для внешнего `libil2cpp.so` function/xref pass также используется `ElfFile.open_mmap`.

## ARM64 allocations

- direct `BL` scanner работает по `memoryview`, не копируя целую executable-секцию;
- ADRP+ADD scanner больше не создаёт Python-list из каждого 32-bit instruction;
- native import/export/dlsym correlation использует индекс библиотек по имени вместо повторных линейных `next(...)` проходов.

## Content-addressed generic correlation cache

Добавлен `CorrelationCache`:

- ключ — SHA-256 всех generic-stage inputs + namespace алгоритма;
- хранение — gzip JSON, atomic replace;
- bounded pruning по числу entries и общему объёму;
- cache возвращает только статический generic correlation stage;
- runtime/probe truth и Menu execution eligibility не кэшируются;
- cache hit/miss и input hashes видны в `correlationCache`/`pipelineDiagnostics`.

Cache можно отключить переменной `MODKIT_DISABLE_RE_CACHE=1`.

## Pipeline decomposition

Staged JSON/merge helpers вынесены из `mobile/engine.py` в `modkit.reworkspace.pipeline`. Это первая часть декомпозиции 300+ KB bridge-модуля без изменения Android API.

## Инварианты

- Menu остаётся fail-closed.
- Static evidence не становится runtime-confirmed из-за cache или typed schema.
- Server/payment bypass не добавлялся.
- APK-set dedupe, split provenance и bounded artifact caps сохранены.
- Внешний RE schema остаётся `modkit-re-1.2`; новый typed contract версионируется отдельно.
