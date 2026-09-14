# ModKit Android 0.9.0-dev9

## Function-level native correlation

- `nativeRelations.symbolEdges` связывает импорт функции одной упакованной `.so` с точным export другой `.so`.
- `nativeRelations.dynamicSymbolEdges` требует одновременно `dlsym`, ссылку на конкретную downstream-библиотеку и точное совпадение строки с её export. Символьные/debug string tables исключены, чтобы не получать тысячи ложных C++ совпадений.
- Для небольших ARM64 helper libraries добавлен bounded `ADRP+ADD` string-xref scanner. Если функция реально материализует адрес строки, связь получает `staticStringXrefs` с function/RVA provenance.
- `nativeRelations.jniDirectCallRefs` и `jniCallChains` показывают только прямые ARM64 `BL` внутри JNI roots (`JNI_OnLoad`, `Java_*`). Это статические ссылки, не runtime trace.

## Targeted IL2CPP xrefs

После загрузки Rodroid/IL2CPP отчёта ModKit делает один bounded проход по `libil2cpp.so` только для high-signal address-bearing controls:

- прямой `BL` должен точно разрешаться в RVA Rodroid method;
- для stripped ELF source method восстанавливается по уникальному managed RVA interval;
- shared/generic starts остаются `ambiguous-shared-rva`;
- результат сохраняется в `nativeRelations.il2cppDirectCallRefs` и finding `re.il2cpp_static_call_references`.

Общий call graph огромного `libil2cpp.so` специально не строится: targeted pass уменьшает RAM/шум и сохраняет memory-fix модель.

## Native / SO Editor

Добавлена команда **«Найти прямые вызовы на RVA (static BL xrefs)»**. Для выбранного RVA показываются callsite, file offset, source function (если она доступна в ELF symbols) и target RVA.

## Проверка на сохранённых Drova артефактах

Статический анализ ранее сохранённого тестового комплекта восстановил цепочки:

- `classes3.dex → libBedo.so` по `Bedo + loadLibrary + JNI_OnLoad`;
- `JNI_OnLoad @ libBedo.so → std::thread constructor` как прямой ARM64 `BL`;
- `_ZN12_GLOBAL__N_17installEv` материализует строку `A64HookFunction` (`ADRP+ADD`), `libBedo.so` содержит `dlsym` и ссылку на `libCore.so`, а `libCore.so` экспортирует `A64HookFunction`;
- в настоящем 134 410 704-byte `libil2cpp.so`:
  - `Drova.CheatGameHandler::StartHandler() → EnableCheatMode()` через call RVA `0x3c30540`;
  - `Drova.CheatGameHandler::CheckActivationCode() → ToggleConsoleWindow()` через `0x3c30ea0`;
  - `Drova.CheatGameHandler::IncreaseCheatCodeCounter() → EnableCheatMode()` через `0x3c31380`.

Эти результаты означают статические code references. Они не объявляются доказательством фактического выполнения соответствующей ветки во время запуска игры.

## Версии

- Android: `versionCode 16`, `versionName 0.9.0-dev9`.
- Python: `0.9.0.dev9`; banner: `0.9.0-dev9`.
