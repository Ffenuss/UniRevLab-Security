# ModKit Android 0.9.0-dev8

## DEX ↔ native linkage

- RE Workspace сохраняет bounded DEX string inventory, достаточный для статической корреляции library-name strings.
- Для `lib*.so` сохраняются embedded library-string references (`libCore.so`, `libil2cpp.so` и т.п.) отдельно от `DT_NEEDED`; строковая ссылка не выдаётся за linker dependency.
- `nativeRelations.dexNativeLinks` связывает DEX с конкретной `.so`, когда в DEX есть matching library name/stem. Наличие `loadLibrary` и `JNI_OnLoad` повышает confidence, но не считается доказательством выполнения конкретной функции.
- `nativeRelations.embeddedLibraryStringEdges` связывает одну `.so` с другой по встроенному имени библиотеки, отдельно от `dependencyEdges`.

## DEX-to-native loader finding

- Новый finding `re.dex_native_loader_bridge` появляется, когда DEX содержит matching library-name + `loadLibrary`, а целевой ELF экспортирует `JNI_OnLoad`.
- Если тот же native loader содержит downstream library reference или dynamic-loader API, finding повышается до `confirmed`.
- Finding описывает packaged loader relationship, а не runtime execution trace.

## Native inventory

- С dev7 сохраняются functions/imports/exports samples, JNI surface, dynamic loading и render/input surface.
- С dev8 эти данные объединены с DEX→SO и SO→SO relationships в одном `nativeRelations` graph-like разделе.

## Menu verification

- Сохраняются full bounded corroborating-evidence chains при переносе candidate из RE Workspace в Menu Builder.
- `promotionRecords` содержит provenance chain вместе с signature/ABI/RVA/resolver/ELF verification.
- `readyForAutoBuild` не позволяет Auto APK молча пропустить high-confidence callable candidate; manual payload по подтверждённому подмножеству остаётся отдельным режимом.

## Проверка на сохранённом Drova menu pack

На ранее сохранённом тестовом комплекте статическая корреляция восстановила:

- `classes3.dex → libBedo.so`: matching `Bedo` + `loadLibrary` + `JNI_OnLoad`, confidence 0.92;
- `libBedo.so → libCore.so`: embedded `libCore.so` reference;
- `libBedo.so`: imports `dlopen`/`dlsym`.

Это ровно тот тип цепочки, который раньше приходилось восстанавливать вручную. Содержимое целевых файлов в репозиторий не включается.

## Версии

- Android: `versionCode 15`, `versionName 0.9.0-dev8`.
- Python: `0.9.0.dev8`; banner: `0.9.0-dev8`.
