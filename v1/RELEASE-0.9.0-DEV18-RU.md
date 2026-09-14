# ModKit Android 0.9.0-dev18 — split IL2CPP bridge

Dev18 исправляет разрыв между главным Rodroid-анализом и RE Workspace для split APK.

- Если `base.apk` не содержит полной пары `global-metadata.dat + libil2cpp.so`, RE Workspace использует уже выбранную на главном экране пару.
- Если для этой пары уже завершён Rodroid-анализ, `analysis.json` и `rodroid/` переиспользуются без повторного 28k+ method dump.
- Внешний `libil2cpp.so` проходит тот же bounded generic native scan и специализированный ARM64 BL/xref + method-context проход.
- В `re-analysis.json` сохраняются `inputSources` и `pipelineDiagnostics`, чтобы было видно, откуда взяты metadata/library и почему xref может отсутствовать.
- Java не материализует полный RE JSON только ради progress-сообщения: WorkerService получает компактный return.
- Главный поиск по Rodroid-каталогу ранжирует точное совпадение имени/класса выше semantic alias (`hp -> health`), сохраняя file-backed paging.
- В строках поиска показываются provenance, static/instance ABI, return/parameter types и причина совпадения.
- RE Workspace показывает источник IL2CPP, pipeline status и краткий IL2CPP control shortlist.

Android: `versionCode 25`, `versionName 0.9.0-dev18`.
Python: `0.9.0.dev18` / `0.9.0-dev18`.
