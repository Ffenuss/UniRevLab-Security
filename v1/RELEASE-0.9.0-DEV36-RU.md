# ModKit 0.9.0-dev36 — Unified Decompiler Workspace

- Добавлен встроенный Decompiler Workspace на **JADX 1.5.6**.
- Обычный APK и установленный APK-set являются равноправными inputs; для APK-set загружаются base + локально скопированные splits.
- Java-like декомпиляция класса выполняется лениво по выбору пользователя, а не для всего приложения при открытии.
- Добавлен Smali view для того же класса без отдельной второй базы навигации.
- Добавлен Resources mode с декодированием Manifest/resources через JADX.
- Добавлены локальные class usages/xrefs.
- Добавлен bounded/cancellable full-text search по декомпилированному коду с лимитом результатов.
- Добавлен явный full decompile export ZIP с diagnostics manifest.
- Native mode связан с существующим ELF/HEX/ARM64 workspace и честно называется disassembly, а не восстановленным C.
- Для декомпиляции не нужен IL2CPP/global-metadata.dat.
- Runtime INTERNET permission не добавлялся.
- Fail-closed Probe/Menu semantics не изменялись.
