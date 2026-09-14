# ModKit Android 0.9.0-dev — RE Workspace / Native Editor / Patch Pack

Снимок разработки поверх сохранённых исходников 0.7.0 и фактического поведения 0.8.1.

## Добавлено

- `modkit.reworkspace.native.NativeWorkspace`:
  - ELF64 обзор, секции, символы, DT_NEEDED/SONAME;
  - RVA ↔ file offset;
  - HEX-страницы и поиск HEX;
  - строки;
  - ARM64 disassembly;
  - редактирование HEX;
  - ограниченный ARM64 assembler (`NOP`, `RET`, `MOV W0/X0,#imm`, `B/BL`);
  - undo, журнал old/new bytes, SHA-256, сохранение новой `.so`.
- `modkit.reworkspace.correlate`:
  - совместный анализ DEX + всех `.so` + текстовых/Unity/IL2CPP артефактов;
  - evidence provenance;
  - статусы `candidate`, `correlated`, `confirmed`;
  - автоматическая корреляция menu/overlay, debug/console, gameplay surface, hook framework и IL2CPP evidence.
- `modkit.patchpack`:
  - проверка ZIP из `classes*.dex` + `.so` перед внедрением;
  - защита от потери существующих DEX-классов;
  - ABI и `DT_NEEDED` проверки;
  - конфликт целевых путей;
  - пересборка неподписанной копии APK с удалением старой `META-INF` подписи.
- `modkit.menu`:
  - декларативная схема меню;
  - элементы toggle/button/slider/label;
  - привязка к finding ID и подтверждённому RVA;
  - генерация аудируемого `modkit-menu.json` и `bindings.generated.h`.

## Проверка

- `pytest`: 132 теста успешно.

## Следующий шаг

Android UI: отдельные экраны RE Workspace, Native/SO Editor, Patch Pack и Menu Builder; после этого Gradle/Chaquopy сборка и тест APK в CI.
