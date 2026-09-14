# ModKit dev36 — исследование и архитектура Decompiler Workspace

Дата исследования: 2026-09-13.

## Цель

Сделать в ModKit один Android-first Decompiler Workspace, который открывает обычные APK и полный локальный APK-set, показывает высокоуровневый DEX-код, smali, Android resources/Manifest, локальные xref и связывает native-часть с уже существующим Native Workspace. Все операции выполняются локально; runtime INTERNET permission для этого не нужен.

## Какие виды декомпиляции реально существуют

1. **Dalvik/ART DEX → Java-like source.** Это восстановление читаемого исходного представления из DEX bytecode. Оно эвристическое: исходные имена локальных переменных, Kotlin-синтаксис и некоторые высокоуровневые конструкции могут быть потеряны.
2. **DEX → Smali.** Дизассемблирование Dalvik bytecode почти один-к-одному в ассемблероподобное представление. Оно хуже читается, но ближе к реально исполняемому DEX и подходит для точного RE/patch workflow.
3. **resources.arsc / binary AXML → XML/resources.** Восстановление AndroidManifest.xml, values, layout и других Android resources.
4. **JVM .class/JAR → Java.** Отдельный класс декомпиляторов. Для APK-first анализа обычно не нужен промежуточный DEX→JAR, если DEX умеет читать нативный Android-декомпилятор.
5. **ELF/native machine code → pseudocode.** Совсем другой класс задачи: машинный ARM64/x86-64 код, CFG, data-flow, symbols, calling conventions. Java/Smali backend его не заменяет.

## Исследованные решения

| Решение | Сильная сторона | Лицензия / состояние | Решение для ModKit |
|---|---|---|---|
| **JADX 1.5.6** | APK/DEX/AAB/ZIP → Java-like source; Manifest/resources; deobfuscation; usages; smali view; библиотечный API | Apache-2.0, активный upstream; 1.5.6 от 2026-07-10 | **Основной backend dev36** |
| **Apktool 3.0.3** | Максимально практичный decode/rebuild ресурсов + smali, близкий к round-trip APK workflow | Apache-2.0; 3.0.3 от 2026-07 | Не встраиваем в dev36: тяжёлый rebuild/AAPT pipeline; используем как эталон resource/rebuild semantics |
| **google/smali / baksmali** | Полный DEX assembler/disassembler | BSD-style ecosystem; активный Google fork | В dev36 отдельная зависимость не нужна: JADX уже отдаёт Smali. Добавлять assembler имеет смысл вместе с отдельным editable-smali rebuild contract |
| **Vineflower** | Очень качественный JVM .class/JAR → Java, современные Java features | Apache-2.0, активный | Не основной: APK содержит DEX; DEX→JAR добавляет лишний преобразующий слой и потерю Android-specific context |
| **CFR/Procyon/JD** | JVM bytecode decompilation | Разные лицензии/модели | Не добавляем: тот же DEX→JAR минус, лишний размер APK |
| **dex2jar** | DEX↔JVM bridge и IR | Активный community toolchain | Не нужен в primary path; JADX читает DEX напрямую |
| **Ghidra Decompiler** | Сильный native pseudocode, CFG/xref/type recovery | Основной код Apache-2.0 + отдельные third-party/GPL modules | Не встраиваем в Android APK: большой SRE runtime и native decompiler process; оставляем как workstation/worker-class решение |
| **RetDec** | ELF/PE/Mach-O, ARM64/x86-64 → C/Python-like output | MIT, LLVM-based; limited maintenance | Не встраиваем: слишком тяжёлый LLVM/native distribution для on-device APK |

## Почему выбран JADX upstream, а не старый Android fork

У JADX есть официальный пример использования библиотеки на Android. В нём upstream рекомендует один worker thread для ограничения памяти, `NoOpCodeCache`, `SimpleCodeWriter`, отключение неподдерживаемого Android secure XML parser и возможность отключить class-set loading. Dev36 повторяет этот Android-safe профиль и добавляет private config/cache/temp directories.

Мы сознательно используем **upstream 1.5.6**, а не фиксируемся на старом Android fork: это даёт свежие security fixes, актуальную DEX/Android поддержку и текущий API. `minSdk 26` ModKit сохраняется; CI обязан доказать D8/Android compile compatibility.

## Итоговая архитектура dev36

### Один workspace вместо россыпи утилит

`DecompilerActivity` показывает четыре режима:

- **Java** — lazy `JavaClass.getCode()`;
- **Smali** — `JavaClass.getSmali()`;
- **Resources** — lazy JADX resource decode/preview;
- **Native** — переход в Native Workspace с честной маркировкой ARM64 disassembly, без ложного заявления «это восстановленный C».

### APK-set first

Для установленного приложения Decompiler Engine читает `installed-target.json` и передаёт JADX **все доступные base/split APK**. Для локального одиночного APK используется рабочий `game.apk`. IL2CPP наличие не требуется.

### Lazy / bounded

- построение списка классов не декомпилирует каждый класс;
- JADX работает в один thread на телефоне;
- code cache отключён;
- полнотекстовый поиск декомпилирует классы по одному, имеет cancel и лимит 100 результатов;
- после поискового просмотра класс выгружается из JADX state, чтобы не накапливать код всего приложения в RAM;
- полный export запускается только явно пользователем.

### Xrefs

Для выбранного класса ModKit показывает `JavaClass.getUseIn()` — локальные incoming usages, обнаруженные JADX. Это навигационная RE-информация, а не доказательство runtime исполнения.

### Export

Явный Export ZIP запускает полный `jadx.save()`, затем потоково упаковывает output и добавляет `modkit-decompiler.json` с backend/input/count diagnostics.

## Что dev36 намеренно НЕ обещает

- Java-like output JADX **не является оригинальным исходным кодом** и не считается автоматически обратно компилируемым.
- Native `.so` **не превращается в Java/Smali** и в dev36 не маркируется как C-decompile.
- Smali в dev36 — просмотр. Writable smali → assemble → DEX replacement должен иметь отдельную transactional rebuild/verification модель, чтобы не портить APK молча.
- JADX сам предупреждает, что 100% кода не всегда удаётся декомпилировать; UI поэтому показывает errors/warnings backend-а.

## Источники

- JADX upstream: https://github.com/skylot/jadx
- JADX 1.5.6 release: https://github.com/skylot/jadx/discussions/2912
- Official JADX Android library example: https://github.com/jadx-decompiler/jadx-lib-android-example
- Apktool: https://apktool.org/
- Google smali: https://github.com/google/smali
- Vineflower: https://github.com/Vineflower/vineflower
- Ghidra: https://github.com/NationalSecurityAgency/ghidra
- RetDec: https://github.com/avast/retdec
