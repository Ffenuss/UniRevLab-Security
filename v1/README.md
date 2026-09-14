# Текущий Android checkpoint: 0.9.0-dev25

`android/` содержит телефонный ModKit с Rodroid Il2CppDumper, RE Workspace, Unity/Addressables
scanner, анализом всех ELF/.so, Native/SO Editor, Patch Pack и Menu Builder. Dev10 добавляет
bounded static relationship graph: DEX loader → JNI/native → SO↔SO import/export/dlsym → IL2CPP
method/xref → reviewable control candidate. Каждое ребро сохраняет evidence class и confidence;
если статического hop не хватает, ModKit показывает PARTIAL/GAP вместо ложной end-to-end цепочки.
Menu Builder по-прежнему разделяет static evidence и executable binding и проверяет RVA/resolver
по реальному ELF. Тестовая подпись итогового APK отличается от подписи оригинала.

Подробности текущего checkpoint: [RELEASE-0.9.0-DEV24-RU.md](RELEASE-0.9.0-DEV24-RU.md).


### Dev20: native-only IL2CPP semantics + compact Menu seed

Dev20 исправляет несовпадение `sourceAttribution`: producer уже выдавал `unique-managed-interval`, а semantic verifier всё ещё ожидал старое имя. Из-за этого настоящие ARM64 direct-BL xref могли оставаться `review`. Добавлен `gameplayRelevance` 0–100, усилено понижение FX/Particle/Rendering/Quality/Lifetime/Lua binding plumbing, а relationship graph отдельно строит `nativeOnlyChains` для managed/native IL2CPP путей без выдуманного DEX/JNI hop. Полный RE JSON остаётся авторитетным; Menu Builder теперь использует компактный `re-analysis.menu.json`, чтобы не загружать сотни мегабайт JSON в память телефона. Точные дубликаты evidence удаляются при сохранении без удаления уникальных фактов.

### Dev15: bounded method-local context

После dev14 high-signal IL2CPP кандидат получает ещё один независимый слой `methodContextVerification`. Для уже выбранного метода ModKit сканирует только его точный metadata->CodeRegistration интервал и сохраняет bounded-контекст: исходящие ARM64 direct `BL` к другим уникальным managed-методам, ADRP+ADD ссылки на printable data и ранние `this + offset` load/store-кандидаты instance-методов. Полная metadata address map остаётся транзитной. Rendering/quality/presentation поверхности (`quality`, `render`, `texture`, `resolution`, `vfx/fx` и т. п.) специально понижаются до review, даже если имя содержит `state` или `speed`. Menu Builder переносит `contextVerified/contextStatus/contextEvidence` и не auto-confirm'ит новый dev15-кандидат при явном context failure.


### Dev14: semantic/xref verification

High-signal IL2CPP методы теперь проходят отдельный статический semantic/xref слой после metadata/ABI/resolver проверки. ModKit атрибутирует ARM64 direct `BL` к caller-методу по полной `global-metadata.dat + CodeRegistration` карте, а не по ближайшему отфильтрованному кандидату. `semanticVerified=true` выставляется только для application-owned callable метода с уникальным managed interval и семантически связанным caller/callee (общий owner или gameplay/debug domain). Ambiguous/framework/name-only совпадения остаются review-only. Menu Builder переносит этот статус и не auto-confirm'ит новый RE-кандидат, если semantic verifier его не подтвердил.


### Dev13: type-verified Instance Resolver + split-APK preflight

Instance Resolver теперь связывает instance-метод с объектом только при доказанной IL2CPP type identity. Помимо `TryGet(out T)` поддержаны singleton-getter’ы `get_Instance()/GetInstance()` с точным совпадением возвращаемого metadata-типа. Menu Builder проверяет target/resolver RVA в executable ELF и для split APK умеет использовать соседний `library.so` только при точном SHA-256 совпадении с RE-отчётом. Неоднозначные или name-only resolver’ы остаются review-only.

### Dev12: metadata-native Method Resolver

Method Resolver строит callable-контракт из `global-metadata.dat` и проверенного CodeRegistration/codegen-module RVA. `dump.cs` остаётся дополнительным corroboration source, а не обязательным источником ABI.
Ниже сохранена документация исходного компьютерного генератора.

# modkit — генератор мод-меню для офлайн Il2Cpp-игры на Android

На вход: `global-metadata.dat` + `libil2cpp.so`. На выход: готовый Android-модуль
(C++ + Gradle) с меню, хуками и патчами, собранный под `arm64-v8a`.

```
global-metadata.dat ─┐
libil2cpp.so ────────┴─> dump.cs / native parse ─> IR ─> rules ─> features ─> C++ проект
```

Только runtime-зависимости: Python ≥ 3.11. `pytest` — для самопроверки.

## Dev21: Universal Method Evidence

`0.9.0-dev21` отделяет доказательство существования/адреса/ABI метода от его семантической интерпретации. Полная metadata сканируется для проверки уникальности CodeRegistration; затем ARM64 direct-BL сканируется по всему множеству уникальных metadata RVA, поэтому обфусцированные `a()/b()/xqv()` обнаруживаются по структуре call graph, а не по словам в имени. Подробный callable-каталог формируется по общим API/ABI и наблюдаемым native-relation признакам без привязки к тестовым приложениям. `method_verification` явно хранит address, ABI, xref, context, semantic и runtime states; статический анализ не может сам выставить runtime confirmation.

`0.9.0-dev22` добавляет полный file-backed metadata-каталог: каждый IL2CPP method row сериализуется независимо от shortlist, имени и наличия direct-BL. Return/parameter ABI shape материализуется потоково для всего каталога, поэтому большой metadata index не требуется держать в RAM. `analysis.methods.jsonl` служит доказательной поверхностью и остаётся fail-closed: подтверждённый RVA/ABI не превращается автоматически в executable control, а runtime status остаётся `not-observed` до отдельной динамической проверки.

`0.9.0-dev23` добавляет on-demand Deep Resolver по точному `metadata_method_id`: он повторно проверяет metadata/RVA/ABI, атрибутирует входящие managed call-sites, разбирает bounded method-local context, ищет type-verified instance resolver и допускает Menu candidate только при независимом structural + semantic + context proof.

`0.9.0-dev24` расширяет Deep Resolver на ARM64 indirect flow: exact `BLR`, tail thunk/trampoline canonicalization и review-only virtual/interface/vtable correlation. Результаты Deep Resolver кэшируются по SHA-256 пары metadata/libil2cpp. Добавлен единый fail-closed маршрут `Deep Resolver → MenuSpec → APK/ELF auto-confirm → payload preflight → menu project`; Android умеет затем использовать существующий DEX-free runtime и тестовую подпись для сборки APK только когда `readyForAutoBuild=true`. Virtual slot-only и иные неоднозначные связи не повышаются до executable binding.


## Быстрый старт

```sh
python3 -m modkit selftest            # прогон всего пайплайна на синтетической игре + сборка C++ на g++
python3 -m pip install -e .           # даёт команду `modkit`

modkit inspect  -m global-metadata.dat -s libil2cpp.so
modkit dump     -m global-metadata.dat -s libil2cpp.so -o ./work   # если есть Il2CppDumper
modkit analyze  -d work/dump.cs --limit 20                        # что предлагает анализатор
modkit build    -d work/dump.cs -m global-metadata.dat -s libil2cpp.so \
                --package com.neondrift.game --app neondrift --out ./neon-mod --verify
```

`modkit build` пишет дерево:

```
neon-mod/
├── app/src/main/cpp/
│   ├── modkit.hpp / modkit.cpp     рантайм: база модуля, mprotect+патч, хуки, il2cpp-api
│   ├── game.hpp / game.cpp         сгенерировано: константы RVA, обратные вызовы, apply()
│   ├── features.inc                таблица фич (идёт прямо в код, без json-парсера)
│   ├── jni_main.cpp                точка входа: ждёт libil2cpp.so, ставит хуки, запускает меню
│   └── overlay.hpp / overlay.cpp   меню в GL-контексте игры (хук eglSwapBuffers + ImGui)
├── app/src/main/modkit/            features.json / patch_plan.json / build.json / README-BUILD.md
├── app/src/main/assets/modkit.properties   значения по умолчанию, правятся на устройстве
├── app/build.gradle, build.sh      сборка через Gradle или чистый NDK
└── third_party/                    сюда кладутся imgui/ и (опционально) dobby/
```

## Как это работает

1. **Дамп.** Основной источник — `dump.cs` от [Il2CppDumper](https://github.com/Perfare/Il2CppDumper):
   только в нём есть `RVA:` у методов. Если дампа нет, `modkit` зовёт дампер сам (`modkit dump`),
   а если думпера нет — разбирает `global-metadata.dat` сам (`modkit/metadata/`) и получает
   имена без адресов: этого хватает, чтобы понять версию метаданных, список assembly, строки
   и состав типов, но не чтобы что-то патчить.
2. **Анализ.** `modkit/analyze/rules.py` + `rules/default.json` описывают, что искать:
   числовые поля с сеттерами (`gold/gems/coins/hp/moveSpeed`), булевы тумблеры (`god|invincible|
   unlockAll`), геттеры, которые удобно заколхоидить в константу, void-методы, которые нужно
   «проглотить», и хуки для наблюдения. Каждой фиче считается `confidence`, мусор из `UnityEngine.*`
   и `System.*` отсекается, дубли схлопываются, всё упирается в `limits.max_features`.
3. **Генерация.** `modkit/codegen/` пишет один C++ TU с таблицей фич и `switch`-ом
   `apply(index, value)`, плюс `features.json` / `patch_plan.json` для UI, CI и офлайн-прошивки.

Три механизма воздействия:

| вид | что делает | когда нужен |
|---|---|---|
| `const_return` | пролог метода заменяется на `mov w0/x0, #imm; ret` (байты считает `modkit/arch/arm64.py`) | геттеры: `get_Gold`, `GetCooldown`, `GetDamage` |
| `value_set` / `toggle` / `action` | прямой вызов managed-метода по `base + rva` в ABI il2cpp (`this` в x0) | сеттеры, публичные `AddGold`, `Save` |
| `field_write` / `static_write` | запись по `this + off` или по абсолютному rva статического поля | поля без внятных сеттеров |

Для экземплярных членов генератор ставит **capture-hook** на метод класса (`Update` → `OnEnable` →
геттер/сеттер), кэширует `this` в слот и меню показывает `obj`/`no obj` — видно, до объекта
уже дошли или нет. Хук-фичи (`TakeDamage`, `Spawn`) получают обратный вызов с той же сигнатурой,
что и оригинал: аргументы уже лежат в x0–x7, поэтому проброс не требует маршалинга.

4. **Меню.** `-DMODKIT_OVERLAY=ON` хукает `eglSwapBuffers` и рисует Dear ImGui контекстом игры —
   ни root, ни `SYSTEM_ALERT_WINDOW` не нужны. Без ImGui остаётся JNI-консоль
   (`LoaderActivity`): список ключей + число, этого хватает для отладки смещений.
5. **Проверка.** `modkit verify` перечитывает `.so` и смотрит, что каждый записанный rva лежит
   в `.text` и декодируется в инструкцию, а не в данные; `modkit apply` умеет вшить
   `patch_plan.json` в копию `libil2cpp.so` (для пересборки APK).

## Команды

| команда | назначение |
|---|---|
| `modkit inspect` | что за файлы на самом деле: версия метаданных, Unity, секции/символы `.so` |
| `modkit dump` | прогнать Il2CppDumper и положить `dump.cs` в `--out` |
| `modkit analyze` | план фич текстом или `--json`, ничего не пишет |
| `modkit build` | сгенерировать модуль (`--verify` сразу проверяет rva по `.so`) |
| `modkit verify` | отдельно сверить план с `.so` |
| `modkit apply` | вшить `patch_plan.json` в копию `libil2cpp.so` |
| `modkit rules` | `--init` — развернуть дефолтные правила, `-r` — залинтовать свои |
| `modkit selftest` | весь пайплайн на синтетической игре + проверка C++ хостовым `g++` |
| `modkit runtime-check` | строгий host C++17 compile-check встроенного Android generic runtime v2 |

## Правила (`rules/*.json`)

```json
{
  "groups":        [{"id": "economy", "label": "Economy", "class": "(player|save)", "member": "(gold|gems)"}],
  "bool_toggles":  [{"id": "god_mode", "label": "God Mode", "class": "player", "member": "(god|invincib)"}],
  "const_returns": [{"id": "no_damage", "value": 0, "member": "^(TakeDamage|ApplyDamage)$"}],
  "actions":       [{"id": "debug.save_now", "kind": "action", "member": "^Save$"}],
  "ignore_classes":[{"class": "^UnityEngine"}],
  "limits":        {"max_features": 48, "min_confidence": 0.34}
}
```

`class`/`member` — регекспы без якорей, регистронезависимые. Правилу достаточно совпасть с
`Namespace.Name` **или** коротким именем класса. Пользовательские правила домердживаются к
встроенным, так что достаточно дописать пару строк под конкретную игру.

## Сборка сгенерированного модуля

```sh
git clone --depth 1 https://github.com/ocornut/imgui neon-mod/third_party/imgui
./build.sh                                   # только NDK, без Gradle
./build.sh -DMODKIT_HAVE_DOBBY=ON             # если добавили dobby (лучше переставляет хуки)
# или: cd neon-mod && ./gradlew :app:assembleRelease
```

## Сборка APK

Готовый проект генерируется в `demo/neon-drift/` (или в `--out` своей папке) и собирается
двумя способами.

**CI (рекомендую).** Файл `.github/workflows/android.yml` ставит SDK 34, NDK
`26.3.11579264`, `cmake 3.22.1`, Gradle 8.9 (AGP 8.5.2 требует Gradle ≥ 8.7), заново
прогоняет `modkit build` по `demo/target/`, делает `assembleDebug` и отдаёт два артефакта:
`loader-apk-debug` (APK лоадера) и `native-lib-arm64` (чистый `libneondrift.so`).
Кнопка — Actions → android → Run workflow. Под свою игру меняются только `target/*`,
`--package` и `--app`.

**Локально.**

```sh
export ANDROID_HOME=~/Android/Sdk
cd demo/neon-drift
gradle wrapper --gradle-version 8.9     # если хочется ./gradlew
gradle --no-daemon assembleDebug        # -> app/build/outputs/apk/debug/app-debug.apk
bash build.sh                           # только NDK, без Gradle: build/arm64-v8a/libneondrift.so
```

`release` в `app/build.gradle` подписан debug-ключом — под магазин нужен свой
`signingConfig` (keystore в `local.properties`, не в репозиторий). `SYSTEM_ALERT_WINDOW` в
манифесте нужен только fallback-консоли; меню в `eglSwapBuffers`-хуке живёт внутри GL-контекста
игры и разрешения не требует.

## Тесты

```sh
make test          # pytest tests -q
make selftest      # python3 -m modkit selftest   (то же самое + сборка C++)
make runtime-check # строгая проверка android/app/src/main/cpp/modkit_runtime.cpp
```

Что покрыто: декодеры arm64 (с сверкой инструкций и adrp/add-окружения), парсер
`global-metadata.dat` (магия/sanity/версии/вывод регионов), парсер `dump.cs`
(смещения, `StaticValue`, модификаторы, generics), читатель ELF (секции, PT_LOAD,
rva↔offset, поиск по байтам), анализатор (правила, confidence, capture-хуки, dropped),
генератор (consistency таблицы ↔ `features.json` ↔ `patch_plan.json`), CLI целиком
и — главное — **хостовый `g++ -fsyntax-only` по всем сгенерированным TU**
(`modkit/selftest/__init__.py::compile_check`), включая вариант с включённым ImGui.

## Ограничения (честно)

* Архитектура одна — `arm64`. Для `armeabi-v7a` нужен Thumb-2 энкодер; `--abi armeabi-v7a`
  приведёт к явной ошибке, а не к битым байтам.
* Патч-стаб пишет 8–24 байта в начало функции. Если пролог содержит PC-relative инструкции,
  встроенный хукер отказывается работать (в логе — рекомендация линковать Dobby).
* Статические поля читаются из аннотации `StaticValue:`; в старых дампах её нет — тогда
  фича уходит в `field_write` и требует экземпляр.
* `global-metadata.dat` разбирается для v23/24/27/29/31; на неизвестной версии включается
  эвристика регионов, и она отдаёт имена, но не адреса.
* Ни одна фича не считается «рабочей» до проверки на устройстве: смещения методов
  меняются между сборками даже когда логика не менялась, поэтому `modkit verify`
  нужно гонять на каждом билде игры.

## dev25: receiver/vtable proof

`0.9.0-dev25` добавляет name-independent exact proof для части ARM64 virtual dispatch: receiver type доказывается из managed ABI, slot-domain берётся из `global-metadata.dat`, а runtime vtable base не хардкодится — он принимается только при единственном решении по нескольким BLR callsite. Неоднозначный virtual/interface dispatch остаётся REVIEW. Подтверждённый virtual edge автоматически входит в существующую цепочку Deep Resolver → MenuSpec → APK/ELF preflight.
