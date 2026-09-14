# ModKit 0.9.0-dev24

## Universal indirect-flow resolver + Deep → Menu pipeline

Dev24 продолжает универсальный resolver без правил для конкретных игр/приложений. Drova/AFK и любые другие APK могут использоваться только как regression fixtures; production-решения строятся по metadata, executable addresses, ABI и machine-code evidence.

### ARM64 Deep Resolver

1. Прямые `BL → RVA` остаются базовым exact evidence.
2. Tail thunk/trampoline канонизируется до конечной реализации; `BL → thunk → method` сохраняется как отдельный доказанный edge.
3. Локальный register-flow разрешает exact `BLR`, когда target выводится из статически доказуемой address/pointer цепочки.
4. Object/vtable/interface-подобные `BLR` сохраняются как `virtualCandidates`; наличие slot shape или function-pointer data slot само по себе **не** подтверждает конкретный managed target.
5. Function-pointer slots и virtual callsites используются как corroboration, но `dispatchCorrelation.confirmedExactTarget` остаётся false до доказательства receiver type или exact pointer flow.
6. Method-local context теперь отдельно хранит прямые и косвенные исходящие managed calls.
7. Runtime truth остаётся `not-observed`: статический resolver не притворяется динамической проверкой.

### Deep Resolver cache

Deep-result кэшируется по exact metadata method identity + SHA-256 `global-metadata.dat` + SHA-256 `libil2cpp.so` + версии resolver engine/schema. Повторная проверка неизменённой пары файлов может вернуть `cache.hit=true` без повторного полного ELF scan. Изменение входного файла меняет cache identity.

### Связка с Menu Builder

Добавлен единый fail-closed pipeline:

`full metadata catalog → Deep Resolver → MenuSpec → APK/ELF auto-confirm → generated menu project → payload preflight`

Метод становится автоматическим control только если одновременно выполнены structural address/ABI/resolver gates, semantic verification, method-local context verification и поддерживаемый binding contract. Затем RVA, целевой ELF и SHA проверяются по выбранному APK.

- `action` может стать `button`.
- `bool_setter` может стать `toggle`.
- `number_setter` не получает выдуманный диапазон: без подтверждённого/заданного slider range остаётся review.
- Instance method требует type-verified resolver.
- Virtual/interface slot-only evidence остаётся review.
- Любой BLOCK в APK/ELF preflight откатывает executable binding.

### Android

Menu Builder получил:

- `Авто: Deep Resolver → подтверждённое меню`;
- `Авто: Deep Resolver → Menu → подписанный APK`.

Второй маршрут запускается только после `readyForAutoBuild=true`, затем использует существующий DEX-free menu payload, применяет его к копии APK и подписывает результат тестовым ключом ModKit. Это не восстанавливает оригинальную подпись приложения.

Карточка Deep Resolver показывает direct/thunk/BLR xrefs, review-only virtual candidates, function-pointer slots, outgoing direct/indirect calls и cache HIT/MISS.

## Проверка checkpoint

- Полный Python regression: **281/281** тестов.
- Native C++ contract: **3/3**.
- `python -m modkit selftest`: **OK**, включая strict compile generated C++ runtime.
- Python bytecode compile: **OK**.
- Production scan: токены/правила `Drova`, `AFK`, `MotionPlayer`, `Just2D`, `SetFxSpeedLifeTime` отсутствуют в `modkit/` и Android production sources.
- Android Gradle/APK checkpoint build в текущем окружении не запускался: отсутствуют Gradle wrapper, Gradle и Android SDK. Поэтому Android-код считается source-integrated/test-covered, но готовый dev24 APK этим checkpoint не подтверждён.
