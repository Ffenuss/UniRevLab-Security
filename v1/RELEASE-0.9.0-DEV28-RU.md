# ModKit 0.9.0-dev28

## Главное

Dev28 развивает универсальный Menu Runtime поверх dev27 Evidence Graph и fail-closed binding. Production-код не содержит правил под конкретную игру.

### Runtime Menu v3

- вкладки `ALL / Combat / Player / Resources / World / Debug`;
- категория передаётся из `MenuSpec` как UI-only metadata и не влияет на executable eligibility;
- drag панели и свёрнутой кнопки использует общую геометрию с hit-testing;
- после перемещения кнопки нажимаются в фактической позиции панели;
- визуальная подсветка строки на нажатие;
- `Reset All` возвращает non-action controls к исходным default и применяет только уже подтверждённые bindings;
- runtime config schema v3, при этом чтение v1/v2 сохранено;
- Menu Builder по-прежнему fail-closed: неподтверждённые discovery/review методы не попадают в executable runtime.

### Безопасность binding

Dev28 не добавляет game-specific offsets, автоматические purchase/currency bypass и не повышает review evidence до callable control. Exact RVA, ABI, semantic/context gates, resolver для instance methods и APK/ELF preflight остаются обязательными.

## Проверки

- 292/292 Python tests
- strict host C++ compile contract
- selftest
- runtime-check
- Android assembleDebug/lintDebug
- unzip/zipalign/apksigner в GitHub Actions
