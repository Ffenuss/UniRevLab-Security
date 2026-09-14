# ModKit Android 0.9.0-dev11

Checkpoint dev11 основан на exact-built dev10, из которого GitHub Actions успешно собрал APK.

## Что изменено

- APK-set/split APK/XAPK/APKS ZIP: вложенные APK анализируются как единый набор, exact duplicate artifacts дедуплицируются по SHA-256.
- APK-set path использует production IL2CPP engine для metadata v27/v29/v31; legacy CLI `metadata.reader` остаётся отдельным compatibility TODO и не используется для этого AFK-прохода.
- Evidence calibration: anti-cheat отделён от cheat controls; framework/rendering/debug noise больше не повышает gameplay/menu confidence.
- ShadowHook и другие hook SDK markers сами по себе не считаются доказательством gameplay hook stack.
- Cross-artifact composite findings требуют как минимум correlated base surfaces; directed graph остаётся источником end-to-end structural evidence.
- DEX method indexing: добавлен dependency-free reader class/method/proto/const-string/invoke tables.
- Trust-boundary analysis: monetization DEX methods помечаются как local/platform/server-backed по прямым ссылкам и строкам; confidence разделён на presence/behavior/actionability.
- Control candidates фильтруют defensive/runtime/framework diagnostics.

## Проверка на AFK Journey 1.7.31

- Unity 2021.3.48f1 / IL2CPP metadata v29.
- `base.apk` не содержит arm64 `libil2cpp.so`, companion ABI artifact корректно объединяется с base.
- Metadata: 132 images, 21 502 type definitions, 167 426 methods, 105 960 fields.
- После noise filtering: menu=`candidate 0.36`, debug/gameplay=`candidate 0.48`, hook-framework не подтверждён, actionable control candidates=`0`.
- Monetization DEX surface содержит Lilith SDK / Google Billing orchestration и server-backed order/sign/cashier request flows; это evidence архитектуры, не утверждение об уязвимости.
- Managed anti-cheat surface: `IGameMap::GetMapCheatDetectionPath` (RVA `0x1EC2800`), `MapRuntime.Map::GetMapCheatDetectionPath` (RVA `0x1BFBF48`), `MapAntiCheatObjInteractNetData`. Serialize callbacks последнего являются тривиальными `RET`, то есть класс выглядит как data carrier; прямых ARM64 BL-callers к двум path methods в bounded scan не найдено, поэтому виртуальный/косвенный dispatch не выдаётся за подтверждённый caller.

## Версия

- Android: `versionCode 18`, `versionName 0.9.0-dev11`.
- Python: `0.9.0.dev11`; banner: `0.9.0-dev11`.

## Release gates

- `pytest`: 214 passed.
- `modkit selftest`: PASS.
- `modkit runtime-check`: PASS (strict clang++ host syntax/ABI gate).
