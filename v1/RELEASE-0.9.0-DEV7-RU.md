# ModKit Android 0.9.0-dev7

## Auto-build decision records

- `auto_confirm_bindings` теперь возвращает `promotionRecords` с полной причиной каждого автоматического повышения: signature, ABI, static/instance, target RVA, resolver RVA, target `.so`, источник evidence и точный результат ELF-preflight.
- Схема auto-confirm обновлена до `modkit-menu-auto-confirm-1.1`.
- Сводный preflight обновлён до `modkit-menu-preflight-1.1`.

## Строгая автосборка

- `readyForPayload` по-прежнему разрешает ручную сборку подтверждённого подмножества controls.
- Новый `readyForAutoBuild` требует, чтобы не осталось high-confidence callable evidence, которое автосборка молча проигнорировала бы.
- Такие элементы считаются `actionableReview` и дают `ACTIONABLE_REVIEW_REMAINING`; Android Auto APK останавливается и предлагает открыть Menu Builder.
- Ручная сборка остаётся доступной отдельно и не меняет прежнюю семантику `readyForPayload`.

## Более глубокий анализ всех .so

- Native inventory теперь сохраняет количество functions/imports/exports и bounded samples symbol names.
- Для каждой библиотеки отдельно выводятся JNI exports / `JNI_OnLoad` / `RegisterNatives` marker.
- RE Workspace строит `nativeRelations`: внутренние `DT_NEEDED` связи между `.so`, внешние dependencies, dynamic-loading (`dlopen`/`dlsym`) и render/input (`eglSwapBuffers` / `AMotionEvent_getAction`) surfaces.
- Эти данные являются структурным evidence и не выдаются за runtime execution trace.

## Android UI

- RE Workspace показывает число native links, JNI, dynamic-loading и render/input surfaces.
- Menu Builder показывает отдельно готовность manual payload и строгой Auto APK, включая `actionableReview`.

## Версии

- Android: `versionCode 14`, `versionName 0.9.0-dev7`.
- Python: `0.9.0.dev7`; banner: `0.9.0-dev7`.
