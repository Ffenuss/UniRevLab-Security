# ModKit Android 0.9.0-dev10

## Что добавлено

- `relationshipGraph` (`modkit-static-relationship-graph-1.0`) в полном RE-отчёте.
- Узлы: DEX, native library, native function, managed/IL2CPP method, control candidate.
- Рёбра не смешиваются: `loadLibrary`, JNI export, ARM64 direct `BL`, `DT_NEEDED`, embedded library ref, exact import→export, function-scoped dlsym string-xref, managed direct call, candidate provenance.
- Полные цепочки (`completeChains`) строятся только при непрерывной directed static evidence path от DEX loader до control candidate.
- Незавершённые loader paths сохраняются в `partialLoaderChains`; неподключённые controls — в `gaps`.
- Никакой отсутствующий hop между helper `.so` и `libil2cpp.so` не угадывается.
- Export RVA теперь сохраняется для retained dynamic exports и используется для точной стыковки function-level graph.
- Control candidate extraction больше не поднимает ELF `.debug_*` section names как developer/debug controls.
- Android RE Workspace показывает graph node/edge counts, CHAIN/PARTIAL/GAP.

## Реальная проверка Drova menu pack

На `drova-touch-menu-v3-fixed(1).zip` ModKit сохранил DEX→native loader relation и bounded partial JNI/native paths. Function-scoped `install → A64HookFunction` остаётся отдельным статическим evidence fragment, если отсутствует доказанный прямой hop от JNI chain. Это намеренно: граф не превращает correlation в runtime trace.

## Версии

- Android: `versionCode 17`, `versionName 0.9.0-dev10`.
- Python: `0.9.0.dev10`; banner: `0.9.0-dev10`.
