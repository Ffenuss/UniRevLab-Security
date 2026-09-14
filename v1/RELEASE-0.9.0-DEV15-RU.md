# ModKit Android 0.9.0-dev15-method-context

Dev15 добавляет bounded method-local context поверх цепочки `metadata -> CodeRegistration RVA -> ABI -> instance resolver -> semantic/xref -> Menu Builder`. Цель — снизить ложные `state/speed/debug` совпадения и отделить технические rendering/quality методы от действительно интересных прикладных поверхностей.

## Что изменено

- `_metadata_callsite_sources` умеет одновременно атрибутировать caller и строить контекст только для выбранных high-signal методов.
- Для каждого selected метода используется точный интервал между уникальными metadata-backed method RVA; интервалы >256 KiB fail-closed.
- Внутри интервала декодируются только статические ARM64 признаки: direct `BL`, ADRP+ADD адресные materialization и ранние integer LDR/STR `[x0 + imm]` до первого вызова у instance-метода.
- Direct `BL` target повышается до managed-callee только если target RVA однозначно принадлежит одному metadata-методу.
- Printable string reference сохраняется только если адрес указывает в non-executable ELF segment.
- `this+offset` остаётся неназванным кандидатом; field name появляется только при независимом точном `dump.cs owner + offset` совпадении.
- Новый `methodContextVerification` отделён от обычного confidence и от dev14 `semanticVerification`.
- `contextVerified=true` требует address-bearing callable target, application provenance и хотя бы один точный method-local managed relation; string/field evidence используется только как corroboration.
- Добавлен отрицательный semantic context для rendering/quality/presentation терминов: `quality`, `render`, `texture`, `shadow`, `resolution`, `mipmap`, `graphics`, `visual`, `vfx/fx`, `particle`, `camera`, `shader`, `lod` и др. Такие методы остаются review-only.
- Menu Builder переносит `contextVerified`, `contextStatus`, `contextConfidence`, `contextEvidence`, `contextBlocker` и блокирует auto-confirm только при явном dev15 context failure. Старые dev14/manual MenuSpec без этих полей остаются совместимыми.
- Android RE Workspace показывает сводку context verification и bounded method-context counts; Menu Builder показывает Method context status у каждого кандидата.

## Реальная проверка на сохранённой Drova-паре

Проверка выполнена статически на сохранённых `global-metadata.dat` v29 (~20 MiB) и ARM64 `libil2cpp.so` (~138 MiB). Полная metadata resolution сохранила прежнюю базу: 167426 metadata methods и 144135 unique executable RVA.

Для 16 методов, которые dev14 ранее пометил semantic-verified, dev15 построил exact method-local context. Все 16 были сняты с auto-confirm как технические/presentation поверхности: `MemoryQualityState::*`, `DeviceQualityState::Reset`, `IGame.QualityManager::set_qualityLevel` и `BattleFxHelper::*`. Это не удаление находок: они остаются в review с blocker `technical-rendering-or-quality-surface`.

Показательный пример: `BattleFxHelper::SetGlobalFrozenState` действительно имеет exact local `BL -> BattleFxHelper::SetFrozenState`, но владелец `BattleFxHelper` содержит FX/presentation provenance, поэтому связь сохраняется как evidence, а автоматический gameplay вывод запрещён.

## Fail-closed

Dev15 не повышает метод, если interval неоднозначен/слишком велик, target BL не принадлежит одному metadata-методу, строка лежит в executable segment, field offset не имеет точного owner+offset corroboration, target относится к framework/technical rendering surface, ABI/signature не поддержан, instance resolver не type-verified или ELF preflight не проходит.

## Версии

- Android: `versionCode 22`, `versionName 0.9.0-dev15-method-context`.
- Python: `0.9.0.dev15`; banner: `0.9.0-dev15-method-context`.
