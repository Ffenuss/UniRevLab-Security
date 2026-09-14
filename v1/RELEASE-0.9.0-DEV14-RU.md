# ModKit Android 0.9.0-dev14-semantic-xref

Dev14 усиливает цепочку `metadata -> CodeRegistration RVA -> ABI -> instance resolver -> Menu Builder` отдельной статической semantic/xref-верификацией. Цель этапа — не считать метод «игровым контролом» только потому, что его имя похоже на `SetSpeed`, `SetState` или `EnableDebug`.

## Что изменено

- ARM64 direct-call scanner ускорен: вместо Python-перебора каждой 4-байтной инструкции используется C-level поиск допустимого старшего байта `BL` с обязательной проверкой выравнивания и полным декодированием immediate.
- `augment_function_correlations` теперь может получать `metadata_path` и строит точный caller attribution через полную таблицу IL2CPP методов.
- Для caller interval используются **все** уникальные metadata->CodeRegistration method starts, а не только high-signal subset из RE JSON.
- В отчёт сохраняются только caller'ы реально найденных xref — полная 144k method map остаётся временной и не раздувает JSON.
- Новый `semanticVerification` отделён от обычного confidence и от ABI/resolver verification.
- `semanticVerified=true` требует одновременно:
  1. уникальный address-bearing metadata callable contract;
  2. application-owned target;
  3. точный `ARM64 BL`;
  4. `unique-metadata-method-interval` для caller;
  5. semantic affinity через тот же owner или общие gameplay/debug tags.
- Ambiguous shared RVA, framework-only методы, name-only совпадения и вызовы без semantic affinity остаются review-only.
- Menu Builder переносит semantic status/confidence/evidence и блокирует auto-confirm для кандидата, который dev14 verifier явно оставил неподтверждённым.
- Старые/manual MenuSpec остаются обратно совместимыми: отсутствие semantic-полей (`None`) не подменяется ложным `False`.
- Android RE Workspace показывает сводку `verified / correlated / review`, Menu Builder — semantic/xref статус каждого кандидата.

## Реальная статическая проверка

На сохранённой паре Drova (`global-metadata.dat` v29 + ARM64 `libil2cpp.so`) использована выборка 50 high-signal методов из dev12 validation:

- 35 точных direct `BL` ссылок на эту выборку;
- 35/35 callsite'ов атрибутированы через полную metadata method map;
- 46 reviewable control candidates в полученной выборке;
- 16 получили `verified-static-xref`;
- 2 получили `correlated-review`;
- 28 оставлены обычным `review`.

Примеры подтверждённой статической связи: `BattleFxHelperWrap::SetFrozenState -> BattleFxHelper::SetFrozenState`, `BattleFxHelperWrap::SetFxSpeed -> BattleFxHelper::SetFxSpeed`, а также одноимённые quality/state wrapper связи. Это доказывает статическую call relationship и семантическую согласованность имён/доменов, но **не** доказывает runtime gameplay effect.

## Fail-closed

Auto-confirm не производится, если нет точного metadata caller interval, если caller attribution неоднозначна, если target относится к framework surface, если xref не имеет semantic affinity, если ABI/signature не поддержан, если instance resolver не type-verified или если ELF preflight не проходит.

## Версии

- Android: `versionCode 21`, `versionName 0.9.0-dev14-semantic-xref`.
- Python: `0.9.0.dev14`; banner: `0.9.0-dev14-semantic-xref`.
