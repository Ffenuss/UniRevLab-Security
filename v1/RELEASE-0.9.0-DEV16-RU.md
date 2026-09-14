# ModKit Android 0.9.0-dev16 — AFK scale/provenance

Dev16 укрепляет dev15 для крупных IL2CPP-игр на реальной базе AFK Journey. Цель этапа — сохранить точный `metadata -> CodeRegistration -> RVA -> semantic/xref -> method-context` анализ, но не позволять middleware/compiler glue вытеснять прикладные методы и снизить пиковую память metadata/caller-resolution.

## Что изменено

- Добавлен provenance-классификатор: `game-primary`, `mixed-firstpass`, `custom-unknown`, `third-party-known`, `framework`.
- `Assembly-CSharp` получает высший приоритет; Unity/System/Mono и известные middleware (`DOTween`, `CriWare/CriMana`, `Cinemachine`, `FMOD`, `Spine`, `Newtonsoft`, `Firebase`, `UniTask`) не считаются игровыми только потому, что у метода подходящее имя.
- Обычный `debug/log` отделён от явных cheat-сигналов; debug-логирование само по себе не превращается в executable control.
- Compiler/delegate glue (`SetStateMachine`, `MoveNext`, `BeginInvoke`, `EndInvoke`, generic `Invoke`) понижен в Menu Builder shortlist, но остаётся в RE evidence/graph.
- Deep method-context выполняется только для приоритетных целей и имеет bounded budgets: до 64 методов, 16 KiB на метод и 256 KiB суммарно. Oversized/generated функции остаются review/unscanned вместо неограниченного Python-разбора.
- Полная caller attribution переведена на компактный/streaming metadata index; для отчёта сохраняются только нужные строки, а не сотни тысяч Python dict.
- `Elf.close()` освобождает крупные segment/relocation/reference структуры после специализированного анализа.
- DEX method table переведён на ленивый bounded cache; полный `method_ids` не материализуется без необходимости.
- RE/xref shortlist сначала ранжируется, затем ограничивается; middleware и compiler glue больше не забивают первые 200 кандидатов.
- Staged re-analysis разделяет тяжёлые evidence-слои и сохраняет fail-closed правила ABI/type/xref/context.

## Реальная проверка — AFK Journey

На предоставленной пользователем паре `global-metadata.dat + libil2cpp.so`:

- metadata version: 29;
- metadata methods: 167426;
- unique metadata -> executable RVA mappings: 144135;
- high-signal callable inventory: 2500 строк до UI shortlist;
- Assembly-CSharp получает приоритет над middleware;
- широкий ARM64 direct-BL поиск на high-signal целях находит статические managed xref, но диагностические/technical методы не получают executable status только по имени;
- `CommonUtils::SetDebugLogActive` может иметь semantic-xref evidence, но остаётся review, если `contextVerified=false`.

Пиковая память metadata resolver на этой AFK базе снижена примерно с 713 MiB до 385 MiB в host validation при сохранении 144135 unique mappings. Отдельные специализированные IL2CPP/xref и generic APK/native стадии проходят в bounded режиме; результат остаётся статическим evidence и не является доказательством runtime/gameplay эффекта.

## Fail-closed

Dev16 не создаёт auto-confirm, если provenance не application/game-primary, xref caller неоднозначен, method-context не подтверждён, ABI не поддержан, instance resolver не type-verified, ELF/hash preflight не проходит или кандидат относится только к middleware/framework/technical debug/rendering поверхности.

## Версии

- Android: `versionCode 23`, `versionName 0.9.0-dev16`.
- Python: `0.9.0.dev16`; banner: `0.9.0-dev16`.
