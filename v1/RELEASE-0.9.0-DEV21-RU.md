# ModKit 0.9.0-dev21

Dev21 переводит IL2CPP Method Resolver с тестово-семантического shortlist на универсальную evidence-based архитектуру.

- вся `global-metadata.dat` по-прежнему проходит полный scan уникальности `CodeRegistration`/RVA;
- подробный callable-каталог удерживается по общим признакам API/ABI (`Set*`, `Enable*`, `Toggle*`, `Apply*`, resolver shapes), а не по именам конкретных игр;
- новый `modkit-method-verification-1.0` разделяет `address`, `ABI`, `xref`, `method context`, `semantic` и `runtime` уровни доказательств;
- статический анализ никогда не выставляет `runtimeConfirmed=true`: реальное runtime-поведение остаётся отдельным будущим dynamic-verifier слоем;
- ARM64 direct-BL prepass теперь сканирует **все уникальные CodeRegistration RVA**, поэтому метод с обфусцированным именем (`a`, `b`, `xqv`) может быть удержан по факту реального native-call relation;
- при большом числе вызванных metadata-методов используется name-independent bounded selection `frequency + rare + address-spread`, чтобы framework hot paths не вытесняли редкие методы;
- повторный typed materialization выполняется только для реально наблюдавшихся target RVA, сохраняя Android heap bounded;
- generic address-confirmed callable может попасть в `controlCandidates` без gameplay-словаря, но остаётся fail-closed по ABI/resolver/context;
- semantic verifier теперь требует минимум два независимых смысловых источника для одного тега; same-owner xref сам по себе больше не считается подтверждением поведения;
- для обфусцированного метода семантика может быть восстановлена только при согласовании независимых источников, например managed peer + method-local string/field evidence;
- direct-BL scanner имеет fallback на executable `PT_LOAD`, поэтому stripped ELF без section table не теряет xref coverage;
- type-verified instance resolver продолжает быть обязательным для instance binding;
- Menu Builder переносит `method_verification` в spec, показывает Method proof и дополнительно проверяет address/ABI перед auto-confirm;
- Android-каталог `analysis.ui.jsonl` теперь содержит universal metadata callable rows и их method proof;
- Drova/AFK больше не являются условиями resolver-а: они остаются только regression/reference datasets.

Архитектурное правило dev21: **имя помогает найти кандидата, но никогда не подтверждает адрес или поведение**. Обфускация имени не мешает структурному подтверждению `metadata identity → unique CodeRegistration RVA → executable segment → direct BL/xref`; неизвестная семантика при этом честно остаётся `unclassified`.
