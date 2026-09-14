# ModKit 0.9.0-dev27 — Gameplay Evidence Graph

Dev27 переводит ModKit от списка технических IL2CPP-методов к доказательному поиску игровых сущностей без правил под конкретные игры.

## Gameplay Discovery

Пользовательский слой теперь агрегирует доказательства по доменам: HP/life-state, damage, currency, level/XP, movement/speed, mana/energy/stamina, cooldowns, inventory/resources, camera/FOV, world/time/weather и debug/dev surfaces.

Метод, поле или package string не становится игровым control только из-за имени. Статусы discovery отделены от executable binding: `CONFIRMED`, `FIELD OBSERVED`, `PACKAGE OBSERVED`, `SCRIPT/CONTENT SEARCH`, `REVIEW`, `NOT FOUND LOCAL`.

## Shared Evidence Graph

Один file-backed native graph хранит exact callers/callees, direct BL/tail-B, bridge relations, engine sinks, typed field accesses и доменные доказательства. Deep Resolver использует dense `metadataMethodId -> byteOffset`, RVA index и graph fast-path вместо повторного полного чтения metadata/ELF для каждого кандидата.

Для legacy/virtual/interface случаев сохранён строгий fallback с BLR/vtable/thunk анализом.

## Exact runtime fields

`FieldDefinition -> MetadataRegistration.fieldOffsets` позволяет связывать ARM64 loads/stores с точным managed field. Typed tracking поддерживает `x0=this`, typed `x1-x7`, CFG-aware register propagation, MOV/object-pointer loads, byte/halfword/integer/scalar-FP accesses и cross-object fields.

## File-backed analysis

`analysis.json` теперь компактный manifest. Полный каталог, индексы, candidates/discoveries, Evidence Graph, fields, resolver/autopilot indexes и gameplay coverage хранятся отдельно, без дублирования сотен мегабайт JSON в памяти.

## Fail-closed Menu Builder

Gameplay discovery не равен executable binding. Control создаётся только после exact address/ABI, semantic/context proof, безопасного static/instance binding и APK/ELF preflight. Instance methods требуют type-verified resolver. Numeric setters без независимо доказанного диапазона остаются evidence-only (`numeric-range-review-required`).

## AFK regression fixture

AFK используется только как внешний regression target; production resolver не содержит AFK-specific имён или правил. На текущем fixture подтверждены exact fields для life-state, progression и movement, а неизвестный локальный numeric HP не подменяется ложным setter-ом.

Локальная release-validation: 291/291 pytest, selftest OK, runtime-check OK. Android assemble/lint, APK unzip, zipalign и apksigner verify выполняются GitHub Actions на ветке `Modkit1`.
