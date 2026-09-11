# ModKit 0.9.0-dev26 — Menu Autopilot

Dev26 связывает полный IL2CPP metadata-каталог с Deep Resolver и Menu Builder без привязки к тестовому приложению.

Pipeline: full catalog structural prefilter → bounded/diverse Deep Resolver queue → semantic/context proof → canonical RVA deduplication → typed MenuSpec → APK/ELF auto-confirm → payload preflight.

Имена и semantic tags используются только для ранжирования очереди. Они не могут создать executable binding. Каждый control заново проходит Deep Resolver. Instance-методы требуют type-verified resolver. Числовые setters без независимо подтверждённого диапазона остаются review.

Локальная проверка: 288/288 pytest, selftest OK, runtime-check OK. Android assemble/lint выполняется отдельно в GitHub Actions ветки Modkit1.
