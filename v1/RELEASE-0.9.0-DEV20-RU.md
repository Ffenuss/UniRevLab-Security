# ModKit 0.9.0-dev20

Checkpoint dev20 усиливает статическую IL2CPP-корреляцию и устойчивость Menu Builder на больших отчётах.

- semantic verifier принимает текущее `unique-managed-interval` и legacy `unique-metadata-method-interval`;
- каждому control candidate назначается `gameplayRelevance` 0–100 для ранжирования, а не как доказательство поведения;
- FX/Particle/Rendering/Quality/Lifetime и Lua binding glue остаются review-only;
- relationship graph сохраняет DEX-root chains и отдельно `nativeOnlyChains`, не синтезируя отсутствующий DEX/JNI hop;
- `re-analysis.menu.json` — компактный sidecar для Menu Builder, полный `re-analysis.json` остаётся авторитетным;
- точные дубликаты evidence дедуплицируются без удаления уникальных фактов.

Все executable bindings по-прежнему fail-closed: RVA, ABI, semantic/context и resolver проверки не заменяются одним именем метода.
