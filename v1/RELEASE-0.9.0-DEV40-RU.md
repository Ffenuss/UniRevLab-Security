# ModKit 0.9.0-dev40 — Simple Mode pipeline, cache, progress and confirmation ladder

- Добавлена отдельная шкала подтверждения: `FOUND_STATIC → APP_OWNED → FLOW_CONFIRMED → LOCATOR_CONFIRMED → RUNTIME_CONFIRMED → PATCH_READY`; `SERVER_AUDIT`, `SDK_NOISE`, `FRAMEWORK_NOISE` остаются отдельными ветками. Locator-тип (`READY_DEX/NATIVE/SCRIPT/RESOURCE`) больше не смешивается со степенью доказанности.
- Gameplay-классификация получила канонические домены и синонимы для HP/health, damage/attack/defense, speed/timeScale, cooldown, currency, level/XP, inventory/reward/drop, camera/FOV, movement/teleport/gravity/jump, mana/stamina/energy.
- Simple Mode получил полный набор фильтров, поиск, объяснение «почему подтверждено / почему ещё не Patch Ready» и handoff точного locator в Decompiler / Native / File Workspace / RE Workspace.
- Добавлен структурированный `simple-progress.json`: этап/всего, оставшиеся этапы, elapsed, число кандидатов/locator/PATCH_READY. В UI есть явная кнопка отмены; между дорогими этапами проверяется cancel flag.
- Добавлен первый безопасный инкрементальный cache layer: SHA-256 каждого APK/split + target digest. При неизменном target переиспользуются уже проверенные analysis/security reports; изменение любого split переводит pipeline на fresh path. Кэш не снижает требования fail-closed validation.
- Network/API/Crypto scan остаётся полностью пассивным. Автоматический server/payment/economy bypass не добавлялся.
- Автосборка по-прежнему разрешена только для MenuSpec controls с проверенным executable binding/RVA и не включает server/trust findings.
