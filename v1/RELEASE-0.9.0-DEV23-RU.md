# ModKit 0.9.0-dev23

## Universal Deep Resolver

Dev23 добавляет on-demand глубокую проверку любого IL2CPP metadata-метода из полного dev22-каталога. Production-логика не содержит правил для конкретных игр/приложений; имена тестовых APK не участвуют в принятии решений.

### Pipeline

1. Выбор выполняется по точному `metadata_method_id`, а не по имени/классу.
2. Повторно доказывается metadata identity и уникальный executable CodeRegistration RVA.
3. ABI восстанавливается из metadata + MetadataRegistration отдельно от UI binding intent.
4. Выполняется bounded single-target ARM64 `BL` scan и сохраняются конкретные входящие call-sites.
5. Caller атрибутируется только к уникальному managed method interval.
6. Внутри точного interval целевого метода анализируются outgoing managed calls, strings и ранние `this+offset` accesses.
7. Instance resolver ищется без зависимости от имени: exact managed target type + отдельное machine-code proof для `return global_ptr` формы.
8. Semantic и method-local context подтверждаются раздельно.
9. Runtime остаётся `not-observed`: статический анализ не выдаётся за выполнение метода.

### Fail-closed Menu Builder

Deep Resolver создаёт `menuCandidate` только когда одновременно пройдены:

- address + ABI (и type-verified resolver для instance);
- semantic verification;
- method-local context verification;
- безопасный binding suggestion.

Даже такой candidate попадает в Menu Builder как evidence/review: executable binding остаётся пустым до независимого APK/ELF preflight существующего Menu Builder.

### Android

- В полном metadata-каталоге у каждой строки есть `Глубоко проверить метод`.
- Результаты сохраняются в `analysis-deep/method-<metadata_id>.json`.
- Карточка показывает xrefs/context/resolver/Menu gate/runtime truth.
- Menu Builder умеет создать review-spec только из прошедших все static gates Deep Resolver.
- Полный dump export включает сохранённые Deep Resolver evidence-файлы.

## Проверка checkpoint

- Python regression: **275/275** тестов пройдено.
- Native C++ contract: **3/3**.
- Production scan: app-specific правила/токены Drova/AFK/MotionPlayer/Just2D/SetFxSpeedLifeTime отсутствуют.
- Python bytecode compile: пройден.
- Android Gradle/APK: в этой среде не запускался, потому что отсутствуют Android SDK/Gradle wrapper; исходники Android-интеграции проверены статически, но APK не считается собранным или подтвержденным.
