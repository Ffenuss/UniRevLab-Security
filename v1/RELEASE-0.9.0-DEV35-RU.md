# ModKit 0.9.0-dev35 — App evidence UX / DEX context cleanup

- DEX/static REVIEW evidence больше не показывает чекбокс и поле `1` как будто это патч.
- Только строки с явным `selectable=true` из IL2CPP patch model могут участвовать в постоянном patch export.
- Menu Builder стал контекстным: обычным приложениям скрыты IL2CPP-only действия; основной путь сокращён до prepare/check/build.
- DEX method-local const-string xrefs сохраняют owning Java/Kotlin method context.
- DEX-only controls не попадают в native Menu seed без отдельного executable DEX patch contract.
- Target Profile больше не считает debug/overlay и одиночные engine-маркеры достаточным доказательством GAME/HYBRID.
- Datadog/RevenueCat/Singular/Statsig и другие известные SDK namespace отделены от application-owned logic, чтобы SDK-строки не давали ложный CONFIRMED.
- Fail-closed semantics сохранены.
