# ModKit Android 0.9.0-dev4

Снимок после закрытия моста Menu Builder -> DEX-free Patch Pack -> изменённый APK.

## Новое относительно dev3

- Menu Builder умеет формировать DEX-free native payload (`modkit-payload.json` + runtime `.so` + spec + validation evidence).
- Payload привязывается к SHA-256 конкретного исходного APK (`sourceApkSha256`).
- Patch Pack проверяет SHA-256:
  - runtime `.so`;
  - `MENU-SPEC.json`;
  - `binding-validation.json`;
  - исходного APK, если payload сгенерирован Menu Builder.
- Подмена любого из перечисленных артефактов даёт `BLOCK` до применения к APK.
- Native runtime подключается без замены `classes*.dex` через проверенную ELF dependency chain (`DT_NEEDED`).
- При недостатке безопасного места в `.dynstr` используется ограниченный `safe-system-chain` fallback с повторной проверкой зависимостей runtime.
- После применения Patch Pack в APK добавляется `assets/modkit-patch-receipt.json`.
- Receipt содержит:
  - SHA-256 исходного APK;
  - SHA-256 Patch Pack;
  - SHA-256 payload manifest;
  - список изменённых/добавленных файлов;
  - before/after SHA-256 и размеры;
  - сведения о native autoload edit;
  - параметры ZIP alignment.
- Финальный SHA-256 APK возвращается отдельно, чтобы не создавать циклический self-hash внутри receipt.
- `.so` сохраняются как `ZIP_STORED` с 16 KiB data alignment.

## Проверка

- Python: 160/160 tests PASS.
- Новые регрессии подтверждают:
  - runtime hash tamper -> BLOCK;
  - применение payload к другому APK -> BLOCK;
  - receipt реально входит в итоговый APK и его before/after хэши совпадают с фактическими ELF-файлами.
- Реальный `libil2cpp.so` Drova (134 410 704 байта):
  - обычный `DT_NEEDED` append отвергнут из-за 1 байта trailing slack в `.dynstr`;
  - `safe-system-chain` успешно прошёл preflight;
  - `liblog.so` заменён на `libmk.so` в host dependency list, а runtime обязан сохранить зависимость от `liblog.so`;
  - Patch Pack inspector: `blocked=false`, BLOCK/WARN issues отсутствуют.

## Ограничение среды

- В текущем контейнере отсутствует полный Android SDK/NDK/Gradle toolchain, поэтому Android APK этого dev-снимка здесь не собирался.
- Python/ELF/Menu/Patch Pack ядро проверено локально тестами.
