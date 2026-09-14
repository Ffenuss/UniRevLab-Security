# ModKit 0.9.0-dev30

## Installed Game Scanner / APK-set discovery

Dev30 добавляет автоматический анализ установленной игры или приложения без ручного поиска split APK.

### Что делает ModKit

- показывает launchable установленные приложения, игры поднимаются выше по Android `ApplicationInfo.CATEGORY_GAME`;
- получает `sourceDir` и все `splitSourceDirs` выбранного пакета;
- копирует base + splits только в private storage ModKit, оригиналы не изменяются;
- собирает локальный APK-set и ведёт provenance каждого split;
- ищет `global-metadata.dat` во всех split APK;
- ищет `libil2cpp.so` во всех split APK и автоматически выбирает ARM64 (`arm64-v8a`);
- если metadata и ARM64 libil2cpp найдены в разных splits, использует их как одну установленную сборку;
- при полной IL2CPP-паре автоматически запускает Rodroid/metadata/Evidence Graph/Gameplay Discovery и готовит read-only Runtime Probe seed;
- если полной пары нет, сканирует весь APK-set как единый target: DEX, все `.so`, Unity/content assets, monetization/trust-boundary evidence и Menu Builder review candidates;
- package/content evidence для Gameplay Discovery теперь читает вложенные split APK, а не только base.apk;
- сохраняет `installed-scan.json`, `installed-apk-set.zip` и при необходимости `game-native-split.apk` для точного provenance packaging target.

### Fail-closed модель сохранена

Installed scan не превращает строковые/DEX совпадения в executable control. `Discovery`, `WATCH/PROBE`, `RUNTIME TEST` и executable binding остаются разными уровнями доказательности. Серверные покупки/валюта остаются security/trust-boundary findings и не получают автоматический bypass.

### Android package visibility

Dev30 не запрашивает широкое `QUERY_ALL_PACKAGES`. Для списка установленных приложений используется Android `<queries>` для `ACTION_MAIN + CATEGORY_LAUNCHER`.
