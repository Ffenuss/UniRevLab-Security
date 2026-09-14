# ModKit 0.9.0-dev29

## Runtime Probe / WATCH

Dev29 разделяет discovery и execution. Exact gameplay field evidence больше не исчезает только потому, что для него пока нет безопасного executable binding.

### Новый read-only runtime config v4

- `WATCH/PROBE` для exact primitive IL2CPP fields: `bool / int32 / uint32 / float`;
- probe хранит exact owner type + field name + runtime offset;
- runtime разрешает `Il2CppClass` через экспортированный IL2CPP API;
- по нажатию `SCAN` выполняется read-only поиск live object exact класса в доступных heap mappings;
- чтение поля выполняется через `process_vm_readv` своего процесса;
- после нахождения объект наблюдается и значение помечается `*`, когда меняется;
- probe controls никогда не проходят через `apply_control`, setter/action/patch не вызываются;
- runtime config v1/v2/v3 остаются читаемыми.

### Gameplay Coverage → Probe Menu

Menu Builder получил отдельные операции:

- `Runtime Probe: gameplay fields → WATCH menu`;
- `Runtime Probe → подписанный тестовый APK`.

Probe Menu строится только из exact field offsets, уже доказанных MetadataRegistration/Evidence Graph. Для split APK packaging preflight отдельно проверяет наличие arm64 native host. Если base APK не содержит native `.so`, выводится `NATIVE_SPLIT_APK_REQUIRED` вместо ложного READY.

### AFK regression

На текущем AFK regression target из `1.zip` dev29 формирует 39 read-only WATCH fields. Включены, среди прочего:

- `IGame.RealMapUnit.alive @ 0x19`;
- `IGame.HeroData.level @ 0x14`;
- `IGame.HeroData.rank @ 0x18`;
- `IGame.AvatarActor.globalSpeed @ 0x88`;
- `IGame.AvatarActor.actionSpeed @ 0x8c`;
- `IGame.InterActCD.cd @ 0x28`;
- camera/FOV exact fields;
- weather/world exact fields;
- debug flags.

`base.apk` из этого regression target является split-base без native libraries, поэтому ProbeSpec = READY, а single-APK payload = REVIEW с `NATIVE_SPLIT_APK_REQUIRED`. Это упаковочное ограничение, не потеря field evidence.

## Проверки

- 298/298 Python tests;
- strict host C++ runtime compile;
- selftest;
- runtime-check;
- Android assembleDebug/lintDebug и APK verification должны пройти в финальном GitHub Actions release run.
