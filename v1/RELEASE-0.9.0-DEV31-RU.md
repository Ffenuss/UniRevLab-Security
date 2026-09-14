# ModKit 0.9.0-dev31 — PackageTarget / APK-set correctness

Первая фаза dev31 закрывает главный разрыв dev30 между анализом split-пакета и последующей сборкой.

## Что изменено

- Добавлен стабильный контракт `modkit-package-target-1.0` (`installed-target.json`).
- Target хранит package/version, SHA-256 всех APK, `targetId`, completeness, выбранные metadata/libil2cpp и точный `patchOwner`.
- Installed Scanner теперь различает `COMPLETE` и `PARTIAL`; неполный APK-set можно анализировать, но сборка целого набора блокируется.
- Локальные имена split APK получают индексный префикс, исключающий коллизии после sanitization.
- Перед сборкой проверяются SHA-256 всех APK target; stale/tampered target требует повторного Installed Scanner.
- `global-metadata.dat` проверяется по IL2CPP magic/version, `libil2cpp.so` — по ELF64/AArch64 header. Одних имён файлов больше недостаточно для статуса полной пары.
- Для установленного split-пакета ModKit изменяет APK, который реально владеет `libil2cpp.so`, а не всегда `base.apk`.
- При APK-set build все APK набора переподписываются одной локальной AndroidKeyStore identity и экспортируются как `.apks` ZIP с `modkit-target.json`.
- Main build, Patch Pack и Menu Builder/preflight переведены на owning APK target.
- Создаётся project/session scaffold `projects/<targetId>/{analysis,reports,build}` с `target.json`, `session.json`, `active.project` и снимками ключевых analysis/re/menu результатов. Тяжёлые JSONL пока не дублируются.
- Главный экран показывает `COMPLETE/PARTIAL` и автоматически предлагает APK или APK-set в зависимости от target.

## Совместимость

Одиночный APK и ручной выбор metadata/libil2cpp продолжают работать по старому single-APK пути. Fail-closed Menu gates, ABI/context/semantic proof и статическое/runtime разделение не ослаблялись.

## Signing hardening

- Встроенный PKCS#12 private key удалён из assets.
- Для тестовых APK ModKit создаёт RSA-3072 identity в AndroidKeyStore.
- Private key остаётся неэкспортируемым на устройстве.
- SHA-256 fingerprint локального сертификата записывается в экспорт APK-set.
- Все splits одного APK-set подписываются одной identity.

Импорт внешнего production/customer keystore остаётся отдельной UI-функцией: dev31 не подменяет безопасный локальный default пользовательским production key.
