# ModKit Android 0.9.0-dev12-method-resolver

Этот checkpoint продолжает dev11 и переносит IL2CPP Method Resolver с эвристики по `dump.cs` на прямую структурную корреляцию `global-metadata.dat + CodeRegistration/Il2CppCodeGenModule`.

## Что изменено

- сохранён восстановленный dev11 RE pipeline: DEX trust-boundary анализ, anti-noise корреляция, APK-set/split APK scan и `modkit-re-1.2`;
- `Metadata` теперь читает `MethodDefinition.flags`, `parameterStart` и `Il2CppParameterDefinition` для metadata v27/v29/v31;
- static/instance определяется по metadata `MethodAttributes.Static`, а не по имени или UI-эвристике;
- return type и primitive parameter types разрешаются через MetadataRegistration type table в `libil2cpp.so`;
- метод сопоставляется с native RVA только при уникальном `DLL + class + method + arity` и уникальном executable address в codegen-module method table;
- callable contract строится непосредственно из metadata; `dump.cs` используется только как дополнительная проверка, если декларация доступна;
- поддержаны безопасные для автоматического описания формы: action без managed-аргументов, `bool` setter, `float/int32` numeric setter и `TryGet(out class)` instance-resolver;
- generic/abstract, неизвестные managed reference/value types, неоднозначные RVA и несовпадающие декларации остаются review-only;
- numeric setter не auto-bind'ится до ручной проверки диапазона slider;
- instance method не auto-bind'ится без подтверждённого same-class `out_ptr_bool` resolver;
- high-signal ранжирование не позволяет тысячам обычных Unity `set_*` вытеснить `debug/console/cheat/speed/state/health/damage/money/progression` методы;
- Menu Builder получает `signatureContract`, metadata token/method id, parameters, executable RVA и provenance.

## Проверка

- Python regression suite: `214 passed`;
- реальная metadata v29: 167426 MethodDefinition;
- ParameterDefinition: 187550;
- уникально разрешено через codegen module tables: 144135 method RVA;
- MetadataRegistration type table найден;
- лениво материализовано 6851 high-signal parameter row вместо хранения всех 187550 параметров в памяти; 38611 address-bearing high-signal/zero-arg rows имеют проверяемую primitive/resolver ABI-форму.

Эти числа подтверждают структурное разрешение адресов и ABI-формы. Они не являются доказательством игрового эффекта конкретного метода без runtime-проверки.

## Версии

- Android: `versionCode 19`, `versionName 0.9.0-dev12-method-resolver`.
- Python: `0.9.0.dev12`; banner: `0.9.0-dev12-method-resolver`.
- RE report schema: `modkit-re-1.2`.
