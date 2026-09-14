# ModKit Android 0.9.0-dev13-instance-resolver

Этот checkpoint продолжает dev12 и усиливает цепочку `metadata method -> instance resolver -> ELF preflight -> Menu Builder`. Автоматическое executable-состояние теперь возможно только при структурно подтверждённой идентичности IL2CPP-типа объекта.

## Что изменено

- `Il2CppType.data` коррелируется с `TypeDefinitionIndex`, поэтому return/parameter type может быть связан с конкретным `DLL + class`;
- `TryGet(out T)` считается подтверждённым resolver только если `T` точно совпадает с классом целевого instance-метода;
- добавлен singleton resolver `get_Instance()/GetInstance()/instance`: zero-arg static pointer-return getter допускается только при точном совпадении возвращаемого IL2CPP-типа;
- resolver-контракт хранит `resolverTargetTypeIndex`, image/class, match strategy и provenance;
- same-owner/name-only совпадения сохранены для review, но больше не могут автоматически сделать control executable;
- Menu Builder требует `resolverVerified=true`, поддерживаемый resolver ABI и валидные resolver/target RVA;
- runtime-config поддерживает `out_ptr_bool` и `return_ptr`; C++ runtime различает обе ABI-формы;
- source APK и target `libil2cpp.so` могут быть привязаны SHA-256 к MenuSpec;
- для split APK, где base APK не содержит `libil2cpp.so`, preflight может использовать соседний `library.so`, но только при точном совпадении ожидаемого SHA-256;
- hash mismatch, отсутствие hash provenance, неверный RVA или непроверенный resolver приводят к BLOCK, а не к автоматическому binding;
- JSON MenuSpec schema обновлена до `modkit-menu-1.1`, validation schema — до `modkit-menu-validation-1.2`.

## Реальная структурная проверка

На сохранённой metadata v29 + `libil2cpp.so`:

- 167426 `MethodDefinition`;
- 144135 методов имеют уникально разрешённый executable RVA;
- найдено 143 структурных resolver-кандидата;
- 142 resolver-кандидата имеют подтверждённую metadata type identity;
- из них 141 `return_ptr` singleton getter и 2 `out_ptr_bool` `TryGet` (один из них type-verified);
- 2074 primitive instance-метода имеют ABI-форму, потенциально совместимую с Menu runtime;
- 55 instance-методов получили exact type-verified resolver pair.

Это доказывает адрес/ABI/type-correlation, но не утверждает игровой эффект метода без runtime-наблюдения.

## Split-APK end-to-end preflight

Сохранённый `base.apk` не содержит `lib/` entries. Для контрольного `FirstPaintController::HideFirstPaint` Menu Builder:

1. проверил SHA-256 исходного base APK;
2. проверил SHA-256 внешнего `library.so` против RE provenance;
3. подтвердил `FirstPaintController::get_Instance` как `return_ptr` resolver с exact metadata type match;
4. проверил resolver RVA и target RVA как executable ELF addresses;
5. перевёл контроль в executable binding без BLOCK.

Контрольная пара: target RVA `45672284`, resolver RVA `45670120`. Код целевой игры при этой проверке не исполнялся.

## Версии

- Android: `versionCode 20`, `versionName 0.9.0-dev13-instance-resolver`.
- Python: `0.9.0.dev13`; banner: `0.9.0-dev13-instance-resolver`.
- RE report schema: `modkit-re-1.2`.
