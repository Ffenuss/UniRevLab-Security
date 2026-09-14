# ModKit Android 0.9.0-dev5

## Основное изменение

Menu Builder теперь сохраняет и исполняет подтверждённый IL2CPP calling contract вместо того,
чтобы считать каждый найденный RVA обычной static native-функцией.

### Instance IL2CPP

- Rodroid C-signature классифицируется как `static` или `instance` по наличию `__this`.
- Для `void(T*, bool, MethodInfo*)` предлагается `bool_setter`, для безаргументного instance-метода — `action`.
- Same-class static resolver вида `bool TryGet(T** out, MethodInfo*)` определяется как `out_ptr_bool`.
- Instance binding разрешается только как `call_abi=il2cpp` и только с подтверждённым resolver RVA.
- Runtime config обновлён до v2: каждая запись содержит target RVA и resolver RVA.
- Встроенный ARM64 runtime перед вызовом получает живой объект через resolver и передаёт `MethodInfo* = nullptr`.
- Target RVA и resolver RVA проверяются на file-backed/executable ещё до генерации payload.

## Menu Builder / UI

- В review-карточке видны signature, ABI, static/INSTANCE, suggested binding, resolver и blocker.
- Сигнатура Rodroid влияет на suggested visual type: `bool_setter -> toggle`, `action -> button`.
- Добавлена однокнопочная цепочка `RE → candidates → auto-confirm → preflight`.
- Добавлено консервативное автоподтверждение: candidate повышается в executable binding только при наличии Rodroid signature contract, достаточной confidence, положительного RVA, совместимого ABI/resolver и успешного ELF-preflight реального APK.
- Кандидаты, давшие BLOCK на ELF-проверке, автоматически откатываются обратно в review-only.
- IL2CPP/instance controls используют built-in generic runtime v2; старый standalone codegen для них не применяется.

## Проверка на сохранённых данных Drova

Статически подтверждены в исходном ARM64 `libil2cpp.so`:

- `CheatGameHandler::EnableCheatMode(bool)` — RVA `0x3C30558`;
- `CheatGameHandler::ToggleConsoleWindow()` — RVA `0x3C31044`;
- `CheatGameHandler::TryGet(out CheatGameHandler)` — resolver RVA `0x3C31898`.

Оба target RVA и resolver RVA file-backed и находятся в executable section. Это подтверждает
адресный/calling-contract preflight, но не заменяет runtime-тест конкретной сборки игры.

## Проверка

- Python regression suite: **179/179 PASS**.
- На сохранённом реальном ARM64 `libil2cpp.so` Drova автоподтверждение повысило `EnableCheatMode(bool)` и `ToggleConsoleWindow()` с общим `TryGet` resolver; `blocked=false`, `rejected=0`.
- Android NDK toolchain отсутствует в текущей изолированной среде, поэтому фактический `assembleDebug`/установка APK остаются внешним build gate.
