# ModKit Android 0.9.0-dev6

## Runtime v2 hardening

- Точный `android/app/src/main/cpp/modkit_runtime.cpp` теперь проходит host-side `clang++/g++ -fsyntax-only` с `-Wall -Wextra -Werror` через Android/EGL/GLES2 stubs.
- Проверка встроена и в `pytest`, и в `modkit selftest`.
- Перед `g_ready=true` runtime проверяет executable mapping как target RVA, так и resolver RVA для instance IL2CPP bindings.
- Добавлена защита от переполнения при вычислении `base + RVA` и диапазонов mapped ELF segments.

## Numeric Rodroid contracts

- Rodroid signature parser различает `bool`, integer и `float/double` параметры.
- Для числовых параметров сохраняются `valueC`, `valueKind`, `managedValueType` и точный suggested control type (`slider_int`/`slider_float`).
- Числовой setter не автоподтверждается, пока пользователь явно не выбрал slider и не задал Min/Max.
- Android Menu Builder больше не подставляет произвольный диапазон `0..100`; Min/Max обязательны для slider, Default опционален и проверяется на попадание в диапазон.

## Rodroid signature hardening

- Calling contract теперь повторно выводится из фактической Rodroid-сигнатуры перед auto-confirm; сериализованная подсказка из JSON больше не считается доверенной.
- Отсекаются ложные controls вроде `.ctor(int)`, `Update(float)` и произвольных методов с одним числовым параметром: auto-binding требует совместимого имени метода и сигнатуры.
- Generic runtime автоматически поддерживает числовые setters только для `System.Int32` и `System.Single`; `Int64`, unsigned-width варианты и `Double` остаются evidence/review до появления соответствующего ABI runtime.
- Static/instance несоответствие блокирует binding; instance IL2CPP по-прежнему требует подтверждённый resolver.

## Structured developer-control discovery

- RE Workspace формирует отдельный finding `re.structured_developer_control_api`, когда Rodroid подтверждает address-bearing cheat/debug/developer методы с безопасно разобранным calling contract.
- Finding хранит provenance по методам/RVA и может усиливаться Unity/Addressables markers, но не выдаёт статическое наличие API за доказательство runtime-поведения.
- На сохранённом Drova dump структурно выделяются, среди прочего, `CheatGameHandler::EnableCheatMode`, `ToggleConsoleWindow`, `Cheat_Damage::set_IsMaxed`, `Cheat_GodMode::SetMaxAttributes`, `Cheat_MaxHealth::SetMaxHealth` и `Cheat_TimeScale::SetTimeScale`.

## Selftest / CI

- `modkit selftest` теперь дополнительно round-trip проверяет runtime config v2, включая instance resolver и numeric setter.
- CI workflow обновлён на NDK 26.3.11579264/CMake 3.22.1 и артефакт `ModKit-Android-0.9.0-dev6`.
- Версии синхронизированы: Android `versionCode 13`, `versionName 0.9.0-dev6`; Python package `0.9.0.dev6`; banner `0.9.0-dev6`.

## Проверка

- Python regression suite: 190/190 PASS.
- `modkit selftest`: generated TUs + built-in runtime v2 strict host compile PASS.
- Android SDK/NDK отсутствуют в локальной рабочей среде, поэтому `assembleDebug` остаётся CI/внешним build gate.
