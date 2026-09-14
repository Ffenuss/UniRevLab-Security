# ModKit Android 0.9.0-dev3

Снимок после восстановления 0.8.1 и развития RE/Native/Menu/Patch Pack.

## Новое относительно dev2

- Menu Builder: редактирование уже найденного элемента, смена visual type и явная binding-привязка.
- Проверка executable bindings по реальному исходному APK:
  - наличие целевой ARM64 `.so`;
  - RVA -> file offset;
  - попадание в executable section;
  - ARM64 disassembly preview;
  - BLOCK для неверного RVA/модуля;
  - предупреждение для нескольких controls на одном RVA.
- RE Workspace формирует `controlCandidates` из Unity/Addressables/native evidence.
- Находки developer/debug surface ранжируются выше обычных Health/Damage/UI-строк.
- Menu Builder получает отдельные review-кандидаты (например Cheat_Invic/NoClip/Weather), но не создаёт исполняемый binding без ручного подтверждения calling convention.
- Исправлена несовместимость имени generated native library: CMake и `System.loadLibrary()` теперь используют одно lowercase-имя.
- RE UI показывает число control candidates.

## Проверка

- Python: 143/143 tests PASS.
- Реальный сохранённый Drova UnityFS bundle: control-candidate extractor поднимает в верхние результаты Cheat Invic, Cheat LevelUp, Cheat Mode, Cheat NoClip, Cheat Weather и AI Debug surface.

## Ограничение текущего снимка

- Android APK этого dev-снимка здесь не собирался: в окружении нет полного Android SDK/NDK/Gradle toolchain.
- Menu runtime source генерируется; автоматическая универсальная загрузка нового native menu внутрь произвольного закрытого APK ещё не завершена. Patch Pack уже умеет безопасно применять готовые DEX/SO payloads.
