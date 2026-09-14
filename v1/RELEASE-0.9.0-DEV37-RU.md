# ModKit 0.9.0-dev37 — Simple Mode + File Workspace + Cocos

## Что добавлено

- Новый экран **«Для глупых · авто-режим»**: один каталог объединяет подтверждённые local controls, review/evidence, Runtime Probe, Application Discovery, Gameplay Discovery, Deep Resolver и trust-boundary находки.
- В Simple Mode все смысловые находки видимы; автоматическая сборка разрешена только для controls с подтверждёнными локальными executable bindings.
- Серверные/платёжные/экономические поверхности отображаются как `SERVER_AUDIT`: ModKit показывает доказательства и теоретическую модель риска, но не генерирует bypass.
- Автоматическое распознавание Unity/IL2CPP, Cocos2d-x C++, Cocos2d-x Lua/JS, Cocos Creator, Lua/xLua/SLua, DEX и native ELF.
- Новый **File Workspace**: открыть внешний файл или entry из base/split APK, редактировать UTF-8 или HEX, сохранить рабочую копию, экспортировать, упаковать явную замену в Patch Pack и собрать подписанный APK/APK-set.
- Patch Pack расширен явным `modkit-workspace-patch-1.0` для замены произвольных APK entries без догадок по имени файла; path traversal и META-INF блокируются.
- Installed Scanner сохраняет Cocos/Lua/JS engine markers вместе с Unity/IL2CPP/Dex/ELF inventory.

## Что не изменено

Профессиональные Decompiler / RE Workspace / Native / Patch Pack / Menu Builder остаются доступны напрямую. Simple Mode является оболочкой над теми же fail-closed анализаторами и не понижает требования к RVA/ABI/binding.
