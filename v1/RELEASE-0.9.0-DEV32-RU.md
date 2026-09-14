# ModKit 0.9.0-dev32 — App/Game profiles, Application Discovery и новый Home UI

Dev32 начинает второй этап roadmap после PackageTarget/dev31: ModKit больше не рассматривает каждый target как игру и адаптирует discovery/UI к обычному Android-приложению, игре или гибридному target.

## Target Profile

Добавлен evidence-based профиль:

- `GAME`
- `APPLICATION`
- `HYBRID`
- `UNKNOWN`

Installed Scanner учитывает Android `CATEGORY_GAME`, Unity/content markers, DEX/native inventory и реальные application-owned trust surfaces. После RE-анализов профиль уточняется по gameplay evidence и DEX trust evidence. IL2CPP сам по себе не считается безусловным доказательством игры.

## Application Discovery

DEX trust-boundary engine расширен с двух категорий до 12:

- Authentication / Session
- Entitlements / Premium / Subscription
- Payments / Purchases
- Feature Flags / Experiments
- Local Storage / Database
- Network / API
- Crypto / Key Storage
- WebView / JavaScript Bridge
- Deep Links / Intents
- Serialization
- Debug / Developer surfaces
- Integrity / Defensive controls

Для каждой поверхности отдельно сохраняются:

- application-owned vs framework/third-party evidence;
- `server-backed`, `platform-backed`, `local`, `unknown` trust boundary;
- `possible-local`, `not-confirmed`, `unknown` local authority;
- presence/behavior confidence;
- прямые методы/strings/invokes;
- remediation guidance.

Статусы Application Discovery:

- `CONFIRMED` — локально найдено application-owned/bundled evidence;
- `REVIEW` — локально есть только framework/third-party evidence;
- `NOT_FOUND_LOCAL` — matching evidence не найдено в просканированных локальных артефактах; это не доказательство отсутствия.

Наличие billing/auth/network/debug surface никогда автоматически не считается уязвимостью и не превращается в working modification.

## Installed Scanner

- DEX trust scan запускается прямо во время base/split inventory, поэтому обычным приложениям не нужна IL2CPP-пара для Application Discovery.
- Analysis остаётся fail-soft для повреждённого/неподдерживаемого DEX: ошибка фиксируется как evidence gap, остальная инвентаризация продолжается.
- Target Profile и Application Discovery сохраняются в `installed-scan.json` и summary target.
- Full IL2CPP path получает те же App/Game profile данные без второго тяжёлого native scan.

## UI / Visual

- Главный экран перестроен карточками по pipeline: Target → Analysis → Discovery/Methods → Result.
- Добавлен Target badge с профилем и confidence.
- Поиск адаптируется к `GAME`, `APPLICATION` и `HYBRID`.
- Installed Apps показывает иконки, package и фильтры `Все / Игры / Приложения`.
- Добавлен structured progress stepper: Input → Inventory → Analysis → Discovery → Probe → Menu → Output.
- Progress bar переключается между indeterminate и фактическим `%`, когда stage отдаёт процент.
- Приложен Material 3 Day/Night theme; основной Home UI и рабочие пространства используют light/dark palette.

## Инварианты

- Menu/Probe fail-closed gates не ослаблялись.
- Static evidence не маркируется runtime-confirmed.
- `NOT_FOUND_LOCAL` не означает глобальное отсутствие функции/поверхности.
- `PARTIAL` APK-set остаётся неполным evidence scope.
- Server/payment bypass не добавлялся; соответствующие поверхности обнаруживаются как trust boundary и remediation evidence.

## UI finalization

Финальный UI-блок dev32 дополнительно закрывает три пункта roadmap:

- Installed Apps переведён с `ListView/BaseAdapter` на `RecyclerView + LinearLayoutManager`; сохранены иконки, поиск по label/package и фильтры Apps/Games/All.
- На Home добавлена отдельная навигация `Discovery / Probe / Menu / Reports`, чтобы основные стадии не были спрятаны внутри технических workspace-кнопок.
- Основной Home/Installed UI вынесен из hardcoded Java-строк в Android resources: русские строки находятся в `res/values/strings.xml`, английские — в `res/values-en/strings.xml`; ключи двух локалей проверяются regression-тестом.

Regression suite после финализации: `312 passed`, `selftest` и `runtime-check builtin-runtime-v4` — PASS локально перед CI.
