# ModKit 0.9.0-dev39 — DEX correctness + signal ranking + readable Simple Mode

- Исправлена критическая DEX-атрибуция: `method_idx_diff` теперь сбрасывается отдельно для direct/virtual lists. Это убирает ситуацию, когда Room-методу ошибочно приписывались вызовы MotionLayout/других соседних методов.
- Framework/SDK-находки сохраняются, но по умолчанию скрыты из «Важное» и доступны через «Все».
- Убрана ложная monetization-классификация `SupportMenuItem.getOrder`; generic currency/locale/analytics строки больше не считаются игровой валютой без игрового контекста.
- Local currency/reward больше не превращаются автоматически в SERVER_AUDIT только из-за слова currency/economy; server status требует реальной trust-boundary evidence.
- Security scan группирует уникальные API/HTTP/WebSocket/host:port и отдельно crypto/key-handling/TLS markers; сетевых подключений и проверки credentials нет.
- Simple Mode получил фильтры «Важное / READY / Gameplay / Server/API / Crypto/Keys / Все», поиск, ownership, краткое место находки и raw JSON только по отдельной кнопке.
- READY_DEX теперь использует точный `artifact + class + method + codeOffset`, а не требует native RVA. Автосборка остаётся fail-closed и принимает только проверенный MenuSpec binding.
