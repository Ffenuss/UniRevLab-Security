# ModKit 0.9.0-dev11 — AFK Journey validation

Validation target: `com.farlightgames.igame.gp`, version `1.7.31`, Unity `2021.3.48f1`, IL2CPP metadata v29.

This document records static-analysis evidence used to calibrate ModKit. It does not assert runtime execution or exploitability.

## APK-set result

The sample is a split/APK-set style input: the base APK contains IL2CPP metadata while the ARM64 `libil2cpp.so` is supplied outside the base APK. Dev11 treats the container and nested APK/companion artifacts as one analysis set and deduplicates identical payloads by SHA-256.

## Final surface classification

| Surface | State | Confidence | Interpretation |
|---|---:|---:|---|
| menu_overlay | candidate | 0.36 | Weak/generic UI evidence only; no developer/mod menu confirmed. |
| debug_console | candidate | 0.48 | Diagnostic/debug vocabulary exists, but no actionable game console was established. |
| gameplay_controls | candidate | 0.48 | Generic gameplay/debug names exist, but no callable control was confirmed. |
| hook_framework | absent | — | Framework/SDK hook markers alone are no longer promoted to a gameplay hook surface. |
| anti_cheat_surface | candidate | 0.48 | Managed anti-cheat-related names and methods exist, but precise runtime role is only partially resolved. |
| il2cpp_surface | confirmed | 0.98 | Metadata and ARM64 IL2CPP runtime are structurally consistent. |
| monetization_surface | confirmed | 0.98 | Multiple application payment/IAP flows are present. |

`confidence` means confidence in the classification/evidence, not vulnerability probability, exploitability, or likelihood that a modification will work.

## Anti-cheat managed methods

### `IGameMap::GetMapCheatDetectionPath`

- Assembly: `Assembly-CSharp.dll`
- Token: `100667790`
- RVA: `0x1EC2800`
- Non-abstract, one user argument.
- Static disassembly shows initialization helpers, a helper call around `0x198C09C`, and a call to `System.String::Format` around `0x50B92F0`.
- Conservative interpretation: appears to construct/format a cheat-detection-related path from runtime data and the supplied argument.
- No direct ARM64 `BL` caller was found in the bounded direct-call scan. This does **not** mean the method is unused; virtual/interface/indirect dispatch remains possible.

### `MapRuntime.Map::GetMapCheatDetectionPath`

- RVA: `0x1BFBF48`
- Non-abstract, one user argument.
- Static disassembly performs initialization, loads map/runtime object data, calls a helper near `0x140AD4C`, then delegates/tail-branches to a shared helper near `0x1417768` with a constant and the original argument.
- Conservative interpretation: resolves map/runtime state and delegates path production/query logic to a shared helper.
- No direct ARM64 `BL` caller was found in the bounded direct-call scan; indirect dispatch is not excluded.

### `MapRuntime.IMap::GetMapCheatDetectionPath`

- Abstract interface declaration.
- No concrete RVA, as expected for an abstract/interface method.

### `MapAntiCheatObjInteractNetData`

- `OnAfterDeserialize` — RVA `0x1EB198C`, first instruction `RET`.
- `OnBeforeSerialize` — RVA `0x1EB1990`, first instruction `RET`.
- `.ctor` — RVA `0x1EB1994`, short thunk/tail branch to a common initializer.

The two serialization callbacks are trivial no-ops in this build. The class therefore looks more like a serialized/network data carrier than a detector by itself.

## Monetization flow

Dev11's DEX method-level analysis identifies a server-backed payment architecture.

### `com.lilith.sdk.payment.iap.IapServiceImpl::launchPurchaseFlowAsync(...)`

Observed responsibilities include product-detail querying, payment-launch reporting and orchestration into the IAP charge path. Relevant strings include `force_iap` and `launch_type`.

### `IapServiceImpl::chargeIAP(...)`

Reads product type/id and payment metadata, selects a `PaymentPluginManager` strategy and calls `BasePayStrategy::pay()`. Strings include `subs`, `inapp` and `pay_item_id`.

### `CashierServiceApi::makeDecision(...)`

Builds a JSON request containing product and regional/payment attributes such as product id/name, subscription flag, currency, amount, region, preference, payment trace id and notify area. The observed endpoint string is `/api/v1/cashier/mobile/decision` and the flow uses the application's HTTPS/OkHttp stack.

### `PaySignRequestHelper::sendPaymentSignRequest(...)`

Coordinates a coroutine-based payment-signing request and passes account/device/application identity material into the request flow.

### `HttpsEngine::postHttpRequestAsyncPurchase(...)`

Implements the actual asynchronous HTTP POST path, writes the request body, connects, checks the response code and returns success/failure callbacks.

### `PayRequestListener::onSuccess(...)`

Parses the JSON response, checks success/error fields, extracts `order_id` and updates purchase/order models.

### `PurchaseReportApi::queryOrders(...)`

Queries the server endpoint `/ordercallback/query`, sending package/application/account parameters and parsing returned `orders`.

### Trust interpretation

- Presence confidence: `0.98`
- Behavior confidence: `0.97`
- Actionability confidence: `0.18`
- Trust boundary: `server-backed`

The static evidence strongly supports the presence and high-level behavior of the payment flow, but does not support the claim that entitlement authority is local or that the payment flow is bypassable client-side.

## Dev11 calibration changes driven by this sample

- Added split APK / APK-set / XAPK / APKS / ZIP aggregation.
- Added artifact SHA-256 deduplication.
- Separated anti-cheat vocabulary from cheat-control vocabulary.
- Suppressed Unity Rendering/DebugManager, Android Material UI, Kotlin/Android debug infrastructure and similar framework noise from actionable controls.
- Prevented raw `global-metadata.dat` strings from becoming callable controls by themselves.
- Required higher-signal, category-specific evidence before actionable surfaces can be promoted.
- Prevented SDK hook-library presence alone from confirming a gameplay/mod hook stack.

Final AFK Journey result after calibration: **0 actionable control candidates**. This is intentional: ModKit retained architectural evidence without inventing callable gameplay controls that the static evidence did not support.
