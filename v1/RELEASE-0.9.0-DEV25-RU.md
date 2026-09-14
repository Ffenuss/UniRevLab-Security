# ModKit 0.9.0-dev25

## Receiver/VTable Exact Proof

Dev25 развивает универсальный Deep Resolver без правил под конкретные APK.

1. Читаются стандартные IL2CPP `vtableMethods` и `interfaceOffsets` из `global-metadata.dat` v27/v29/v31.
2. Virtual `BLR` сначала остаётся review-кандидатом.
3. Receiver type считается доказанным только если цепочка нагрузки укоренена в неизменённом ABI-регистре managed caller-а: `X0=this` либо в конкретном class-параметре `X0..X7`/`X1..X7`.
4. Фиксированный offset `Il2CppClass::vtable` не зашит. Для одного receiver type ModKit пересекает допустимые базы `physicalOffset - 16*metadataSlot` по наблюдаемым callsite-ам. Exact proof появляется только при единственной общей базе.
5. После доказательства базы physical BLR-offset переводится в logical metadata slot, а `vtableMethods` — в конкретный MethodDefinition.
6. MethodRef/generic, interface-typed receiver, неоднозначная база, неизвестный caller или неизвестный TypeIndex остаются REVIEW.
7. Exact virtual edge входит в общий Method Evidence и может дойти до существующего `Deep Resolver -> MenuSpec -> APK/ELF preflight` только после остальных semantic/context/binding gates.

`runtimeTruth` по-прежнему остаётся `not-observed`: статический vtable proof не объявляется runtime-тестом.
