# Third-party notices

## il2cpp-dumper-rs

UniRevLab Security v0.43 uses the `il2cpp_dumper` Rust crate from
https://github.com/rodroidmods/il2cpp-dumper-rs pinned to commit
`8bfb90229539833999e725c5cf6402a435b47f15`.

The dependency's Cargo package metadata declares the MIT license. Copyright is attributed to
Rodroidmods as declared by that package. No target application code is linked into UniRevLab;
selected `libil2cpp.so` and `global-metadata.dat` files are parsed as untrusted input data.

The upstream repository did not expose a root LICENSE file at the pinned revision when this
integration was prepared. This notice records the exact source and declared license; release
distribution must retain this notice and should re-verify upstream licensing before production use.
