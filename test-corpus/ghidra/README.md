# Headless Ghidra regression fixture

`ghidra_fixture.c` is UniRevLab-owned benign code. It exists only to verify the headless reverse-engineering worker.

It contains:

- a classic static JNI export (`Java_com_example_NativeBridge_nativeCheck`);
- a synthetic `JNINativeMethod`-shaped table for `nativeAdd(II)I`;
- benign functions with a branch and function call so CFG/xrefs can be asserted;
- exported `g_CodeRegistration`, `g_MetadataRegistration`, and `il2cpp_codegen_register` symbols plus a callsite for IL2CPP registration-evidence regression.

The fixture does not load external code, access the network, persist, modify other processes, or contain exploitation behavior.
