# Native regression corpus

These files are benign UniRevLab-owned fixtures for static parser regression tests.

- `jni_fixture.c` exports `JNI_OnLoad` and a classic `Java_com_example_NativeBridge_nativeCheck` JNI symbol. It also embeds a `.invalid` HTTP URL and a `RegisterNatives` marker used only to verify string inventory/redaction behavior.
- `build-fixtures.sh` builds two Linux ELF shared objects into `app/src/test/resources/fixtures/`:
  - `libjni_hardened.so`: stack protector, GNU RELRO, immediate binding, non-executable stack;
  - `libjni_weak.so`: executable stack and no GNU RELRO, used only to test detector differentiation.

The analyzer never loads these libraries. Tests open them as byte streams and parse their ELF structures.
