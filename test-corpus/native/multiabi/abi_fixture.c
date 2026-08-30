/* Benign project-owned cross-ABI parser fixture. No syscalls, networking, or target interaction. */
__attribute__((visibility("default"))) int unirevlab_fixture_add(int a, int b) { return a + b; }
__attribute__((visibility("default"))) unsigned long unirevlab_fixture_magic(void) { return 0x554e4952UL; }
