package dev.modkit.mobile;

/**
 * Isolated native disassembly bridge used by static analysis only.
 *
 * This library is deliberately separate from libmk.so: loading the disassembler
 * must never start the ModKit runtime constructor or alter a target process.
 */
public final class NativeDisasmBridge {
    static {
        System.loadLibrary("mkdisasm");
    }

    private NativeDisasmBridge() {}

    public static native String capstoneVersion();

    /**
     * @param code exact function/range bytes
     * @param address virtual/RVA address of code[0]
     * @param architecture one of x86, x86_64, arm, aarch64
     * @param thumb true only for ARM Thumb/Thumb-2
     * @param maxInstructions bounded maximum number of decoded instructions
     * @return JSON using schema modkit-capstone-disasm-1.0
     */
    public static native String disassemble(
            byte[] code,
            long address,
            String architecture,
            boolean thumb,
            int maxInstructions);
}
