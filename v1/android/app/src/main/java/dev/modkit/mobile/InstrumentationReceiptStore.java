package dev.modkit.mobile;

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/**
 * Crash-safe persistence for one outstanding Instrumentation v1 write receipt.
 *
 * A stored receipt is recovery metadata only: loading it never writes target memory.
 * Before a rollback the canonical RootMemoryInstrumentation rollback path still revalidates
 * PID + UID + start-time, current mappings and exact replacement bytes.
 */
final class InstrumentationReceiptStore {
    static final String SCHEMA = "modkit-instrumentation-pending-write-1.0";

    static final class PendingWrite {
        final RootMemoryInstrumentation.WriteReceipt receipt;
        final String modulePath;
        final long rva;
        final long savedAtMs;

        PendingWrite(RootMemoryInstrumentation.WriteReceipt receipt, String modulePath, long rva, long savedAtMs) {
            this.receipt = receipt;
            this.modulePath = modulePath == null ? "" : modulePath;
            this.rva = rva;
            this.savedAtMs = savedAtMs;
        }

        JSONObject toJson() throws Exception {
            return new JSONObject()
                    .put("schema", SCHEMA)
                    .put("receipt", receipt.toJson())
                    .put("modulePath", modulePath)
                    .put("rvaHex", hex(rva))
                    .put("savedAtMs", savedAtMs)
                    .put("recoveryPolicy", "USER_CONFIRMED_ROLLBACK_ONLY");
        }
    }

    private InstrumentationReceiptStore() {}

    static void save(File destination, RootMemoryInstrumentation.WriteReceipt receipt, String modulePath, long rva) throws Exception {
        if (destination == null) throw new IOException("Instrumentation: pending receipt destination missing");
        if (receipt == null) throw new IOException("Instrumentation: pending write receipt missing");
        File parent = destination.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs() && !parent.isDirectory()) {
            throw new IOException("Instrumentation: cannot create receipt directory");
        }
        File part = new File(destination.getPath() + ".part");
        Files.deleteIfExists(part.toPath());
        JSONObject envelope = new PendingWrite(receipt, modulePath, rva, System.currentTimeMillis()).toJson();
        try {
            Files.write(part.toPath(), envelope.toString(2).getBytes(StandardCharsets.UTF_8));
            Files.move(part.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            Files.deleteIfExists(part.toPath());
            throw e;
        }
    }

    static PendingWrite load(File source) throws Exception {
        if (source == null || !source.isFile()) return null;
        byte[] raw = Files.readAllBytes(source.toPath());
        if (raw.length == 0 || raw.length > 64 * 1024) throw new IOException("Instrumentation: pending receipt size invalid");
        JSONObject envelope = new JSONObject(new String(raw, StandardCharsets.UTF_8));
        if (!SCHEMA.equals(envelope.optString("schema"))) throw new IOException("Instrumentation: pending receipt schema mismatch");
        if (!"USER_CONFIRMED_ROLLBACK_ONLY".equals(envelope.optString("recoveryPolicy"))) {
            throw new IOException("Instrumentation: pending receipt recovery policy mismatch");
        }
        JSONObject receiptJson = envelope.optJSONObject("receipt");
        if (receiptJson == null || !"modkit-instrumentation-write-1.0".equals(receiptJson.optString("schema"))) {
            throw new IOException("Instrumentation: pending write receipt schema mismatch");
        }
        if (!receiptJson.optBoolean("verified", false)) throw new IOException("Instrumentation: unverified write receipt cannot be recovered");
        if (!"ONLY_IF_CURRENT_BYTES_MATCH_REPLACEMENT".equals(receiptJson.optString("rollbackPolicy"))) {
            throw new IOException("Instrumentation: rollback policy mismatch");
        }

        JSONObject leaseJson = receiptJson.optJSONObject("lease");
        JSONObject regionJson = receiptJson.optJSONObject("region");
        if (leaseJson == null || regionJson == null) throw new IOException("Instrumentation: incomplete pending write receipt");
        if (!"modkit-instrumentation-lease-1.0".equals(leaseJson.optString("schema"))) {
            throw new IOException("Instrumentation: lease schema mismatch");
        }

        int pid = requirePositiveInt(leaseJson, "pid");
        int uid = requireNonNegativeInt(leaseJson, "uid");
        long startTicks = requirePositiveLong(leaseJson, "startTicks");
        long capturedAtMs = requirePositiveLong(leaseJson, "capturedAtMs");
        RootMemoryInstrumentation.ProcessLease lease = new RootMemoryInstrumentation.ProcessLease(pid, uid, startTicks, capturedAtMs);

        int length = requirePositiveInt(receiptJson, "length");
        if (length > RootMemoryInstrumentation.MAX_WRITE_BYTES) throw new IOException("Instrumentation: pending write exceeds guarded transaction limit");
        byte[] original = parseHexBytes(receiptJson.optString("originalHex"), length);
        byte[] replacement = parseHexBytes(receiptJson.optString("replacementHex"), length);
        long address = parseHexLong(receiptJson.optString("addressHex"));
        long appliedAtMs = requirePositiveLong(receiptJson, "appliedAtMs");

        long regionStart = parseHexLong(regionJson.optString("startHex"));
        long regionEnd = parseHexLong(regionJson.optString("endHex"));
        String perms = regionJson.optString("perms", "");
        String path = regionJson.optString("path", "");
        if (regionEnd <= regionStart) throw new IOException("Instrumentation: invalid stored memory region");
        if (perms.indexOf('r') < 0 || perms.indexOf('w') < 0) throw new IOException("Instrumentation: stored rollback region is not readable+writable");
        if (address < regionStart || address > Long.MAX_VALUE - length || address + length > regionEnd) {
            throw new IOException("Instrumentation: stored write range is outside stored region");
        }
        RootMemoryInstrumentation.MemoryRegion region = new RootMemoryInstrumentation.MemoryRegion(regionStart, regionEnd, perms, path);
        RootMemoryInstrumentation.WriteReceipt receipt = new RootMemoryInstrumentation.WriteReceipt(
                lease, address, original, replacement, region, appliedAtMs);

        String modulePath = envelope.optString("modulePath", "");
        long rva = parseHexLong(envelope.optString("rvaHex", "0x0"));
        long savedAtMs = requirePositiveLong(envelope, "savedAtMs");
        return new PendingWrite(receipt, modulePath, rva, savedAtMs);
    }

    static void clear(File destination) throws IOException {
        if (destination == null) return;
        Files.deleteIfExists(destination.toPath());
        Files.deleteIfExists(new File(destination.getPath() + ".part").toPath());
    }

    private static int requirePositiveInt(JSONObject value, String name) throws IOException {
        long parsed = value.optLong(name, -1L);
        if (parsed <= 0 || parsed > Integer.MAX_VALUE) throw new IOException("Instrumentation: invalid " + name);
        return (int) parsed;
    }

    private static int requireNonNegativeInt(JSONObject value, String name) throws IOException {
        long parsed = value.optLong(name, -1L);
        if (parsed < 0 || parsed > Integer.MAX_VALUE) throw new IOException("Instrumentation: invalid " + name);
        return (int) parsed;
    }

    private static long requirePositiveLong(JSONObject value, String name) throws IOException {
        long parsed = value.optLong(name, -1L);
        if (parsed <= 0) throw new IOException("Instrumentation: invalid " + name);
        return parsed;
    }

    private static byte[] parseHexBytes(String raw, int expectedLength) throws IOException {
        if (raw == null || raw.length() != expectedLength * 2 || !raw.matches("[0-9a-fA-F]+")) {
            throw new IOException("Instrumentation: invalid persisted byte sequence");
        }
        byte[] out = new byte[expectedLength];
        for (int i = 0; i < expectedLength; i++) {
            out[i] = (byte) Integer.parseInt(raw.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static long parseHexLong(String value) throws IOException {
        if (value == null) throw new IOException("Instrumentation: missing hex value");
        String normalized = value.trim();
        if (normalized.startsWith("0x") || normalized.startsWith("0X")) normalized = normalized.substring(2);
        if (normalized.isEmpty() || !normalized.matches("[0-9a-fA-F]+")) throw new IOException("Instrumentation: invalid hex value");
        try {
            long parsed = Long.parseUnsignedLong(normalized, 16);
            if (parsed < 0) throw new NumberFormatException("overflow");
            return parsed;
        } catch (NumberFormatException e) {
            throw new IOException("Instrumentation: hex value out of signed address range");
        }
    }

    private static String hex(long value) { return String.format(Locale.ROOT, "0x%x", value); }
}
