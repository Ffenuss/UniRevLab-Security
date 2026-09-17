package dev.modkit.mobile;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Instrumentation v1 memory primitive for an explicitly selected rooted process.
 *
 * Every access is bound to a process lease (PID + UID + /proc start-time), checked
 * against the current memory map and limited in size. Writes are compare-before-write,
 * verified after the write and carry the exact original bytes needed for guarded undo.
 * This class intentionally does not provide arbitrary command execution or a hook API;
 * higher layers must build typed operations on these fail-closed primitives.
 */
final class RootMemoryInstrumentation {
    static final int MAX_READ_BYTES = 4096;
    static final int MAX_WRITE_BYTES = 256;

    private RootMemoryInstrumentation() {}

    static final class ProcessLease {
        final int pid;
        final int uid;
        final long startTicks;
        final long capturedAtMs;

        ProcessLease(int pid, int uid, long startTicks, long capturedAtMs) {
            this.pid = pid;
            this.uid = uid;
            this.startTicks = startTicks;
            this.capturedAtMs = capturedAtMs;
        }

        JSONObject toJson() {
            JSONObject out = new JSONObject();
            try {
                out.put("schema", "modkit-instrumentation-lease-1.0");
                out.put("pid", pid);
                out.put("uid", uid);
                out.put("startTicks", startTicks);
                out.put("capturedAtMs", capturedAtMs);
            } catch (JSONException ignored) {}
            return out;
        }
    }

    static final class MemoryRegion {
        final long start;
        final long end;
        final String perms;
        final String path;

        MemoryRegion(long start, long end, String perms, String path) {
            this.start = start;
            this.end = end;
            this.perms = perms == null ? "" : perms;
            this.path = path == null ? "" : path;
        }

        boolean readable() { return perms.indexOf('r') >= 0; }
        boolean writable() { return perms.indexOf('w') >= 0; }
        boolean executable() { return perms.indexOf('x') >= 0; }

        boolean contains(long address, int length) {
            if (address < start || length < 0) return false;
            long finish = address + (long) length;
            return finish >= address && finish <= end;
        }

        JSONObject toJson() {
            JSONObject out = new JSONObject();
            try {
                out.put("startHex", hex(start));
                out.put("endHex", hex(end));
                out.put("perms", perms);
                out.put("path", path);
            } catch (JSONException ignored) {}
            return out;
        }
    }

    static final class WriteReceipt {
        final ProcessLease lease;
        final long address;
        final byte[] original;
        final byte[] replacement;
        final MemoryRegion region;
        final long appliedAtMs;

        WriteReceipt(ProcessLease lease, long address, byte[] original, byte[] replacement, MemoryRegion region, long appliedAtMs) {
            this.lease = lease;
            this.address = address;
            this.original = original.clone();
            this.replacement = replacement.clone();
            this.region = region;
            this.appliedAtMs = appliedAtMs;
        }

        JSONObject toJson() {
            JSONObject out = new JSONObject();
            try {
                out.put("schema", "modkit-instrumentation-write-1.0");
                out.put("lease", lease.toJson());
                out.put("addressHex", hex(address));
                out.put("length", replacement.length);
                out.put("originalHex", bytesToHex(original));
                out.put("replacementHex", bytesToHex(replacement));
                out.put("region", region.toJson());
                out.put("appliedAtMs", appliedAtMs);
                out.put("verified", true);
                out.put("rollbackPolicy", "ONLY_IF_CURRENT_BYTES_MATCH_REPLACEMENT");
            } catch (JSONException ignored) {}
            return out;
        }
    }

    static ProcessLease captureLease(int pid, int expectedUid) throws IOException {
        if (pid <= 1) throw new IOException("Instrumentation: invalid PID");
        ProcessIdentity identity = readIdentity(pid);
        if (expectedUid >= 0 && identity.uid != expectedUid) {
            throw new IOException("Instrumentation: UID changed before lease capture");
        }
        return new ProcessLease(pid, identity.uid, identity.startTicks, System.currentTimeMillis());
    }

    static byte[] read(ProcessLease lease, long address, int length) throws IOException {
        requireLease(lease);
        if (length <= 0 || length > MAX_READ_BYTES) throw new IOException("Instrumentation: read length out of bounds");
        MemoryRegion region = requireRegion(lease, address, length, false);
        if (!region.readable()) throw new IOException("Instrumentation: target mapping is not readable");
        return readRaw(lease.pid, address, length);
    }

    static WriteReceipt guardedWrite(ProcessLease lease, long address, byte[] expectedOriginal, byte[] replacement) throws IOException {
        requireLease(lease);
        if (expectedOriginal == null || replacement == null || expectedOriginal.length == 0 || expectedOriginal.length != replacement.length) {
            throw new IOException("Instrumentation: expected/replacement bytes must be non-empty and equal length");
        }
        if (replacement.length > MAX_WRITE_BYTES) throw new IOException("Instrumentation: write exceeds guarded transaction limit");

        MemoryRegion region = requireRegion(lease, address, replacement.length, true);
        byte[] current = readRaw(lease.pid, address, replacement.length);
        if (!Arrays.equals(current, expectedOriginal)) {
            throw new IOException("Instrumentation: compare-before-write failed; target bytes changed");
        }

        writeRaw(lease.pid, address, replacement);
        byte[] verified = readRaw(lease.pid, address, replacement.length);
        if (!Arrays.equals(verified, replacement)) {
            try { writeRaw(lease.pid, address, current); } catch (Exception ignored) {}
            throw new IOException("Instrumentation: write verification failed; rollback attempted");
        }
        return new WriteReceipt(lease, address, current, replacement, region, System.currentTimeMillis());
    }

    static void rollback(WriteReceipt receipt) throws IOException {
        if (receipt == null) throw new IOException("Instrumentation: missing write receipt");
        requireLease(receipt.lease);
        requireRegion(receipt.lease, receipt.address, receipt.replacement.length, true);
        byte[] current = readRaw(receipt.lease.pid, receipt.address, receipt.replacement.length);
        if (!Arrays.equals(current, receipt.replacement)) {
            throw new IOException("Instrumentation: rollback blocked because current bytes no longer match the applied transaction");
        }
        writeRaw(receipt.lease.pid, receipt.address, receipt.original);
        byte[] verified = readRaw(receipt.lease.pid, receipt.address, receipt.original.length);
        if (!Arrays.equals(verified, receipt.original)) throw new IOException("Instrumentation: rollback verification failed");
    }

    static MemoryRegion requireRegion(ProcessLease lease, long address, int length, boolean forWrite) throws IOException {
        requireLease(lease);
        if (address < 0 || length <= 0) throw new IOException("Instrumentation: invalid address range");
        List<MemoryRegion> regions = readRegions(lease.pid);
        for (MemoryRegion region : regions) {
            if (!region.contains(address, length)) continue;
            if (!region.readable()) throw new IOException("Instrumentation: mapping is not readable");
            if (forWrite && !region.writable()) throw new IOException("Instrumentation: mapping is not writable");
            return region;
        }
        throw new IOException("Instrumentation: address is not contained in a current process mapping");
    }

    private static void requireLease(ProcessLease lease) throws IOException {
        if (lease == null) throw new IOException("Instrumentation: process lease required");
        ProcessIdentity current = readIdentity(lease.pid);
        if (current.uid != lease.uid || current.startTicks != lease.startTicks) {
            throw new IOException("Instrumentation: stale process lease; PID was restarted or identity changed");
        }
    }

    private static final class ProcessIdentity {
        final int uid;
        final long startTicks;
        ProcessIdentity(int uid, long startTicks) { this.uid = uid; this.startTicks = startTicks; }
    }

    private static ProcessIdentity readIdentity(int pid) throws IOException {
        RootAccess.ExecResult status = RootAccess.runSu("cat /proc/" + pid + "/status", 4_000, 128 * 1024);
        if (status.timedOut || status.exitCode != 0) throw new IOException("Instrumentation: process status unavailable");
        int uid = parseStatusUid(status.output);
        if (uid < 0) throw new IOException("Instrumentation: process UID unavailable");

        RootAccess.ExecResult stat = RootAccess.runSu("cat /proc/" + pid + "/stat", 4_000, 64 * 1024);
        if (stat.timedOut || stat.exitCode != 0) throw new IOException("Instrumentation: process start time unavailable");
        long startTicks = parseStartTicks(stat.output);
        if (startTicks < 0) throw new IOException("Instrumentation: invalid process start time");
        return new ProcessIdentity(uid, startTicks);
    }

    private static List<MemoryRegion> readRegions(int pid) throws IOException {
        RootAccess.ExecResult maps = RootAccess.runSu("cat /proc/" + pid + "/maps", 6_000, 4 * 1024 * 1024);
        if (maps.timedOut || maps.exitCode != 0 || maps.truncated) throw new IOException("Instrumentation: complete memory map unavailable");
        ArrayList<MemoryRegion> out = new ArrayList<>();
        for (String line : maps.output.split("\\R")) {
            MemoryRegion region = parseRegion(line);
            if (region != null) out.add(region);
        }
        return out;
    }

    private static MemoryRegion parseRegion(String line) {
        if (line == null) return null;
        String[] parts = line.trim().split("\\s+", 6);
        if (parts.length < 5) return null;
        String[] range = parts[0].split("-", 2);
        if (range.length != 2) return null;
        long start = parseHexLong(range[0], -1), end = parseHexLong(range[1], -1);
        if (start < 0 || end <= start) return null;
        String path = parts.length >= 6 ? parts[5].trim() : "";
        return new MemoryRegion(start, end, parts[1], path);
    }

    private static byte[] readRaw(int pid, long address, int length) throws IOException {
        String command = "dd if=/proc/" + pid + "/mem bs=1 skip=" + address + " count=" + length + " 2>/dev/null | od -An -v -tx1";
        RootAccess.ExecResult result = RootAccess.runSu(command, 6_000, Math.max(16 * 1024, length * 8));
        if (result.timedOut || result.exitCode != 0 || result.truncated) throw new IOException("Instrumentation: memory read failed");
        String trimmed = result.output == null ? "" : result.output.trim();
        if (trimmed.isEmpty()) throw new IOException("Instrumentation: memory read returned no bytes");
        String[] tokens = trimmed.split("\\s+");
        if (tokens.length != length) throw new IOException("Instrumentation: memory read length mismatch");
        byte[] bytes = new byte[length];
        for (int i = 0; i < tokens.length; i++) {
            if (!tokens[i].matches("[0-9a-fA-F]{2}")) throw new IOException("Instrumentation: invalid memory byte output");
            bytes[i] = (byte) Integer.parseInt(tokens[i], 16);
        }
        return bytes;
    }

    private static void writeRaw(int pid, long address, byte[] bytes) throws IOException {
        StringBuilder escaped = new StringBuilder(bytes.length * 4);
        for (byte value : bytes) escaped.append(String.format(Locale.ROOT, "\\\\%03o", value & 0xff));
        String command = "printf '%b' '" + escaped + "' | dd of=/proc/" + pid + "/mem bs=1 seek=" + address + " count=" + bytes.length + " conv=notrunc 2>/dev/null";
        RootAccess.ExecResult result = RootAccess.runSu(command, 6_000, 32 * 1024);
        if (result.timedOut || result.exitCode != 0) throw new IOException("Instrumentation: memory write failed");
    }

    private static int parseStatusUid(String status) {
        if (status == null) return -1;
        for (String line : status.split("\\R")) {
            if (!line.startsWith("Uid:")) continue;
            String[] parts = line.substring(4).trim().split("\\s+");
            if (parts.length == 0) return -1;
            try { return Integer.parseInt(parts[0]); } catch (NumberFormatException ignored) { return -1; }
        }
        return -1;
    }

    private static long parseStartTicks(String stat) {
        if (stat == null) return -1;
        String text = stat.trim();
        int close = text.lastIndexOf(')');
        if (close < 0 || close + 2 >= text.length()) return -1;
        String[] afterComm = text.substring(close + 2).trim().split("\\s+");
        // afterComm[0] is field 3 (state), therefore field 22 (starttime) is index 19.
        if (afterComm.length <= 19) return -1;
        try { return Long.parseLong(afterComm[19]); } catch (NumberFormatException ignored) { return -1; }
    }

    private static long parseHexLong(String value, long fallback) {
        try { return Long.parseUnsignedLong(value.trim(), 16); } catch (Exception ignored) { return fallback; }
    }

    private static String hex(long value) { return String.format(Locale.ROOT, "0x%x", value); }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        return out.toString();
    }
}
