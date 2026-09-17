package dev.modkit.mobile;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Instrumentation v1 typed module + RVA resolver.
 *
 * A caller selects a process explicitly and captures a {@link RootMemoryInstrumentation.ProcessLease}.
 * This resolver never accepts a shell fragment. Module selectors are compared only inside Java against
 * the live /proc/<pid>/maps snapshot. A basename selector must identify exactly one mapped path, the
 * load bias must be consistent across that module's file-backed mappings, and every resolved access
 * must fit completely inside a current mapping belonging to that same module.
 */
final class RootModuleAddressResolver {
    private static final int MAX_MAPS_BYTES = 4 * 1024 * 1024;

    private RootModuleAddressResolver() {}

    static final class ResolvedAddress {
        final RootMemoryInstrumentation.ProcessLease lease;
        final String selector;
        final String modulePath;
        final String moduleName;
        final long loadBias;
        final long rva;
        final long address;
        final int length;
        final String perms;
        final long resolvedAtMs;

        ResolvedAddress(
                RootMemoryInstrumentation.ProcessLease lease,
                String selector,
                String modulePath,
                long loadBias,
                long rva,
                long address,
                int length,
                String perms,
                long resolvedAtMs) {
            this.lease = lease;
            this.selector = selector;
            this.modulePath = modulePath;
            this.moduleName = basename(modulePath);
            this.loadBias = loadBias;
            this.rva = rva;
            this.address = address;
            this.length = length;
            this.perms = perms;
            this.resolvedAtMs = resolvedAtMs;
        }

        JSONObject toJson() {
            JSONObject out = new JSONObject();
            try {
                out.put("schema", "modkit-instrumentation-address-1.0");
                out.put("lease", lease.toJson());
                out.put("selector", selector);
                out.put("modulePath", modulePath);
                out.put("moduleName", moduleName);
                out.put("loadBiasHex", hex(loadBias));
                out.put("rvaHex", hex(rva));
                out.put("addressHex", hex(address));
                out.put("length", length);
                out.put("perms", perms);
                out.put("resolvedAtMs", resolvedAtMs);
                out.put("freshnessPolicy", "RE_RESOLVE_EXACT_MODULE_BEFORE_ACCESS");
            } catch (JSONException ignored) {}
            return out;
        }
    }

    private static final class MapRow {
        final long start;
        final long end;
        final long fileOffset;
        final String perms;
        final String path;

        MapRow(long start, long end, long fileOffset, String perms, String path) {
            this.start = start;
            this.end = end;
            this.fileOffset = fileOffset;
            this.perms = perms;
            this.path = path;
        }

        boolean readable() { return perms.indexOf('r') >= 0; }
        boolean writable() { return perms.indexOf('w') >= 0; }

        boolean contains(long address, int length) {
            if (address < start || length <= 0) return false;
            long finish = address + (long) length;
            return finish >= address && finish <= end;
        }
    }

    static ResolvedAddress resolve(
            RootMemoryInstrumentation.ProcessLease lease,
            String moduleSelector,
            long rva,
            int length,
            boolean forWrite) throws IOException {
        if (lease == null) throw new IOException("Instrumentation: process lease required for module resolution");
        String selector = normalizeSelector(moduleSelector);
        if (selector.isEmpty()) throw new IOException("Instrumentation: module selector is empty");
        if (rva < 0) throw new IOException("Instrumentation: RVA must be non-negative");
        if (length <= 0) throw new IOException("Instrumentation: resolved access length must be positive");
        if (forWrite && length > RootMemoryInstrumentation.MAX_WRITE_BYTES) {
            throw new IOException("Instrumentation: module write exceeds guarded transaction limit");
        }
        if (!forWrite && length > RootMemoryInstrumentation.MAX_READ_BYTES) {
            throw new IOException("Instrumentation: module read length out of bounds");
        }

        // Revalidate the process lease through the canonical memory primitive before trusting maps.
        RootMemoryInstrumentation.requireRegion(lease, firstReadableAddress(lease), 1, false);

        List<MapRow> rows = readMaps(lease.pid);
        LinkedHashMap<String, List<MapRow>> candidates = new LinkedHashMap<>();
        boolean exactPath = selector.indexOf('/') >= 0;
        for (MapRow row : rows) {
            if (row.path.isEmpty() || row.path.charAt(0) == '[') continue;
            String normalizedPath = normalizeMappedPath(row.path);
            if (normalizedPath.isEmpty()) continue;
            boolean match = exactPath ? normalizedPath.equals(selector) : basename(normalizedPath).equals(selector);
            if (!match) continue;
            candidates.computeIfAbsent(normalizedPath, ignored -> new ArrayList<>()).add(row);
        }
        if (candidates.isEmpty()) throw new IOException("Instrumentation: requested module is not mapped in the selected process");
        if (candidates.size() != 1) throw new IOException("Instrumentation: module selector is ambiguous across mapped paths");

        Map.Entry<String, List<MapRow>> only = candidates.entrySet().iterator().next();
        String modulePath = only.getKey();
        List<MapRow> moduleRows = only.getValue();
        long loadBias = consistentLoadBias(moduleRows);
        if (rva > Long.MAX_VALUE - loadBias) throw new IOException("Instrumentation: RVA address overflow");
        long address = loadBias + rva;

        MapRow owner = null;
        for (MapRow row : moduleRows) {
            if (row.contains(address, length)) {
                owner = row;
                break;
            }
        }
        if (owner == null) throw new IOException("Instrumentation: resolved RVA is outside the selected module mappings");
        if (!owner.readable()) throw new IOException("Instrumentation: resolved module mapping is not readable");
        if (forWrite && !owner.writable()) throw new IOException("Instrumentation: resolved module mapping is not writable");

        // Canonical region validation catches map races between the resolver snapshot and the access.
        RootMemoryInstrumentation.MemoryRegion canonical = RootMemoryInstrumentation.requireRegion(lease, address, length, forWrite);
        String canonicalPath = normalizeMappedPath(canonical.path);
        if (!modulePath.equals(canonicalPath)) {
            throw new IOException("Instrumentation: module mapping changed during RVA resolution");
        }
        return new ResolvedAddress(lease, selector, modulePath, loadBias, rva, address, length, owner.perms, System.currentTimeMillis());
    }

    static byte[] read(ResolvedAddress resolved) throws IOException {
        ResolvedAddress fresh = revalidate(resolved, false);
        return RootMemoryInstrumentation.read(fresh.lease, fresh.address, fresh.length);
    }

    static RootMemoryInstrumentation.WriteReceipt guardedWrite(
            ResolvedAddress resolved,
            byte[] expectedOriginal,
            byte[] replacement) throws IOException {
        if (resolved == null) throw new IOException("Instrumentation: resolved module address required");
        if (replacement == null || replacement.length != resolved.length) {
            throw new IOException("Instrumentation: replacement length must match resolved transaction length");
        }
        ResolvedAddress fresh = revalidate(resolved, true);
        return RootMemoryInstrumentation.guardedWrite(fresh.lease, fresh.address, expectedOriginal, replacement);
    }

    private static ResolvedAddress revalidate(ResolvedAddress previous, boolean forWrite) throws IOException {
        if (previous == null) throw new IOException("Instrumentation: resolved module address required");
        ResolvedAddress fresh = resolve(previous.lease, previous.modulePath, previous.rva, previous.length, forWrite);
        if (!fresh.modulePath.equals(previous.modulePath)
                || fresh.loadBias != previous.loadBias
                || fresh.address != previous.address) {
            throw new IOException("Instrumentation: module mapping moved after address resolution");
        }
        return fresh;
    }

    private static long firstReadableAddress(RootMemoryInstrumentation.ProcessLease lease) throws IOException {
        List<MapRow> rows = readMaps(lease.pid);
        for (MapRow row : rows) {
            if (row.readable() && row.start >= 0 && row.end > row.start) return row.start;
        }
        throw new IOException("Instrumentation: selected process has no readable mappings");
    }

    private static long consistentLoadBias(List<MapRow> rows) throws IOException {
        Long loadBias = null;
        for (MapRow row : rows) {
            if (row.fileOffset < 0 || row.fileOffset > row.start) {
                throw new IOException("Instrumentation: invalid module file offset in memory map");
            }
            long candidate = row.start - row.fileOffset;
            if (loadBias == null) loadBias = candidate;
            else if (loadBias.longValue() != candidate) {
                throw new IOException("Instrumentation: module load bias is ambiguous across mappings");
            }
        }
        if (loadBias == null || loadBias < 0) throw new IOException("Instrumentation: module load bias unavailable");
        return loadBias;
    }

    private static List<MapRow> readMaps(int pid) throws IOException {
        RootAccess.ExecResult maps = RootAccess.runSu("cat /proc/" + pid + "/maps", 6_000, MAX_MAPS_BYTES);
        if (maps.timedOut || maps.exitCode != 0 || maps.truncated) {
            throw new IOException("Instrumentation: complete memory map unavailable for module resolution");
        }
        ArrayList<MapRow> out = new ArrayList<>();
        for (String line : maps.output.split("\\R")) {
            MapRow row = parseMapRow(line);
            if (row != null) out.add(row);
        }
        if (out.isEmpty()) throw new IOException("Instrumentation: memory map contains no usable rows");
        return out;
    }

    private static MapRow parseMapRow(String line) {
        if (line == null) return null;
        String[] parts = line.trim().split("\\s+", 6);
        if (parts.length < 5) return null;
        String[] range = parts[0].split("-", 2);
        if (range.length != 2) return null;
        long start = parseHex(range[0]), end = parseHex(range[1]), offset = parseHex(parts[2]);
        if (start < 0 || end <= start || offset < 0) return null;
        String path = parts.length >= 6 ? parts[5].trim() : "";
        return new MapRow(start, end, offset, parts[1], path);
    }

    private static String normalizeSelector(String raw) {
        if (raw == null) return "";
        String value = normalizeMappedPath(raw.trim());
        while (value.contains("//")) value = value.replace("//", "/");
        return value;
    }

    private static String normalizeMappedPath(String raw) {
        if (raw == null) return "";
        String value = raw.trim();
        if (value.endsWith(" (deleted)")) value = value.substring(0, value.length() - " (deleted)".length());
        return value;
    }

    private static String basename(String path) {
        if (path == null || path.isEmpty()) return "";
        String name = new File(path).getName();
        return name == null ? "" : name;
    }

    private static long parseHex(String value) {
        try { return Long.parseUnsignedLong(value.trim(), 16); }
        catch (Exception ignored) { return -1; }
    }

    private static String hex(long value) { return String.format(Locale.ROOT, "0x%x", value); }
}
