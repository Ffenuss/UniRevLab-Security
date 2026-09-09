from pathlib import Path
import sys

root = Path(sys.argv[1])
src = root / "android/app/src/main/java/dev/modkit/mobile"

replacements = {
    "ReWorkspaceActivity.java": [
        ("Files.readString(app.file(name).toPath(),StandardCharsets.UTF_8)", "Io.readUtf8(app.file(name))"),
    ],
    "NativeWorkspaceActivity.java": [
        ("Files.readString(app.file(name).toPath(),StandardCharsets.UTF_8)", "Io.readUtf8(app.file(name))"),
    ],
    "PatchPackActivity.java": [
        ("Files.readString(app.file(name).toPath(),StandardCharsets.UTF_8)", "Io.readUtf8(app.file(name))"),
    ],
    "MenuBuilderActivity.java": [
        ("Files.readString(app.file(\"menu-spec.json\").toPath(),StandardCharsets.UTF_8)", "Io.readUtf8(app.file(\"menu-spec.json\"))"),
        ("Files.writeString(app.file(\"menu-spec.json\").toPath(),o.toString(2),StandardCharsets.UTF_8)", "Io.writeUtf8(app.file(\"menu-spec.json\"),o.toString(2))"),
        ("Files.readString(app.file(\"menu-validation.json\").toPath(),StandardCharsets.UTF_8)", "Io.readUtf8(app.file(\"menu-validation.json\"))"),
        ("Files.readString(app.file(\"menu-preflight.json\").toPath(),StandardCharsets.UTF_8)", "Io.readUtf8(app.file(\"menu-preflight.json\"))"),
    ],
}

for filename, pairs in replacements.items():
    path = src / filename
    text = path.read_text(encoding="utf-8")
    for old, new in pairs:
        if old not in text:
            raise SystemExit(f"expected expression not found in {filename}: {old}")
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")

(src / "Io.java").write_text(r'''package dev.modkit.mobile;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

final class Io {
    private Io() {}

    static String readUtf8(File file) throws IOException {
        try (FileInputStream in = new FileInputStream(file);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) {
                out.write(buffer, 0, n);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    static void writeUtf8(File file, String text) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs() && !parent.isDirectory()) {
            throw new IOException("Cannot create directory: " + parent);
        }
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
            out.flush();
        }
    }
}
''', encoding="utf-8")

for path in src.glob("*.java"):
    text = path.read_text(encoding="utf-8")
    if "Files.readString(" in text or "Files.writeString(" in text:
        raise SystemExit(f"Java 11 Files API remains in {path.name}")

print("Applied Android Java compatibility patch")
