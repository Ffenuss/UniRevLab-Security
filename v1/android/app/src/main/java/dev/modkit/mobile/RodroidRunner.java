package dev.modkit.mobile;

import android.content.Context;
import java.io.*;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicBoolean;

final class RodroidRunner {
    interface Listener { void progress(String text); }

    static File run(Context context, File binary, File metadata, File base,
                    AtomicBoolean cancelled, Listener listener) throws Exception {
        deleteTree(base);
        if (!base.mkdirs() && !base.isDirectory()) throw new IOException("Не удалось создать каталог дампа");
        File config = new File(base, "config.json");
        try (InputStream in=context.getAssets().open("rodroid-config.json")) {
            Files.copy(in, config.toPath());
        }
        File executable = new File(context.getApplicationInfo().nativeLibraryDir, "librodroid.so");
        if (!executable.canExecute()) executable.setExecutable(true, false);
        Process process = new ProcessBuilder(executable.getAbsolutePath(),
                "--binary",binary.getAbsolutePath(), "--metadata",metadata.getAbsolutePath(),
                "--output",base.getAbsolutePath(), "--config",config.getAbsolutePath())
                .redirectErrorStream(true).directory(base).start();
        process.getOutputStream().close();
        StringBuilder tail = new StringBuilder();
        try (BufferedReader reader=new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line=reader.readLine())!=null) {
                if (cancelled.get()) { process.destroyForcibly(); throw new IOException("Операция отменена"); }
                String clean=line.replaceAll("\\u001B\\[[;\\d]*m","").trim();
                if (!clean.isEmpty()) {
                    listener.progress("Rodroid: "+clean);
                    tail.append(clean).append('\n');
                    if (tail.length()>12000) tail.delete(0,tail.length()-12000);
                }
            }
        }
        int code=process.waitFor();
        if (cancelled.get()) throw new IOException("Операция отменена");
        if (code!=0) throw new IOException("Rodroid завершился с кодом "+code+": "+tail);
        File[] dumps=base.listFiles(f->f.isDirectory()&&f.getName().startsWith("Dump"));
        if (dumps==null||dumps.length!=1||!new File(dumps[0],"script.json").isFile()||!new File(dumps[0],"dump.cs").isFile())
            throw new IOException("Rodroid не создал полный dump.cs/script.json");
        return dumps[0];
    }

    static void deleteTree(File file) throws IOException {
        if (!file.exists()) return;
        File[] children=file.listFiles();
        if (children!=null) for(File child:children) deleteTree(child);
        if(!file.delete()) throw new IOException("Не удалось очистить "+file.getName());
    }
}
