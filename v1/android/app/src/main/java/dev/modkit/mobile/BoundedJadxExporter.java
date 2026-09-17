package dev.modkit.mobile;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.impl.NoOpCodeCache;
import jadx.api.impl.SimpleCodeWriter;
import jadx.api.security.JadxSecurityFlag;
import jadx.api.security.impl.JadxSecurity;
import jadx.core.plugins.files.IJadxFilesGetter;

/**
 * Bounded-memory source reconstruction exporter.
 *
 * Large split-heavy games can contain a very large base.apk. Loading every
 * classes*.dex from that APK into one JadxDecompiler can exceed the Android heap
 * before Java gets a chance to throw/catch OutOfMemoryError. To keep the process
 * alive, each APK is now opened only as a ZIP container and every root classes*.dex
 * is extracted, decompiled, saved and closed independently. Apktool owns resource,
 * manifest and smali reconstruction in the next pipeline stage, so JADX deliberately
 * skips resources here instead of duplicating them in memory.
 */
final class BoundedJadxExporter {
    static final String BACKEND="JADX 1.5.6 bounded";

    interface Progress { void progress(String text); }

    static final class Result {
        final File output;
        final int classCount,resourceCount,errorCount,warnCount,failedInputs;
        final boolean complete;
        final JSONArray inputs,degradedReasons;
        Result(File output,int classCount,int resourceCount,int errorCount,int warnCount,int failedInputs,boolean complete,JSONArray inputs,JSONArray degradedReasons){
            this.output=output;this.classCount=classCount;this.resourceCount=resourceCount;this.errorCount=errorCount;this.warnCount=warnCount;this.failedInputs=failedInputs;this.complete=complete;this.inputs=inputs;this.degradedReasons=degradedReasons;
        }
    }

    private static final class DexEntryInfo {
        final String name; final long uncompressedSize;
        DexEntryInfo(String name,long uncompressedSize){this.name=name;this.uncompressedSize=uncompressedSize;}
    }

    private BoundedJadxExporter(){}

    static Result export(Context context,List<File> targetInputs,AtomicBoolean cancelled,Progress progress)throws Exception{
        if(targetInputs==null||targetInputs.isEmpty())throw new IOException("JADX: target inputs пусты");
        App app=(App)context.getApplicationContext();
        File root=app.file("jadx-batch");deleteTree(root);mkdir(root);
        File zip=app.file("modkit-decompiled.zip"),tmp=app.file("modkit-decompiled.zip.tmp");
        Files.deleteIfExists(zip.toPath());Files.deleteIfExists(tmp.toPath());

        int classes=0,resources=0,errors=0,warns=0,failed=0;
        JSONArray rows=new JSONArray(),degraded=new JSONArray();
        ArrayList<File> completedDirs=new ArrayList<>();

        for(int i=0;i<targetInputs.size();i++){
            check(cancelled);
            File input=targetInputs.get(i);
            JSONObject row=new JSONObject().put("index",i).put("name",input.getName()).put("size",input.length());
            File itemRoot=new File(root,String.format(Locale.ROOT,"%03d-%s",i,safe(input.getName())));mkdir(itemRoot);
            List<DexEntryInfo> dexEntries;
            try{dexEntries=listDexEntries(input);}catch(Throwable t){
                failed++;
                String message=safeMessage(t);
                row.put("status","FAILED").put("dexCount",0).put("errorClass",t.getClass().getName()).put("error",message);
                rows.put(row);degraded.put(input.getName()+": "+t.getClass().getSimpleName()+": "+message);
                AnalysisJournal.exception(context,"JADX_CONTAINER_FAILURE",t);
                continue;
            }
            row.put("dexCount",dexEntries.size()).put("resourcesDelegatedToApktool",true);
            if(dexEntries.isEmpty()){
                row.put("status","NO_DEX").put("dexSucceeded",0).put("dexFailed",0);
                rows.put(row);completedDirs.add(itemRoot);continue;
            }

            int apkClasses=0,apkErrors=0,apkWarns=0,dexSucceeded=0,dexFailed=0;
            JSONArray dexRows=new JSONArray();
            for(int d=0;d<dexEntries.size();d++){
                check(cancelled);
                DexEntryInfo dexInfo=dexEntries.get(d);
                File dexRoot=new File(itemRoot,String.format(Locale.ROOT,"dex-%03d-%s",d,safe(dexInfo.name)));
                File outDir=new File(dexRoot,"out"),configDir=new File(dexRoot,"config"),cacheDir=new File(dexRoot,"cache"),tempDir=new File(dexRoot,"tmp"),dexFile=new File(dexRoot,"input.dex");
                mkdir(outDir);mkdir(configDir);mkdir(cacheDir);mkdir(tempDir);
                JSONObject dexRow=new JSONObject().put("index",d).put("entry",dexInfo.name).put("declaredSize",dexInfo.uncompressedSize);
                JadxDecompiler jadx=null;
                try{
                    if(progress!=null)progress.progress("JADX bounded: "+(i+1)+"/"+targetInputs.size()+" · "+input.getName()+" · DEX "+(d+1)+"/"+dexEntries.size()+" · "+dexInfo.name);
                    extractDex(input,dexInfo.name,dexFile,cancelled);
                    dexRow.put("size",dexFile.length());
                    AnalysisJournal.append(context,"BACKEND_START","JADX "+input.getName()+"!"+dexInfo.name,new JSONObject().put("apkIndex",i).put("dexIndex",d).put("dexTotal",dexEntries.size()).put("memory",AnalysisJournal.memory()));

                    JadxArgs args=new JadxArgs();
                    args.setInputFiles(Collections.singletonList(dexFile));
                    args.setOutDir(outDir);
                    args.setThreadsCount(1);
                    args.setSkipResources(true);
                    args.setCodeCache(NoOpCodeCache.INSTANCE);
                    args.setCodeWriterProvider(SimpleCodeWriter::new);
                    java.util.Set<JadxSecurityFlag> flags=JadxSecurityFlag.all();flags.remove(JadxSecurityFlag.SECURE_XML_PARSER);args.setSecurity(new JadxSecurity(flags));
                    args.setLoadJadxClsSetFile(false);
                    args.setFilesGetter(new IJadxFilesGetter(){
                        @Override public Path getConfigDir(){return configDir.toPath();}
                        @Override public Path getCacheDir(){return cacheDir.toPath();}
                        @Override public Path getTempDir(){return tempDir.toPath();}
                    });
                    jadx=new JadxDecompiler(args);
                    jadx.load();check(cancelled);
                    int c=jadx.getClasses().size();
                    jadx.save();check(cancelled);
                    int e=jadx.getErrorsCount(),w=jadx.getWarnsCount();
                    apkClasses+=c;apkErrors+=e;apkWarns+=w;classes+=c;errors+=e;warns+=w;dexSucceeded++;
                    dexRow.put("status","SUCCESS").put("classes",c).put("errors",e).put("warnings",w);
                    AnalysisJournal.append(context,"BACKEND_FINISH","JADX "+input.getName()+"!"+dexInfo.name,new JSONObject().put("status","SUCCESS").put("classes",c).put("errors",e).put("warnings",w).put("memory",AnalysisJournal.memory()));
                }catch(InterruptedIOException cancelledError){throw cancelledError;}
                catch(Throwable t){
                    dexFailed++;
                    String message=safeMessage(t);
                    dexRow.put("status","FAILED").put("errorClass",t.getClass().getName()).put("error",message).put("memory",AnalysisJournal.memory());
                    degraded.put(input.getName()+"!"+dexInfo.name+": "+t.getClass().getSimpleName()+": "+message);
                    AnalysisJournal.exception(context,t instanceof OutOfMemoryError?"JADX_OOM":"JADX_DEX_FAILURE",t);
                    if(progress!=null)progress.progress("JADX DEX частичен: "+input.getName()+"!"+dexInfo.name+" · "+t.getClass().getSimpleName()+" · продолжаю следующий DEX.");
                }finally{
                    if(jadx!=null)try{jadx.close();}catch(Throwable ignored){}
                    dexRows.put(dexRow);
                    try{Files.deleteIfExists(dexFile.toPath());}catch(Exception ignored){}
                    try{deleteTree(cacheDir);}catch(Exception ignored){}
                    try{deleteTree(tempDir);}catch(Exception ignored){}
                    System.gc();
                }
            }

            boolean apkComplete=dexFailed==0;
            if(!apkComplete)failed++;
            row.put("status",apkComplete?"SUCCESS":"PARTIAL").put("dexSucceeded",dexSucceeded).put("dexFailed",dexFailed)
                    .put("classes",apkClasses).put("errors",apkErrors).put("warnings",apkWarns).put("dex",dexRows);
            rows.put(row);completedDirs.add(itemRoot);
        }

        check(cancelled);
        JSONObject manifest=new JSONObject()
                .put("schema","modkit-jadx-bounded-1.1")
                .put("backend",BACKEND)
                .put("strategy","APK_CONTAINER_TO_SINGLE_DEX")
                .put("resourcesDelegatedToApktool",true)
                .put("complete",failed==0)
                .put("inputCount",targetInputs.size())
                .put("failedInputs",failed)
                .put("classes",classes).put("resources",resources).put("errors",errors).put("warnings",warns)
                .put("inputs",rows).put("degradedReasons",degraded);

        try(ZipOutputStream out=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))){
            byte[] buffer=new byte[128*1024];
            for(File item:completedDirs){check(cancelled);zipTree(root,item,out,buffer,cancelled);}
            ZipEntry meta=new ZipEntry("modkit-jadx-bounded.json");meta.setTime(0L);out.putNextEntry(meta);out.write(manifest.toString(2).getBytes(StandardCharsets.UTF_8));out.closeEntry();
        }catch(Exception e){Files.deleteIfExists(tmp.toPath());throw e;}
        catch(Error e){try{Files.deleteIfExists(tmp.toPath());}catch(Exception ignored){}throw e;}
        Files.move(tmp.toPath(),zip.toPath(),StandardCopyOption.REPLACE_EXISTING);
        return new Result(zip,classes,resources,errors,warns,failed,failed==0,rows,degraded);
    }

    private static List<DexEntryInfo> listDexEntries(File apk)throws IOException{
        ArrayList<DexEntryInfo> out=new ArrayList<>();
        try(ZipFile zip=new ZipFile(apk)){
            Enumeration<? extends ZipEntry> entries=zip.entries();
            while(entries.hasMoreElements()){
                ZipEntry entry=entries.nextElement();if(entry.isDirectory())continue;
                String name=entry.getName();
                if(name.matches("classes(?:\\d+)?\\.dex"))out.add(new DexEntryInfo(name,entry.getSize()));
            }
        }
        out.sort(Comparator.comparingInt(value->dexOrdinal(value.name)));
        return out;
    }

    private static int dexOrdinal(String name){
        if("classes.dex".equals(name))return 1;
        try{return Integer.parseInt(name.substring("classes".length(),name.length()-".dex".length()));}catch(Exception ignored){return Integer.MAX_VALUE;}
    }

    private static void extractDex(File apk,String entryName,File destination,AtomicBoolean cancelled)throws Exception{
        try(ZipFile zip=new ZipFile(apk)){
            ZipEntry entry=zip.getEntry(entryName);if(entry==null||entry.isDirectory())throw new IOException("DEX entry исчез: "+entryName);
            try(InputStream in=new BufferedInputStream(zip.getInputStream(entry));BufferedOutputStream out=new BufferedOutputStream(new FileOutputStream(destination))){
                byte[] buffer=new byte[256*1024];int n;while((n=in.read(buffer))!=-1){check(cancelled);out.write(buffer,0,n);}out.flush();
            }
        }catch(Exception e){try{Files.deleteIfExists(destination.toPath());}catch(Exception ignored){}throw e;}
    }

    private static void check(AtomicBoolean cancelled)throws InterruptedIOException{if((cancelled!=null&&cancelled.get())||Thread.currentThread().isInterrupted())throw new InterruptedIOException("cancelled");}
    private static void mkdir(File value)throws IOException{if(!value.isDirectory()&&!value.mkdirs()&&!value.isDirectory())throw new IOException("Cannot create "+value);}
    private static String safe(String value){String s=value==null?"input.apk":value.replaceAll("[^A-Za-z0-9._-]+","_");return s.isEmpty()?"input.apk":s;}
    private static String safeMessage(Throwable t){String m=t==null?null:t.getMessage();return m==null?(t==null?"unknown":t.getClass().getSimpleName()):m;}

    private static void zipTree(File root,File node,ZipOutputStream out,byte[] buffer,AtomicBoolean cancelled)throws Exception{
        check(cancelled);File[] children=node.listFiles();if(children==null)return;
        java.util.Arrays.sort(children,java.util.Comparator.comparing(File::getName));
        for(File child:children){check(cancelled);if(child.isDirectory()){zipTree(root,child,out,buffer,cancelled);continue;}
            String rel=root.toPath().relativize(child.toPath()).toString().replace(File.separatorChar,'/');
            ZipEntry entry=new ZipEntry(rel);entry.setTime(0L);out.putNextEntry(entry);
            try(InputStream in=new BufferedInputStream(new FileInputStream(child))){int n;while((n=in.read(buffer))!=-1){check(cancelled);out.write(buffer,0,n);}}
            out.closeEntry();
        }
    }

    private static void deleteTree(File value)throws IOException{
        if(value==null||!value.exists())return;
        if(value.isDirectory()){File[] children=value.listFiles();if(children!=null)for(File child:children)deleteTree(child);}
        if(!value.delete()&&value.exists())throw new IOException("Cannot delete "+value);
    }
}
