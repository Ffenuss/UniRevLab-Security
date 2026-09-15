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
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.impl.NoOpCodeCache;
import jadx.api.impl.SimpleCodeWriter;
import jadx.api.security.JadxSecurityFlag;
import jadx.api.security.impl.JadxSecurity;
import jadx.core.plugins.files.IJadxFilesGetter;

/**
 * Bounded-memory full reconstruction exporter.
 *
 * Full Analysis must not keep an entire base+split APK set inside one long-lived
 * JadxDecompiler. Each APK member is loaded, saved, closed and garbage-collected
 * before the next member is opened. Cross-split interactive xrefs remain a later
 * Decompiler 2.0 concern; this class exists to make full reconstruction reliable.
 */
final class BoundedJadxExporter {
    static final String BACKEND="JADX 1.5.6 bounded";

    interface Progress {
        void progress(String text);
    }

    static final class Result {
        final File output;
        final int classCount,resourceCount,errorCount,warnCount,failedInputs;
        final boolean complete;
        final JSONArray inputs,degradedReasons;
        Result(File output,int classCount,int resourceCount,int errorCount,int warnCount,int failedInputs,boolean complete,JSONArray inputs,JSONArray degradedReasons){
            this.output=output;this.classCount=classCount;this.resourceCount=resourceCount;this.errorCount=errorCount;this.warnCount=warnCount;this.failedInputs=failedInputs;this.complete=complete;this.inputs=inputs;this.degradedReasons=degradedReasons;
        }
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
            File itemRoot=new File(root,String.format(Locale.ROOT,"%03d-%s",i,safe(input.getName())));
            File outDir=new File(itemRoot,"out"),configDir=new File(itemRoot,"config"),cacheDir=new File(itemRoot,"cache"),tempDir=new File(itemRoot,"tmp");
            mkdir(outDir);mkdir(configDir);mkdir(cacheDir);mkdir(tempDir);
            JadxDecompiler jadx=null;
            try{
                if(progress!=null)progress.progress("JADX bounded: "+(i+1)+"/"+targetInputs.size()+" · "+input.getName());
                JSONObject memoryStart=AnalysisJournal.memory();
                AnalysisJournal.append(context,"BACKEND_START","JADX "+input.getName(),new JSONObject().put("index",i).put("total",targetInputs.size()).put("memory",memoryStart));
                JadxArgs args=new JadxArgs();
                args.setInputFiles(Collections.singletonList(input));
                args.setOutDir(outDir);
                args.setThreadsCount(1);
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
                int c=jadx.getClasses().size(),r=jadx.getResources().size();
                jadx.save();check(cancelled);
                int e=jadx.getErrorsCount(),w=jadx.getWarnsCount();
                classes+=c;resources+=r;errors+=e;warns+=w;
                row.put("status","SUCCESS").put("classes",c).put("resources",r).put("errors",e).put("warnings",w);
                completedDirs.add(itemRoot);
                AnalysisJournal.append(context,"BACKEND_FINISH","JADX "+input.getName(),new JSONObject().put("status","SUCCESS").put("classes",c).put("resources",r).put("errors",e).put("warnings",w).put("memory",AnalysisJournal.memory()));
            }catch(InterruptedIOException cancelledError){throw cancelledError;}
            catch(Throwable t){
                failed++;
                String message=safeMessage(t);
                row.put("status","FAILED").put("errorClass",t.getClass().getName()).put("error",message).put("memory",AnalysisJournal.memory());
                degraded.put(input.getName()+": "+t.getClass().getSimpleName()+": "+message);
                AnalysisJournal.exception(context,t instanceof OutOfMemoryError?"JADX_OOM":"JADX_FAILURE",t);
                if(progress!=null)progress.progress("JADX частичен: "+input.getName()+" · "+t.getClass().getSimpleName()+" · продолжаю следующий APK/backend.");
            }finally{
                if(jadx!=null)try{jadx.close();}catch(Throwable ignored){}
                rows.put(row);
                System.gc();
            }
        }

        check(cancelled);
        JSONObject manifest=new JSONObject()
                .put("schema","modkit-jadx-bounded-1.0")
                .put("backend",BACKEND)
                .put("complete",failed==0)
                .put("inputCount",targetInputs.size())
                .put("failedInputs",failed)
                .put("classes",classes).put("resources",resources).put("errors",errors).put("warnings",warns)
                .put("inputs",rows).put("degradedReasons",degraded);

        try(ZipOutputStream out=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))){
            byte[] buffer=new byte[128*1024];
            for(File item:completedDirs){check(cancelled);zipTree(root,item,out,buffer,cancelled);}
            ZipEntry meta=new ZipEntry("modkit-jadx-bounded.json");meta.setTime(0L);out.putNextEntry(meta);out.write(manifest.toString(2).getBytes(StandardCharsets.UTF_8));out.closeEntry();
        }catch(Throwable t){Files.deleteIfExists(tmp.toPath());throw t;}
        Files.move(tmp.toPath(),zip.toPath(),StandardCopyOption.REPLACE_EXISTING);
        return new Result(zip,classes,resources,errors,warns,failed,failed==0,rows,degraded);
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