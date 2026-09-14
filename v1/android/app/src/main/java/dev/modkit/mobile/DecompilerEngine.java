package dev.modkit.mobile;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaNode;
import jadx.api.ResourceFile;
import jadx.api.impl.NoOpCodeCache;
import jadx.api.impl.SimpleCodeWriter;
import jadx.api.security.JadxSecurityFlag;
import jadx.api.security.impl.JadxSecurity;
import jadx.core.plugins.files.IJadxFilesGetter;
import jadx.core.xmlgen.ResContainer;

/**
 * ModKit dev36 decompiler backend.
 *
 * Design rules:
 *  - APK/APK-set aware (base + every locally copied split is loaded together)
 *  - lazy Java generation: class index never calls getCode()
 *  - one JADX worker thread on Android to cap memory pressure
 *  - no network dependency at runtime; all analysis is local
 *  - Java source is a decompiler view, not an editable/recompilable source of truth
 *  - Smali view is the bytecode-level representation exposed by JADX
 */
final class DecompilerEngine implements Closeable {
    static final String BACKEND = "JADX 1.5.6";
    static final int MAX_SEARCH_HITS = 100;
    static final int MAX_XREFS = 120;

    static final class ClassEntry {
        final String fullName;
        final String shortName;
        ClassEntry(String fullName, String shortName) { this.fullName=fullName; this.shortName=shortName; }
    }

    static final class SearchHit {
        final String className;
        final int line;
        final String preview;
        SearchHit(String className, int line, String preview) { this.className=className; this.line=line; this.preview=preview; }
    }

    private final App app;
    private final File outDir;
    private final File configDir;
    private final File cacheDir;
    private final File tempDir;
    private JadxDecompiler jadx;
    private final LinkedHashMap<String,JavaClass> classes = new LinkedHashMap<>();
    private List<File> inputs = Collections.emptyList();

    DecompilerEngine(Context context) {
        this.app=(App)context.getApplicationContext();
        File root=app.file("decompiler");
        this.outDir=new File(root,"export");
        this.configDir=new File(root,"config");
        this.cacheDir=new File(root,"cache");
        this.tempDir=new File(root,"tmp");
    }

    synchronized void open() throws Exception {
        close();
        inputs=resolveTargetInputs(app);
        if(inputs.isEmpty()) throw new FileNotFoundException("Сначала выберите APK или установленный пакет.");
        mkdir(configDir); mkdir(cacheDir); mkdir(tempDir); mkdir(outDir);

        JadxArgs args=new JadxArgs();
        args.setInputFiles(inputs);
        args.setOutDir(outDir);
        args.setThreadsCount(1);
        args.setCodeCache(NoOpCodeCache.INSTANCE);
        args.setCodeWriterProvider(SimpleCodeWriter::new);
        Set<JadxSecurityFlag> flags=JadxSecurityFlag.all();
        flags.remove(JadxSecurityFlag.SECURE_XML_PARSER);
        args.setSecurity(new JadxSecurity(flags));
        args.setLoadJadxClsSetFile(false);
        args.setFilesGetter(new IJadxFilesGetter(){
            @Override public Path getConfigDir(){return configDir.toPath();}
            @Override public Path getCacheDir(){return cacheDir.toPath();}
            @Override public Path getTempDir(){return tempDir.toPath();}
        });

        JadxDecompiler instance=new JadxDecompiler(args);
        try {
            instance.load();
            ArrayList<JavaClass> ordered=new ArrayList<>(instance.getClasses());
            ordered.sort(Comparator.comparing(JavaClass::getFullName,String.CASE_INSENSITIVE_ORDER));
            for(JavaClass cls:ordered) classes.put(cls.getFullName(),cls);
            jadx=instance;
        } catch(Throwable t) {
            try{instance.close();}catch(Throwable ignored){}
            throw t;
        }
    }

    synchronized boolean isOpen(){return jadx!=null;}
    synchronized int classCount(){return classes.size();}
    synchronized int resourceCount(){return jadx==null?0:jadx.getResources().size();}
    synchronized int errorCount(){return jadx==null?0:jadx.getErrorsCount();}
    synchronized int warnCount(){return jadx==null?0:jadx.getWarnsCount();}
    synchronized List<File> inputFiles(){return new ArrayList<>(inputs);}

    synchronized List<ClassEntry> classes(String query, int limit) {
        String q=query==null?"":query.trim().toLowerCase(Locale.ROOT);
        ArrayList<ClassEntry> out=new ArrayList<>();
        for(JavaClass cls:classes.values()){
            String full=cls.getFullName();
            if(!q.isEmpty()&&!full.toLowerCase(Locale.ROOT).contains(q))continue;
            out.add(new ClassEntry(full,cls.getName()));
            if(out.size()>=limit)break;
        }
        return out;
    }

    synchronized String javaCode(String fullName) throws Exception {
        JavaClass cls=requireClass(fullName);
        try{return cls.getCode();}
        catch(Throwable t){throw new Exception("JADX Java decode failed for "+fullName+": "+safeMessage(t),t);}
    }

    synchronized String smaliCode(String fullName) throws Exception {
        JavaClass cls=requireClass(fullName);
        try{return cls.getSmali();}
        catch(Throwable t){throw new Exception("Smali decode failed for "+fullName+": "+safeMessage(t),t);}
    }

    synchronized String xrefs(String fullName) throws Exception {
        JavaClass cls=requireClass(fullName);
        try {
            List<JavaNode> useIn=cls.getUseIn();
            StringBuilder sb=new StringBuilder();
            sb.append("Uses of ").append(fullName).append(" · ").append(useIn.size()).append('\n');
            int count=0;
            for(JavaNode node:useIn){
                sb.append("• ").append(node.getFullName()).append('\n');
                if(++count>=MAX_XREFS){sb.append("… truncated at ").append(MAX_XREFS).append("\n");break;}
            }
            if(useIn.isEmpty())sb.append("No local incoming references reported by JADX.\n");
            return sb.toString();
        } catch(Throwable t){throw new Exception("Xref resolution failed: "+safeMessage(t),t);}
    }

    List<SearchHit> searchCode(String query, AtomicBoolean cancel) throws Exception {
        final String q=query==null?"":query.trim().toLowerCase(Locale.ROOT);
        if(q.length()<2)throw new IllegalArgumentException("Введите минимум 2 символа.");
        final ArrayList<JavaClass> snapshot;
        synchronized(this){ snapshot=new ArrayList<>(classes.values()); }
        ArrayList<SearchHit> hits=new ArrayList<>();
        for(JavaClass cls:snapshot){
            if(cancel!=null&&cancel.get())break;
            String code;
            synchronized(this){
                try{code=cls.getCode();}
                catch(Throwable ignored){continue;}
            }
            String[] lines=code.split("\\R",-1);
            for(int i=0;i<lines.length;i++){
                if(cancel!=null&&cancel.get())break;
                if(lines[i].toLowerCase(Locale.ROOT).contains(q)){
                    String p=lines[i].trim();
                    if(p.length()>180)p=p.substring(0,180)+"…";
                    hits.add(new SearchHit(cls.getFullName(),i+1,p));
                    if(hits.size()>=MAX_SEARCH_HITS)return hits;
                }
            }
            synchronized(this){try{cls.unload();}catch(Throwable ignored){}}
        }
        return hits;
    }

    synchronized List<String> resources(String query, int limit) {
        ensureOpen();
        String q=query==null?"":query.trim().toLowerCase(Locale.ROOT);
        ArrayList<String> out=new ArrayList<>();
        for(ResourceFile rf:jadx.getResources()){
            String n=rf.getDeobfName();
            if(!q.isEmpty()&&!n.toLowerCase(Locale.ROOT).contains(q))continue;
            out.add(n);
            if(out.size()>=limit)break;
        }
        out.sort(String.CASE_INSENSITIVE_ORDER);
        return out;
    }

    synchronized String resourcePreview(String name) throws Exception {
        ensureOpen();
        ResourceFile found=null;
        for(ResourceFile rf:jadx.getResources()) if(name.equals(rf.getDeobfName())||name.equals(rf.getOriginalName())){found=rf;break;}
        if(found==null)throw new FileNotFoundException(name);
        try {
            ResContainer c=found.loadContent();
            StringBuilder sb=new StringBuilder();
            renderContainer(c,sb,0,256*1024);
            if(sb.length()==0)return "Binary resource: "+name+" ("+found.getType()+")";
            return sb.toString();
        } catch(Throwable t){throw new Exception("Resource decode failed: "+safeMessage(t),t);}
    }

    /** Save complete JADX output then zip it. Intended for explicit user export only. */
    synchronized File exportAllZip(AtomicBoolean cancel) throws Exception {
        ensureOpen();
        deleteTree(outDir);mkdir(outDir);
        if(cancel!=null&&cancel.get())throw new InterruptedIOException("cancelled");
        try{jadx.save();}catch(Throwable t){throw new Exception("JADX export failed: "+safeMessage(t),t);}
        if(cancel!=null&&cancel.get())throw new InterruptedIOException("cancelled");
        File zip=app.file("modkit-decompiled.zip");
        File tmp=new File(zip.getParentFile(),zip.getName()+".tmp");
        try(ZipOutputStream z=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))){
            zipTree(outDir,outDir,z,cancel);
            JSONObject manifest=new JSONObject()
                .put("schema","modkit-decompiler-export-1.0")
                .put("backend",BACKEND)
                .put("inputs",new JSONArray(inputNames()))
                .put("classes",classes.size())
                .put("errors",jadx.getErrorsCount())
                .put("warnings",jadx.getWarnsCount());
            ZipEntry e=new ZipEntry("modkit-decompiler.json");z.putNextEntry(e);z.write(manifest.toString(2).getBytes(StandardCharsets.UTF_8));z.closeEntry();
        }
        Files.move(tmp.toPath(),zip.toPath(),java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        return zip;
    }

    private List<String> inputNames(){ArrayList<String> out=new ArrayList<>();for(File f:inputs)out.add(f.getName());return out;}

    static List<File> resolveTargetInputs(App app) throws Exception {
        ArrayList<File> out=new ArrayList<>();
        File target=app.file("installed-target.json");
        if(target.isFile()){
            JSONObject obj=new JSONObject(Io.readUtf8(target));
            JSONArray splits=obj.optJSONArray("splits");
            if(splits!=null){
                for(int i=0;i<splits.length();i++){
                    JSONObject row=splits.optJSONObject(i);if(row==null)continue;
                    File f=new File(row.optString("path",""));
                    if(f.isFile()&&!containsCanonical(out,f))out.add(f);
                }
            }
        }
        if(out.isEmpty()){
            File base=app.file("game.apk");
            if(base.isFile())out.add(base);
        }
        return out;
    }

    private static boolean containsCanonical(List<File> files,File candidate) throws IOException{
        String c=candidate.getCanonicalPath();for(File f:files)if(f.getCanonicalPath().equals(c))return true;return false;
    }

    private JavaClass requireClass(String name) throws FileNotFoundException {ensureOpen();JavaClass cls=classes.get(name);if(cls==null)throw new FileNotFoundException(name);return cls;}
    private void ensureOpen(){if(jadx==null)throw new IllegalStateException("Decompiler is not loaded");}
    private static void mkdir(File f) throws IOException{if(!f.isDirectory()&&!f.mkdirs()&&!f.isDirectory())throw new IOException("Cannot create "+f);}
    private static String safeMessage(Throwable t){String m=t.getMessage();return m==null?t.getClass().getSimpleName():m;}

    private static void renderContainer(ResContainer c,StringBuilder sb,int depth,int max){
        if(c==null||sb.length()>=max)return;
        if(c.getDataType()==ResContainer.DataType.TEXT||c.getDataType()==ResContainer.DataType.RES_TABLE){
            try{String s=c.getText().getCodeStr();if(s!=null&&!s.isEmpty()){if(depth>0)sb.append("\n// ").append(c.getName()).append('\n');sb.append(s);}}
            catch(Throwable ignored){}
        } else if(c.getDataType()==ResContainer.DataType.DECODED_DATA){
            byte[] data=c.getDecodedData();
            if(data!=null&&looksText(data))sb.append(new String(data,StandardCharsets.UTF_8));
        }
        for(ResContainer child:c.getSubFiles()){if(sb.length()>=max)break;renderContainer(child,sb,depth+1,max);}
        if(sb.length()>max){sb.setLength(max);sb.append("\n… preview truncated …");}
    }
    private static boolean looksText(byte[] b){int n=Math.min(b.length,4096),bad=0;for(int i=0;i<n;i++){int v=b[i]&0xff;if(v==0)return false;if(v<9||(v>13&&v<32))bad++;}return n==0||bad<n/20+1;}

    private static void zipTree(File root,File node,ZipOutputStream z,AtomicBoolean cancel)throws Exception{
        if(cancel!=null&&cancel.get())throw new InterruptedIOException("cancelled");
        File[] children=node.listFiles();if(children==null)return;Arrays.sort(children,Comparator.comparing(File::getName));byte[] buf=new byte[128*1024];
        for(File f:children){
            if(cancel!=null&&cancel.get())throw new InterruptedIOException("cancelled");
            if(f.isDirectory()){zipTree(root,f,z,cancel);continue;}
            String rel=root.toPath().relativize(f.toPath()).toString().replace(File.separatorChar,'/');
            ZipEntry e=new ZipEntry(rel);z.putNextEntry(e);try(InputStream in=new BufferedInputStream(new FileInputStream(f))){int n;while((n=in.read(buf))!=-1){if(cancel!=null&&cancel.get())throw new InterruptedIOException("cancelled");z.write(buf,0,n);}}z.closeEntry();
        }
    }
    private static void deleteTree(File f)throws IOException{if(!f.exists())return;if(f.isDirectory()){File[] a=f.listFiles();if(a!=null)for(File c:a)deleteTree(c);}if(!f.delete()&&f.exists())throw new IOException("Cannot delete "+f);}

    @Override public synchronized void close(){
        classes.clear();inputs=Collections.emptyList();
        if(jadx!=null){try{jadx.close();}catch(Throwable ignored){}jadx=null;}
    }
}
