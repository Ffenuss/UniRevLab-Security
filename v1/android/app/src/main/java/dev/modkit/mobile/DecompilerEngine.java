package dev.modkit.mobile;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaNode;
import jadx.api.impl.NoOpCodeCache;
import jadx.api.impl.SimpleCodeWriter;
import jadx.api.security.JadxSecurityFlag;
import jadx.api.security.impl.JadxSecurity;
import jadx.core.plugins.files.IJadxFilesGetter;

/**
 * ModKit 1.1 low-memory decompiler backend.
 *
 * APK sets are never kept in one JADX instance. Every classes*.dex is extracted
 * and indexed independently; interactive Java/Smali decoding reopens only the
 * owning DEX and closes it immediately. Resources are indexed directly from APK
 * ZIPs, so browsing them does not require loading all bytecode into Java heap.
 */
final class DecompilerEngine implements Closeable {
    static final String BACKEND = "JADX 1.5.6 · bounded DEX";
    static final int MAX_SEARCH_HITS = 100;
    static final int MAX_XREFS = 120;
    private static final int MAX_RESOURCE_PREVIEW=256*1024;
    private static final int BUFFER=128*1024;

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
    private static final class DexUnit {
        final int id;final File apk,dex;final String apkName,entry;
        DexUnit(int id,File apk,File dex,String apkName,String entry){this.id=id;this.apk=apk;this.dex=dex;this.apkName=apkName;this.entry=entry;}
        String label(){return apkName+"!"+entry;}
    }
    private static final class IndexedClass {
        final String fullName,shortName;final DexUnit unit;
        IndexedClass(String fullName,String shortName,DexUnit unit){this.fullName=fullName;this.shortName=shortName;this.unit=unit;}
    }
    private static final class ResourceRef {
        final String key,entry;final File apk;
        ResourceRef(String key,String entry,File apk){this.key=key;this.entry=entry;this.apk=apk;}
    }

    private final App app;
    private final File root,configDir,cacheDir,tempDir,dexDir,exportDir;
    private final ArrayList<File> inputs=new ArrayList<>();
    private final ArrayList<DexUnit> dexUnits=new ArrayList<>();
    private final LinkedHashMap<String,IndexedClass> classes=new LinkedHashMap<>();
    private final LinkedHashMap<String,ResourceRef> resources=new LinkedHashMap<>();
    private final ArrayList<String> loadFailures=new ArrayList<>();
    private boolean open=false;
    private int jadxErrors=0,jadxWarnings=0,duplicateClasses=0;

    DecompilerEngine(Context context) {
        this.app=(App)context.getApplicationContext();
        root=app.file("decompiler");configDir=new File(root,"config");cacheDir=new File(root,"cache");tempDir=new File(root,"tmp");dexDir=new File(tempDir,"dex");exportDir=new File(root,"export");
    }

    synchronized void open() throws Exception {
        close();deleteTree(tempDir);deleteTree(exportDir);mkdir(configDir);mkdir(cacheDir);mkdir(tempDir);mkdir(dexDir);mkdir(exportDir);
        TargetResolver.Target target=TargetResolver.resolve(app);inputs.addAll(target.apkFiles());
        int id=0;
        for(File apk:inputs){
            try(ZipFile zip=new ZipFile(apk)){
                ArrayList<? extends ZipEntry> entries=Collections.list(zip.entries());entries.sort(Comparator.comparing(ZipEntry::getName,String.CASE_INSENSITIVE_ORDER));
                for(ZipEntry entry:entries){
                    if(entry.isDirectory())continue;String name=entry.getName();String lower=name.toLowerCase(Locale.ROOT);
                    if(lower.matches("(?:^|.*/)classes\\d*\\.dex")){
                        File dest=new File(dexDir,String.format(Locale.ROOT,"%04d-%s-%s",id,safe(apk.getName()),safe(new File(name).getName())));extract(zip,entry,dest);dexUnits.add(new DexUnit(id++,apk,dest,apk.getName(),name));
                    }else if(!lower.startsWith("meta-inf/")&&!lower.endsWith(".dex")){
                        String key=apk.getName()+"!"+name;resources.put(key,new ResourceRef(key,name,apk));
                    }
                }
            }
        }
        for(DexUnit unit:dexUnits){
            JadxDecompiler jadx=null;
            try{
                jadx=createJadx(unit.dex,new File(tempDir,"index-"+unit.id));jadx.load();
                ArrayList<JavaClass> ordered=new ArrayList<>(jadx.getClasses());ordered.sort(Comparator.comparing(JavaClass::getFullName,String.CASE_INSENSITIVE_ORDER));
                for(JavaClass cls:ordered){String full=cls.getFullName();if(classes.containsKey(full)){duplicateClasses++;continue;}classes.put(full,new IndexedClass(full,cls.getName(),unit));}
                jadxErrors+=jadx.getErrorsCount();jadxWarnings+=jadx.getWarnsCount();
            }catch(Throwable t){loadFailures.add(unit.label()+": "+t.getClass().getSimpleName()+": "+safeMessage(t));AnalysisJournal.exception(app,t instanceof OutOfMemoryError?"DECOMPILER_INDEX_OOM":"DECOMPILER_INDEX_FAILURE",t);}
            finally{if(jadx!=null)try{jadx.close();}catch(Throwable ignored){}System.gc();}
        }
        open=true;
        AnalysisJournal.append(app,"DECOMPILER_INDEX_READY","Low-memory DEX index ready",new JSONObject().put("apkCount",inputs.size()).put("dexCount",dexUnits.size()).put("classCount",classes.size()).put("resourceCount",resources.size()).put("failures",loadFailures.size()).put("duplicates",duplicateClasses).put("memory",AnalysisJournal.memory()));
    }

    synchronized boolean isOpen(){return open;}
    synchronized int classCount(){return classes.size();}
    synchronized int resourceCount(){return resources.size();}
    synchronized int errorCount(){return jadxErrors+loadFailures.size();}
    synchronized int warnCount(){return jadxWarnings+duplicateClasses;}
    synchronized List<File> inputFiles(){return new ArrayList<>(inputs);}

    synchronized List<ClassEntry> classes(String query,int limit){ensureOpen();String q=query==null?"":query.trim().toLowerCase(Locale.ROOT);ArrayList<ClassEntry> out=new ArrayList<>();for(IndexedClass cls:classes.values()){if(!q.isEmpty()&&!cls.fullName.toLowerCase(Locale.ROOT).contains(q))continue;out.add(new ClassEntry(cls.fullName,cls.shortName));if(out.size()>=limit)break;}return out;}

    String javaCode(String fullName)throws Exception{return decodeClass(fullName,false);}
    String smaliCode(String fullName)throws Exception{return decodeClass(fullName,true);}
    private String decodeClass(String fullName,boolean smali)throws Exception{
        IndexedClass indexed; synchronized(this){ensureOpen();indexed=classes.get(fullName);}if(indexed==null)throw new FileNotFoundException(fullName);
        JadxDecompiler jadx=null;try{jadx=createJadx(indexed.unit.dex,new File(tempDir,"decode-"+indexed.unit.id));jadx.load();JavaClass cls=findClass(jadx,fullName);if(cls==null)throw new FileNotFoundException(fullName+" in "+indexed.unit.label());String code=smali?cls.getSmali():cls.getCode();return "// Source: "+indexed.unit.label()+"\n"+code;}
        catch(OutOfMemoryError oom){AnalysisJournal.exception(app,"DECOMPILER_DECODE_OOM",oom);throw new Exception("Недостаточно Java heap для одного DEX: "+indexed.unit.label(),oom);}
        catch(Exception e){throw e;}catch(Throwable t){throw new Exception((smali?"Smali":"JADX Java")+" decode failed for "+fullName+": "+safeMessage(t),t);}finally{if(jadx!=null)try{jadx.close();}catch(Throwable ignored){}System.gc();}
    }

    String xrefs(String fullName)throws Exception{
        IndexedClass indexed; synchronized(this){ensureOpen();indexed=classes.get(fullName);}if(indexed==null)throw new FileNotFoundException(fullName);
        JadxDecompiler jadx=null;try{jadx=createJadx(indexed.unit.dex,new File(tempDir,"xref-"+indexed.unit.id));jadx.load();JavaClass cls=findClass(jadx,fullName);if(cls==null)throw new FileNotFoundException(fullName);List<JavaNode> useIn=cls.getUseIn();StringBuilder sb=new StringBuilder("Uses of ").append(fullName).append(" · same DEX ").append(indexed.unit.label()).append(" · ").append(useIn.size()).append('\n');int count=0;for(JavaNode node:useIn){sb.append("• ").append(node.getFullName()).append('\n');if(++count>=MAX_XREFS){sb.append("… truncated at ").append(MAX_XREFS).append('\n');break;}}if(useIn.isEmpty())sb.append("No incoming references reported inside this DEX. Cross-DEX relationship evidence is available from RE/Evidence Graph.\n");return sb.toString();}
        catch(OutOfMemoryError oom){AnalysisJournal.exception(app,"DECOMPILER_XREF_OOM",oom);throw new Exception("Недостаточно heap для xref DEX: "+indexed.unit.label(),oom);}finally{if(jadx!=null)try{jadx.close();}catch(Throwable ignored){}System.gc();}
    }

    List<SearchHit> searchCode(String query,AtomicBoolean cancel)throws Exception{
        String q=query==null?"":query.trim().toLowerCase(Locale.ROOT);if(q.length()<2)throw new IllegalArgumentException("Введите минимум 2 символа.");
        ArrayList<DexUnit> units; synchronized(this){ensureOpen();units=new ArrayList<>(dexUnits);}ArrayList<SearchHit> hits=new ArrayList<>();
        for(DexUnit unit:units){check(cancel);JadxDecompiler jadx=null;try{jadx=createJadx(unit.dex,new File(tempDir,"search-"+unit.id));jadx.load();for(JavaClass cls:jadx.getClasses()){check(cancel);String code;try{code=cls.getCode();}catch(Throwable ignored){continue;}String[] lines=code.split("\\R",-1);for(int i=0;i<lines.length;i++){check(cancel);if(lines[i].toLowerCase(Locale.ROOT).contains(q)){String p=lines[i].trim();if(p.length()>180)p=p.substring(0,180)+"…";hits.add(new SearchHit(cls.getFullName(),i+1,"["+unit.label()+"] "+p));if(hits.size()>=MAX_SEARCH_HITS)return hits;}}try{cls.unload();}catch(Throwable ignored){}}}
            catch(OutOfMemoryError oom){AnalysisJournal.exception(app,"DECOMPILER_SEARCH_OOM",oom);}
            catch(InterruptedIOException cancelled){throw cancelled;}
            catch(Throwable failure){AnalysisJournal.exception(app,"DECOMPILER_SEARCH_PARTIAL",failure);}
            finally{if(jadx!=null)try{jadx.close();}catch(Throwable ignored){}System.gc();}
        }
        return hits;
    }

    synchronized List<String> resources(String query,int limit){ensureOpen();String q=query==null?"":query.trim().toLowerCase(Locale.ROOT);ArrayList<String> out=new ArrayList<>();for(String key:resources.keySet()){if(!q.isEmpty()&&!key.toLowerCase(Locale.ROOT).contains(q))continue;out.add(key);if(out.size()>=limit)break;}return out;}

    String resourcePreview(String key)throws Exception{
        ResourceRef ref; synchronized(this){ensureOpen();ref=resources.get(key);}if(ref==null)throw new FileNotFoundException(key);
        try(ZipFile zip=new ZipFile(ref.apk)){ZipEntry e=zip.getEntry(ref.entry);if(e==null)throw new FileNotFoundException(key);long declared=e.getSize();if(declared>MAX_RESOURCE_PREVIEW)return "Binary/large resource: "+key+" · "+declared+" bytes. Open it in File Workspace for format-aware inspection.";byte[] data;try(InputStream in=zip.getInputStream(e)){data=readLimited(in,MAX_RESOURCE_PREVIEW+1);}if(data.length>MAX_RESOURCE_PREVIEW)return "Resource preview capped at "+MAX_RESOURCE_PREVIEW+" bytes: "+key;if(looksText(data))return new String(data,StandardCharsets.UTF_8);return "Binary resource: "+key+" · "+data.length+" bytes. Open in File Workspace for HEX/format-aware view.";}
    }

    File exportAllZip(AtomicBoolean cancel)throws Exception{
        synchronized(this){ensureOpen();}
        deleteTree(exportDir);mkdir(exportDir);File zipFile=app.file("modkit-decompiled.zip"),tmp=app.file("modkit-decompiled.zip.tmp");Files.deleteIfExists(tmp.toPath());
        JSONArray unitRows=new JSONArray();int failed=0;
        for(DexUnit unit:new ArrayList<>(dexUnits)){check(cancel);JadxDecompiler jadx=null;File out=new File(exportDir,String.format(Locale.ROOT,"dex-%04d-%s",unit.id,safe(unit.apkName)));mkdir(out);try{jadx=createJadx(unit.dex,out);jadx.getArgs().setOutDir(out);jadx.load();jadx.save();unitRows.put(new JSONObject().put("source",unit.label()).put("status","SUCCESS").put("classes",jadx.getClasses().size()).put("errors",jadx.getErrorsCount()).put("warnings",jadx.getWarnsCount()));}
            catch(InterruptedIOException cancelled){throw cancelled;}
            catch(Throwable t){failed++;unitRows.put(new JSONObject().put("source",unit.label()).put("status","FAILED").put("errorClass",t.getClass().getName()).put("error",safeMessage(t)));AnalysisJournal.exception(app,t instanceof OutOfMemoryError?"DECOMPILER_EXPORT_OOM":"DECOMPILER_EXPORT_PARTIAL",t);}
            finally{if(jadx!=null)try{jadx.close();}catch(Throwable ignored){}System.gc();}
        }
        try(ZipOutputStream z=new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)))){
            zipTree(exportDir,exportDir,z,cancel);
            streamRawResources(z,cancel);
            JSONObject manifest=new JSONObject().put("schema","modkit-decompiler-export-2.0").put("backend",BACKEND).put("apkInputs",new JSONArray(inputNames())).put("dexUnits",dexUnits.size()).put("classes",classes.size()).put("resources",resources.size()).put("indexFailures",new JSONArray(loadFailures)).put("exportFailures",failed).put("units",unitRows);
            ZipEntry e=new ZipEntry("modkit-decompiler.json");e.setTime(0L);z.putNextEntry(e);z.write(manifest.toString(2).getBytes(StandardCharsets.UTF_8));z.closeEntry();
        }catch(Exception e){Files.deleteIfExists(tmp.toPath());throw e;}catch(Error e){try{Files.deleteIfExists(tmp.toPath());}catch(Exception ignored){}throw e;}
        Files.move(tmp.toPath(),zipFile.toPath(),StandardCopyOption.REPLACE_EXISTING);return zipFile;
    }

    private void streamRawResources(ZipOutputStream z,AtomicBoolean cancel)throws Exception{
        byte[] buffer=new byte[BUFFER];for(File apk:new ArrayList<>(inputs)){check(cancel);try(ZipFile input=new ZipFile(apk)){ArrayList<? extends ZipEntry> entries=Collections.list(input.entries());entries.sort(Comparator.comparing(ZipEntry::getName,String.CASE_INSENSITIVE_ORDER));for(ZipEntry entry:entries){check(cancel);if(entry.isDirectory())continue;String low=entry.getName().toLowerCase(Locale.ROOT);if(low.matches("(?:^|.*/)classes\\d*\\.dex")||low.startsWith("meta-inf/"))continue;ZipEntry out=new ZipEntry("raw-resources/"+safe(apk.getName())+"/"+entry.getName());out.setTime(0L);z.putNextEntry(out);try(InputStream in=input.getInputStream(entry)){int n;while((n=in.read(buffer))!=-1){check(cancel);z.write(buffer,0,n);}}z.closeEntry();}}}
    }

    private JadxDecompiler createJadx(File input,File work)throws Exception{
        mkdir(work);File config=new File(work,"config"),cache=new File(work,"cache"),tmp=new File(work,"tmp");mkdir(config);mkdir(cache);mkdir(tmp);
        JadxArgs args=new JadxArgs();args.setInputFiles(Collections.singletonList(input));args.setThreadsCount(1);args.setCodeCache(NoOpCodeCache.INSTANCE);args.setCodeWriterProvider(SimpleCodeWriter::new);Set<JadxSecurityFlag> flags=JadxSecurityFlag.all();flags.remove(JadxSecurityFlag.SECURE_XML_PARSER);args.setSecurity(new JadxSecurity(flags));args.setLoadJadxClsSetFile(false);args.setFilesGetter(new IJadxFilesGetter(){@Override public Path getConfigDir(){return config.toPath();}@Override public Path getCacheDir(){return cache.toPath();}@Override public Path getTempDir(){return tmp.toPath();}});return new JadxDecompiler(args);
    }
    private static JavaClass findClass(JadxDecompiler jadx,String fullName){for(JavaClass cls:jadx.getClasses())if(fullName.equals(cls.getFullName()))return cls;return null;}
    private List<String> inputNames(){ArrayList<String> out=new ArrayList<>();for(File f:inputs)out.add(f.getName());return out;}

    static List<File> resolveTargetInputs(App app)throws Exception{return TargetResolver.resolve(app).apkFiles();}

    private static void extract(ZipFile zip,ZipEntry entry,File dest)throws IOException{try(InputStream in=new BufferedInputStream(zip.getInputStream(entry));FileOutputStream out=new FileOutputStream(dest)){byte[] b=new byte[BUFFER];int n;while((n=in.read(b))!=-1)out.write(b,0,n);}}
    private static byte[] readLimited(InputStream in,int limit)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[65536];int n,total=0;while((n=in.read(b))!=-1){if(total+n>limit){out.write(b,0,Math.max(0,limit-total));break;}out.write(b,0,n);total+=n;}return out.toByteArray();}
    private static boolean looksText(byte[] b){int n=Math.min(b.length,4096),bad=0;if(n==0)return true;for(int i=0;i<n;i++){int v=b[i]&255;if(v==0)return false;if(v<9||(v>13&&v<32))bad++;}return bad<n/20+1;}
    private static void check(AtomicBoolean cancel)throws InterruptedIOException{if((cancel!=null&&cancel.get())||Thread.currentThread().isInterrupted())throw new InterruptedIOException("cancelled");}
    private void ensureOpen(){if(!open)throw new IllegalStateException("Decompiler is not loaded");}
    private static void mkdir(File f)throws IOException{if(!f.isDirectory()&&!f.mkdirs()&&!f.isDirectory())throw new IOException("Cannot create "+f);}
    private static String safe(String value){String s=value==null?"item":value.replaceAll("[^A-Za-z0-9._-]+","_");return s.isEmpty()?"item":s;}
    private static String safeMessage(Throwable t){String m=t==null?null:t.getMessage();return m==null?(t==null?"unknown":t.getClass().getSimpleName()):m;}
    private static void zipTree(File root,File node,ZipOutputStream z,AtomicBoolean cancel)throws Exception{check(cancel);File[] children=node.listFiles();if(children==null)return;Arrays.sort(children,Comparator.comparing(File::getName));byte[] buf=new byte[BUFFER];for(File f:children){check(cancel);if(f.isDirectory()){zipTree(root,f,z,cancel);continue;}String rel=root.toPath().relativize(f.toPath()).toString().replace(File.separatorChar,'/');ZipEntry e=new ZipEntry(rel);e.setTime(0L);z.putNextEntry(e);try(InputStream in=new BufferedInputStream(new FileInputStream(f))){int n;while((n=in.read(buf))!=-1){check(cancel);z.write(buf,0,n);}}z.closeEntry();}}
    private static void deleteTree(File f)throws IOException{if(f==null||!f.exists())return;if(f.isDirectory()){File[] a=f.listFiles();if(a!=null)for(File c:a)deleteTree(c);}if(!f.delete()&&f.exists())throw new IOException("Cannot delete "+f);}

    @Override public synchronized void close(){classes.clear();resources.clear();dexUnits.clear();inputs.clear();loadFailures.clear();open=false;jadxErrors=jadxWarnings=duplicateClasses=0;}
}
