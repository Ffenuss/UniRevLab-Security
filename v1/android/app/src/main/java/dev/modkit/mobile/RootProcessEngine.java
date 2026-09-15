package dev.modkit.mobile;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Read-only rooted runtime backend.
 * "Attach" opens a validated procfs observation session; it never writes target memory,
 * injects code, changes registers, sends signals, or starts external instrumentation.
 */
final class RootProcessEngine {
    private RootProcessEngine() {}
    private static boolean blank(String value){return value==null||value.trim().isEmpty();}

    static final class ProcessInfo {
        final int pid; final int uid; final String name; final String cmdline;
        ProcessInfo(int pid,int uid,String name,String cmdline){this.pid=pid;this.uid=uid;this.name=name;this.cmdline=cmdline;}
        String label(){String shown=blank(cmdline)?name:cmdline;if(shown.length()>70)shown=shown.substring(0,70)+"…";return shown+"  · PID "+pid+" · uid "+uid;}
        JSONObject toJson(){
            JSONObject out=new JSONObject();
            try{
                out.put("pid",pid);
                out.put("uid",uid);
                out.put("name",name);
                out.put("cmdline",cmdline);
            }catch(JSONException ignored){
                // Runtime inventory must remain usable even if JSON serialization is partial.
            }
            return out;
        }
    }

    static final class MemoryMap {
        final long start,end,fileOffset;final String perms,path;
        MemoryMap(long start,long end,long fileOffset,String perms,String path){this.start=start;this.end=end;this.fileOffset=fileOffset;this.perms=perms;this.path=path;}
        boolean executable(){return perms!=null&&perms.indexOf('x')>=0;}
        JSONObject toJson(){
            JSONObject out=new JSONObject();
            try{
                out.put("startHex",hex(start));out.put("endHex",hex(end));out.put("offsetHex",hex(fileOffset));
                out.put("perms",perms);out.put("path",path);out.put("executable",executable());
            }catch(JSONException ignored){}
            return out;
        }
    }

    static final class ModuleImage {
        final String path;final long loadBase,start,end;final int mappingCount,executableMappings;
        ModuleImage(String path,long loadBase,long start,long end,int mappingCount,int executableMappings){this.path=path;this.loadBase=loadBase;this.start=start;this.end=end;this.mappingCount=mappingCount;this.executableMappings=executableMappings;}
        String basename(){int slash=path.lastIndexOf('/');return slash>=0?path.substring(slash+1):path;}
        JSONObject toJson(){
            JSONObject out=new JSONObject();
            try{
                out.put("path",path);out.put("basename",basename());out.put("loadBaseHex",hex(loadBase));
                out.put("startHex",hex(start));out.put("endHex",hex(end));out.put("mappingCount",mappingCount);
                out.put("executableMappings",executableMappings);
            }catch(JSONException ignored){}
            return out;
        }
    }

    private static final class ModuleAccumulator {
        final String path;long loadBase=Long.MAX_VALUE,start=Long.MAX_VALUE,end=Long.MIN_VALUE;int mappingCount,executableMappings;
        ModuleAccumulator(String path){this.path=path;}
        void add(MemoryMap map){
            long candidate=map.fileOffset<=map.start?map.start-map.fileOffset:map.start;
            if(candidate<loadBase)loadBase=candidate;if(map.start<start)start=map.start;if(map.end>end)end=map.end;
            mappingCount++;if(map.executable())executableMappings++;
        }
        ModuleImage finish(){return new ModuleImage(path,loadBase==Long.MAX_VALUE?start:loadBase,start,end,mappingCount,executableMappings);}
    }

    static final class RuntimeSession {
        final ProcessInfo process; final long createdAtMs; final String status;
        final List<String> modules; final List<Integer> threads; final boolean mapsTruncated;
        final List<MemoryMap> mappings; final List<ModuleImage> moduleImages;
        RuntimeSession(ProcessInfo process,long createdAtMs,String status,List<String> modules,List<Integer>threads,boolean mapsTruncated,List<MemoryMap> mappings,List<ModuleImage> moduleImages){
            this.process=process;this.createdAtMs=createdAtMs;this.status=status;this.modules=modules;this.threads=threads;this.mapsTruncated=mapsTruncated;this.mappings=mappings;this.moduleImages=moduleImages;
        }
        JSONObject toJson(RootAccess.ProbeResult root){
            JSONObject out=new JSONObject();
            try{
                JSONArray mappingRows=new JSONArray();for(MemoryMap row:mappings)mappingRows.put(row.toJson());
                JSONArray moduleRows=new JSONArray();for(ModuleImage row:moduleImages)moduleRows.put(row.toJson());
                out.put("schema","modkit-runtime-session-1.1");
                out.put("backend","runtime.root-procfs");
                out.put("mode","READ_ONLY_OBSERVATION");
                out.put("createdAtMs",createdAtMs);
                out.put("process",process.toJson());
                out.put("root",root==null?JSONObject.NULL:root.toJson());
                out.put("status",status);
                out.put("moduleCount",modules.size());
                out.put("modules",new JSONArray(modules));
                out.put("moduleImageCount",moduleImages.size());
                out.put("moduleImages",moduleRows);
                out.put("mappingCount",mappings.size());
                out.put("mappings",mappingRows);
                out.put("threadCount",threads.size());
                out.put("threads",new JSONArray(threads));
                out.put("mapsTruncated",mapsTruncated);
                out.put("writesTargetMemory",false);
                out.put("readsTargetMemoryBytes",false);
                out.put("injectsCode",false);
            }catch(JSONException ignored){
                // A serialization problem must not invalidate an otherwise valid read-only session.
            }
            return out;
        }
    }

    static List<ProcessInfo> listProcesses() throws Exception {
        String command="for p in /proc/[0-9]*; do pid=${p#/proc/}; [ -r \"$p/status\" ] || continue; uid=$(awk '/^Uid:/{print $2;exit}' \"$p/status\" 2>/dev/null); name=$(cat \"$p/comm\" 2>/dev/null | tr '\\t\\r\\n' '   '); cmd=$(cat \"$p/cmdline\" 2>/dev/null | tr '\\000\\t\\r\\n' '    '); printf '%s\\t%s\\t%s\\t%s\\n' \"$pid\" \"$uid\" \"$name\" \"$cmd\"; done";
        RootAccess.ExecResult result=RootAccess.runSu(command,12_000,2*1024*1024);
        if(result.timedOut)throw new java.io.IOException("Process inventory timed out");
        if(result.exitCode!=0)throw new java.io.IOException("Root process inventory failed: "+RootAccess.sanitizeLine(result.output));
        ArrayList<ProcessInfo> out=new ArrayList<>();
        for(String line:result.output.split("\\R")){String[] parts=line.split("\\t",4);if(parts.length<3)continue;int pid=parseInt(parts[0],-1),uid=parseInt(parts[1],-1);if(pid<=1||uid<0)continue;String name=clean(parts[2]),cmd=parts.length>=4?clean(parts[3]):"";if(blank(name)&&blank(cmd))continue;out.add(new ProcessInfo(pid,uid,name,cmd));}
        out.sort((a,b)->{boolean aa=a.uid>=10_000,bb=b.uid>=10_000;if(aa!=bb)return aa?-1:1;String al=(blank(a.cmdline)?a.name:a.cmdline).toLowerCase(Locale.ROOT),bl=(blank(b.cmdline)?b.name:b.cmdline).toLowerCase(Locale.ROOT);int by=al.compareTo(bl);return by!=0?by:Integer.compare(a.pid,b.pid);});
        return out;
    }

    static RuntimeSession attachReadOnly(ProcessInfo requested) throws Exception {
        if(requested==null||requested.pid<=1)throw new IllegalArgumentException("Invalid PID");int pid=requested.pid;String prefix="/proc/"+pid;
        RootAccess.ExecResult alive=RootAccess.runSu("test -d "+prefix,3_000,8*1024);if(alive.exitCode!=0||alive.timedOut)throw new java.io.IOException("Процесс уже завершён или недоступен.");
        RootAccess.ExecResult statusResult=RootAccess.runSu("cat "+prefix+"/status",5_000,128*1024);if(statusResult.exitCode!=0)throw new java.io.IOException("Не удалось открыть /proc/"+pid+"/status");
        int actualPid=parseStatusInt(statusResult.output,"Pid:"),actualUid=parseStatusInt(statusResult.output,"Uid:");if(actualPid!=pid)throw new java.io.IOException("PID изменился во время подключения.");if(requested.uid>=0&&actualUid>=0&&actualUid!=requested.uid)throw new java.io.IOException("UID процесса изменился во время подключения.");
        RootAccess.ExecResult mapsResult=RootAccess.runSu("cat "+prefix+"/maps",8_000,4*1024*1024);if(mapsResult.exitCode!=0)throw new java.io.IOException("Не удалось прочитать memory map процесса.");
        RootAccess.ExecResult threadsResult=RootAccess.runSu("ls -1 "+prefix+"/task 2>/dev/null",5_000,256*1024);

        Set<String> modules=new LinkedHashSet<>();List<MemoryMap> mappings=new ArrayList<>();Map<String,ModuleAccumulator> grouped=new LinkedHashMap<>();
        for(String line:mapsResult.output.split("\\R")){
            MemoryMap map=parseMapLine(line);if(map==null||blank(map.path)||!map.path.startsWith("/"))continue;
            mappings.add(map);modules.add(map.path);ModuleAccumulator acc=grouped.get(map.path);if(acc==null){acc=new ModuleAccumulator(map.path);grouped.put(map.path,acc);}acc.add(map);
        }
        List<ModuleImage> moduleImages=new ArrayList<>();for(ModuleAccumulator acc:grouped.values())moduleImages.add(acc.finish());
        moduleImages.sort((a,b)->{int by=Long.compare(a.loadBase,b.loadBase);return by!=0?by:a.path.compareTo(b.path);});

        ArrayList<Integer> threads=new ArrayList<>();if(threadsResult.exitCode==0){for(String line:threadsResult.output.split("\\R")){int tid=parseInt(line.trim(),-1);if(tid>0)threads.add(tid);}Collections.sort(threads);}
        String canonicalName=statusValue(statusResult.output,"Name:");ProcessInfo actual=new ProcessInfo(pid,actualUid,blank(canonicalName)?requested.name:canonicalName,requested.cmdline);
        return new RuntimeSession(actual,System.currentTimeMillis(),statusResult.output,new ArrayList<>(modules),threads,mapsResult.truncated,mappings,moduleImages);
    }

    private static MemoryMap parseMapLine(String line){
        if(line==null)return null;String text=line.trim();if(text.isEmpty())return null;String[] parts=text.split("\\s+",6);if(parts.length<5)return null;
        String[] range=parts[0].split("-",2);if(range.length!=2)return null;long start=parseHex(range[0],-1),end=parseHex(range[1],-1),fileOffset=parseHex(parts[2],-1);if(start<0||end<=start||fileOffset<0)return null;
        String path=parts.length>=6?parts[5].trim():"";if(path.endsWith(" (deleted)"))path=path.substring(0,path.length()-10).trim();return new MemoryMap(start,end,fileOffset,parts[1],path);
    }
    private static long parseHex(String value,long fallback){try{return Long.parseUnsignedLong(value.trim(),16);}catch(Exception ignored){return fallback;}}
    private static String hex(long value){return String.format(Locale.ROOT,"0x%x",value);}
    private static String clean(String value){return value==null?"":value.replace('\u0000',' ').replace('\r',' ').replace('\n',' ').trim();}
    private static int parseInt(String value,int fallback){try{return Integer.parseInt(value.trim());}catch(Exception ignored){return fallback;}}
    private static int parseStatusInt(String status,String key){String value=statusValue(status,key);if(blank(value))return-1;return parseInt(value.split("\\s+",2)[0],-1);}
    private static String statusValue(String status,String key){if(status==null)return"";for(String line:status.split("\\R"))if(line.startsWith(key))return line.substring(key.length()).trim();return"";}
}
