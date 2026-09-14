package dev.modkit.mobile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
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
        JSONObject toJson(){return new JSONObject().put("pid",pid).put("uid",uid).put("name",name).put("cmdline",cmdline);}
    }

    static final class RuntimeSession {
        final ProcessInfo process; final long createdAtMs; final String status; final List<String> modules; final List<Integer> threads; final boolean mapsTruncated;
        RuntimeSession(ProcessInfo process,long createdAtMs,String status,List<String> modules,List<Integer> threads,boolean mapsTruncated){this.process=process;this.createdAtMs=createdAtMs;this.status=status;this.modules=modules;this.threads=threads;this.mapsTruncated=mapsTruncated;}
        JSONObject toJson(RootAccess.ProbeResult root){return new JSONObject().put("schema","modkit-runtime-session-1.0").put("backend","runtime.root-procfs").put("mode","READ_ONLY_OBSERVATION").put("createdAtMs",createdAtMs).put("process",process.toJson()).put("root",root==null?JSONObject.NULL:root.toJson()).put("status",status).put("moduleCount",modules.size()).put("modules",new JSONArray(modules)).put("threadCount",threads.size()).put("threads",new JSONArray(threads)).put("mapsTruncated",mapsTruncated).put("writesTargetMemory",false).put("injectsCode",false);}
    }

    static List<ProcessInfo> listProcesses() throws Exception {
        String command="for p in /proc/[0-9]*; do pid=${p#/proc/}; [ -r \"$p/status\" ] || continue; uid=$(awk '/^Uid:/{print $2;exit}' \"$p/status\" 2>/dev/null); name=$(cat \"$p/comm\" 2>/dev/null | tr '\\t\\r\\n' '   '); cmd=$(cat \"$p/cmdline\" 2>/dev/null | tr '\\000\\t\\r\\n' '    '); printf '%s\\t%s\\t%s\\t%s\\n' \"$pid\" \"$uid\" \"$name\" \"$cmd\"; done";
        RootAccess.ExecResult result=RootAccess.runSu(command,12_000,2*1024*1024);
        if(result.timedOut)throw new java.io.IOException("Process inventory timed out");
        if(result.exitCode!=0)throw new java.io.IOException("Root process inventory failed: "+RootAccess.sanitizeLine(result.output));
        ArrayList<ProcessInfo> out=new ArrayList<>();
        for(String line:result.output.split("\\R")){String[] parts=line.split("\\t",4);if(parts.length<3)continue;int pid=parseInt(parts[0],-1),uid=parseInt(parts[1],-1);if(pid<=1||uid<0)continue;String name=clean(parts[2]),cmd=parts.length>=4?clean(parts[3]):"";if(blank(name)&&blank(cmd))continue;out.add(new ProcessInfo(pid,uid,name,cmd));}
        out.sort((a,b)->{boolean aa=a.uid>=10_000,bb=b.uid>=10_000;if(aa!=bb)return aa?-1:1;String al=(blank(a.cmdline)?a.name:a.cmdline).toLowerCase(java.util.Locale.ROOT),bl=(blank(b.cmdline)?b.name:b.cmdline).toLowerCase(java.util.Locale.ROOT);int by=al.compareTo(bl);return by!=0?by:Integer.compare(a.pid,b.pid);});
        return out;
    }

    static RuntimeSession attachReadOnly(ProcessInfo requested) throws Exception {
        if(requested==null||requested.pid<=1)throw new IllegalArgumentException("Invalid PID");int pid=requested.pid;String prefix="/proc/"+pid;
        RootAccess.ExecResult alive=RootAccess.runSu("test -d "+prefix,3_000,8*1024);if(alive.exitCode!=0||alive.timedOut)throw new java.io.IOException("Процесс уже завершён или недоступен.");
        RootAccess.ExecResult statusResult=RootAccess.runSu("cat "+prefix+"/status",5_000,128*1024);if(statusResult.exitCode!=0)throw new java.io.IOException("Не удалось открыть /proc/"+pid+"/status");
        int actualPid=parseStatusInt(statusResult.output,"Pid:"),actualUid=parseStatusInt(statusResult.output,"Uid:");if(actualPid!=pid)throw new java.io.IOException("PID изменился во время подключения.");if(requested.uid>=0&&actualUid>=0&&actualUid!=requested.uid)throw new java.io.IOException("UID процесса изменился во время подключения.");
        RootAccess.ExecResult mapsResult=RootAccess.runSu("cat "+prefix+"/maps",8_000,4*1024*1024);if(mapsResult.exitCode!=0)throw new java.io.IOException("Не удалось прочитать memory map процесса.");
        RootAccess.ExecResult threadsResult=RootAccess.runSu("ls -1 "+prefix+"/task 2>/dev/null",5_000,256*1024);
        Set<String> modules=new LinkedHashSet<>();for(String line:mapsResult.output.split("\\R")){int slash=line.indexOf('/');if(slash<0)continue;String path=line.substring(slash).trim();if(path.endsWith(" (deleted)"))path=path.substring(0,path.length()-10);if(!blank(path))modules.add(path);}
        ArrayList<Integer> threads=new ArrayList<>();if(threadsResult.exitCode==0){for(String line:threadsResult.output.split("\\R")){int tid=parseInt(line.trim(),-1);if(tid>0)threads.add(tid);}Collections.sort(threads);}
        String canonicalName=statusValue(statusResult.output,"Name:");ProcessInfo actual=new ProcessInfo(pid,actualUid,blank(canonicalName)?requested.name:canonicalName,requested.cmdline);
        return new RuntimeSession(actual,System.currentTimeMillis(),statusResult.output,new ArrayList<>(modules),threads,mapsResult.truncated);
    }

    private static String clean(String value){return value==null?"":value.replace('\u0000',' ').replace('\r',' ').replace('\n',' ').trim();}
    private static int parseInt(String value,int fallback){try{return Integer.parseInt(value.trim());}catch(Exception ignored){return fallback;}}
    private static int parseStatusInt(String status,String key){String value=statusValue(status,key);if(blank(value))return-1;return parseInt(value.split("\\s+",2)[0],-1);}
    private static String statusValue(String status,String key){if(status==null)return"";for(String line:status.split("\\R"))if(line.startsWith(key))return line.substring(key.length()).trim();return"";}
}
