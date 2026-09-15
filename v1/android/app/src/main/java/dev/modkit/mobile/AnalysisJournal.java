package dev.modkit.mobile;

import android.content.Context;

import org.json.JSONObject;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * Bounded, append-only diagnostics journal for the current ModKit process/session.
 * It intentionally records ModKit events only; it does not collect unrelated device activity.
 */
final class AnalysisJournal {
    static final String FILE_NAME="session-diagnostics.jsonl";
    private static final String PREVIOUS_NAME="session-diagnostics.previous.jsonl";
    private static final long MAX_BYTES=4L*1024L*1024L;
    private static final int MAX_STACK_CHARS=16000;
    private static final Object LOCK=new Object();

    private AnalysisJournal(){}

    static JSONObject data(String key,Object value){JSONObject row=new JSONObject();try{row.put(key,value);}catch(Exception ignored){}return row;}

    static void startSession(Context context){
        synchronized(LOCK){
            try{
                File current=new File(context.getFilesDir(),FILE_NAME);
                File previous=new File(context.getFilesDir(),PREVIOUS_NAME);
                if(current.isFile()&&current.length()>0){
                    Files.deleteIfExists(previous.toPath());
                    Files.move(current.toPath(),previous.toPath(),StandardCopyOption.REPLACE_EXISTING);
                }
            }catch(Exception ignored){}
        }
        JSONObject data=new JSONObject();
        try{data.put("pid",android.os.Process.myPid());data.put("memory",memory());}catch(Exception ignored){}
        append(context,"SESSION_START","ModKit process started",data);
    }

    static void append(Context context,String type,String message){append(context,type,message,null);}

    static void append(Context context,String type,String message,JSONObject data){
        if(context==null)return;
        synchronized(LOCK){
            try{
                File file=new File(context.getFilesDir(),FILE_NAME);
                if(file.isFile()&&file.length()>MAX_BYTES)rotateOversize(context,file);
                JSONObject row=new JSONObject()
                        .put("schema","modkit-session-event-1.0")
                        .put("timeMs",System.currentTimeMillis())
                        .put("type",type==null?"EVENT":type)
                        .put("message",message==null?"":message)
                        .put("thread",Thread.currentThread().getName());
                if(data!=null)row.put("data",data);
                try(BufferedWriter out=new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file,true),StandardCharsets.UTF_8))){
                    out.write(row.toString());out.newLine();
                }
            }catch(Throwable ignored){}
        }
    }

    static void exception(Context context,String type,Throwable error){
        JSONObject data=new JSONObject();
        try{
            data.put("exceptionClass",error==null?"null":error.getClass().getName());
            data.put("exceptionMessage",error==null?"":String.valueOf(error.getMessage()));
            data.put("memory",memory());
            if(error!=null){
                StringWriter sw=new StringWriter();error.printStackTrace(new PrintWriter(sw));String stack=sw.toString();
                if(stack.length()>MAX_STACK_CHARS)stack=stack.substring(0,MAX_STACK_CHARS)+"\n… truncated …";
                data.put("stack",stack);
            }
        }catch(Throwable ignored){}
        append(context,type,error==null?"unknown exception":String.valueOf(error),data);
    }

    static JSONObject memory(){
        Runtime runtime=Runtime.getRuntime();long max=runtime.maxMemory(),total=runtime.totalMemory(),free=runtime.freeMemory();
        JSONObject row=new JSONObject();
        try{row.put("maxBytes",max).put("allocatedBytes",total).put("freeAllocatedBytes",free).put("usedBytes",Math.max(0L,total-free)).put("headroomBytes",Math.max(0L,max-(total-free)));}catch(Exception ignored){}
        return row;
    }

    private static void rotateOversize(Context context,File current){
        try{
            File previous=new File(context.getFilesDir(),PREVIOUS_NAME);
            Files.deleteIfExists(previous.toPath());
            Files.move(current.toPath(),previous.toPath(),StandardCopyOption.REPLACE_EXISTING);
        }catch(Exception ignored){}
    }
}
