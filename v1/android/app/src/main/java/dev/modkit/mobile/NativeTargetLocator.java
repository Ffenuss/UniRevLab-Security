package dev.modkit.mobile;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Enumerates and extracts native libraries from the canonical APK/APK-set target. */
final class NativeTargetLocator {
    static final class Entry {
        final TargetResolver.Member member;final String zipEntry,abi;final long size;
        Entry(TargetResolver.Member member,String zipEntry,String abi,long size){this.member=member;this.zipEntry=zipEntry;this.abi=abi;this.size=size;}
        String label(){return member.name+" · "+abi+" · "+zipEntry+" · "+String.format(Locale.ROOT,"%.1f MB",size/1048576.0);}
    }
    interface Progress { void progress(String text); }
    private NativeTargetLocator(){}

    static List<Entry> list(TargetResolver.Target target,AtomicBoolean cancelled)throws Exception{
        ArrayList<Entry> out=new ArrayList<>();
        for(TargetResolver.Member member:target.members){
            check(cancelled);
            try(ZipFile zip=new ZipFile(member.file)){
                java.util.Enumeration<? extends ZipEntry> it=zip.entries();
                while(it.hasMoreElements()){
                    check(cancelled);ZipEntry entry=it.nextElement();if(entry.isDirectory())continue;String name=entry.getName();String low=name.toLowerCase(Locale.ROOT);if(!low.endsWith(".so"))continue;
                    String abi=abi(name);if(abi==null)abi="unknown";out.add(new Entry(member,name,abi,Math.max(0L,entry.getSize())));
                }
            }
        }
        out.sort(Comparator.comparing((Entry e)->e.abi).thenComparing(e->e.member.index).thenComparing(e->e.zipEntry,String.CASE_INSENSITIVE_ORDER));
        return out;
    }

    static String extract(Entry entry,File destination,AtomicBoolean cancelled,Progress progress)throws Exception{
        File tmp=new File(destination.getParentFile(),destination.getName()+".tmp");Files.deleteIfExists(tmp.toPath());MessageDigest digest=MessageDigest.getInstance("SHA-256");long total=0L;
        try(ZipFile zip=new ZipFile(entry.member.file)){
            ZipEntry source=zip.getEntry(entry.zipEntry);if(source==null||source.isDirectory())throw new java.io.FileNotFoundException(entry.zipEntry);
            try(InputStream in=new BufferedInputStream(zip.getInputStream(source));FileOutputStream out=new FileOutputStream(tmp)){
                byte[] buffer=new byte[1024*1024];int n;while((n=in.read(buffer))!=-1){check(cancelled);out.write(buffer,0,n);digest.update(buffer,0,n);total+=n;if(progress!=null&&total%(8L*1024L*1024L)<buffer.length)progress.progress("Native target import: "+entry.member.name+"!"+entry.zipEntry+" · "+(total/1048576L)+" MB");}
            }
        }catch(Throwable e){try{Files.deleteIfExists(tmp.toPath());}catch(Exception ignored){}throw e;}
        if(total<20L){Files.deleteIfExists(tmp.toPath());throw new java.io.IOException("Native entry слишком мал или повреждён");}
        try(InputStream in=new BufferedInputStream(new java.io.FileInputStream(tmp))){byte[] h=new byte[4];if(in.read(h)!=4||h[0]!=0x7f||h[1]!='E'||h[2]!='L'||h[3]!='F'){Files.deleteIfExists(tmp.toPath());throw new java.io.IOException("Выбранный entry не является ELF");}}
        Files.move(tmp.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING);
        StringBuilder out=new StringBuilder();for(byte b:digest.digest())out.append(String.format(Locale.ROOT,"%02x",b));return out.toString();
    }

    static Entry resolve(TargetResolver.Target target,int splitIndex,String zipEntry,AtomicBoolean cancelled)throws Exception{
        for(Entry entry:list(target,cancelled))if(entry.member.index==splitIndex&&entry.zipEntry.equals(zipEntry))return entry;
        throw new java.io.FileNotFoundException("Native entry больше не принадлежит текущему target: split="+splitIndex+" · "+zipEntry);
    }

    private static String abi(String name){String low=name.toLowerCase(Locale.ROOT);java.util.regex.Matcher m=java.util.regex.Pattern.compile("(?:^|/)lib/([^/]+)/[^/]+\\.so$").matcher(low);return m.find()?m.group(1):null;}
    private static void check(AtomicBoolean cancelled)throws java.io.InterruptedIOException{if((cancelled!=null&&cancelled.get())||Thread.currentThread().isInterrupted())throw new java.io.InterruptedIOException("cancelled");}
}
