package com.axuan.vivoe2eeprover;
import java.lang.reflect.*;
import java.util.*;
import java.util.regex.*;

/** Host-only reference-table renaming; raw executable instructions remain real. */
final class RawCodeNames {
    private static boolean platform(String owner) {
        return owner.startsWith("Ljava/")||owner.startsWith("Landroid/")||owner.startsWith("Ljavax/")||owner.startsWith("Lorg/json/");
    }
    static DexIndex renamed(DexIndex source)throws Exception {
        Map<String,String> types=new LinkedHashMap<>();
        for(String type:source.parents.keySet())if(!platform(type))types.put(type,"Lchanged/Type"+types.size()+";");
        Set<Object> readers=Collections.newSetFromMap(new IdentityHashMap<Object,Boolean>());
        for(DexIndex.MethodData method:source.methods.values())readers.add(reader(method));
        Map<DexIndex.Ref,String> names=new LinkedHashMap<>();
        for(Object reader:readers)for(String table:new String[]{"methodIds","fieldIds"}) {
            for(DexIndex.Ref ref:(DexIndex.Ref[])field(reader,table))
                if(types.containsKey(ref.owner)&&!ref.name.startsWith("<"))names.putIfAbsent(ref,"member"+names.size());
        }
        DexIndex result=new DexIndex();
        for(Map.Entry<String,String> entry:source.parents.entrySet())result.parents.put(types.getOrDefault(entry.getKey(),entry.getKey()),types.getOrDefault(entry.getValue(),entry.getValue()));
        for(DexIndex.MethodData method:source.methods.values()) {
            DexIndex.Ref ref=ref(method.ref,types,names);result.methods.put(ref.key(),method.withRef(ref));
        }
        for(Object reader:readers) {
            for(String table:new String[]{"methodIds","fieldIds"}) {
                DexIndex.Ref[] refs=(DexIndex.Ref[])field(reader,table);
                for(int i=0;i<refs.length;i++)refs[i]=ref(refs[i],types,names);
            }
            String[] refs=(String[])field(reader,"types");for(int i=0;i<refs.length;i++)refs[i]=descriptor(refs[i],types);
        }
        return result;
    }
    static Object reader(DexIndex.MethodData method)throws Exception { return field(method,"reader"); }
    static Object field(Object receiver,String name)throws Exception {
        Field field=receiver.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(receiver);
    }
    static void clear(DexIndex index)throws Exception {
        Field field=DexIndex.MethodData.class.getDeclaredField("facts");field.setAccessible(true);
        for(DexIndex.MethodData method:index.methods.values())field.set(method,null);
    }
    private static DexIndex.Ref ref(DexIndex.Ref ref,Map<String,String> types,Map<DexIndex.Ref,String> names) {
        return new DexIndex.Ref(types.getOrDefault(ref.owner,ref.owner),names.getOrDefault(ref,ref.name),descriptor(ref.type,types));
    }
    private static String descriptor(String value,Map<String,String> types) {
        Matcher matcher=Pattern.compile("L[^;]+;").matcher(value);StringBuffer result=new StringBuffer();
        while(matcher.find())matcher.appendReplacement(result,Matcher.quoteReplacement(types.getOrDefault(matcher.group(),matcher.group())));
        matcher.appendTail(result);return result.toString();
    }
}
