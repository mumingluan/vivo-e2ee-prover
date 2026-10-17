package com.axuan.vivoe2eeprover;

import java.io.*;
import java.util.*;

/** Match semantics and call graphs; ambiguous plans are rejected before any hook. */
final class RiskResolver {
    interface Match { boolean accepts(DexIndex.MethodData method) throws IOException; }
    static final class Plan {
        final DexIndex.Ref debug, developer, adb, socket, credit, init, localTask, syncTask;
        Plan(DexIndex.Ref a, DexIndex.Ref b, DexIndex.Ref c, DexIndex.Ref d, DexIndex.Ref e,
                DexIndex.Ref init, DexIndex.Ref localTask, DexIndex.Ref syncTask) {
            debug=a; developer=b; adb=c; socket=d; credit=e; this.init=init; this.localTask=localTask; this.syncTask=syncTask;
        }
        String describe() { return "debug="+debug+"\ndeveloper="+developer+"\nadb="+adb+"\nsocket="+socket+"\ncredit="+credit+"\ninit="+init+"\nlocalTask="+localTask+"\nsyncTask="+syncTask; }
    }
    static Plan vms(DexIndex index) throws IOException {
        DexIndex.MethodData debug=unique(index,"debug dispatcher",m -> m.isStatic()
                && m.ref.type.equals("(Ljava/lang/String;)Ljava/lang/Object;")
                && m.facts().strings.contains("debuging") && m.facts().strings.contains("usbConnected")
                && m.facts().text("Unknown type"));
        DexIndex.MethodData developer=unique(index,"development setting",m -> m.isStatic()
                && m.ref.owner.equals(debug.ref.owner) && m.ref.type.equals("(Landroid/content/Context;)Z")
                && m.facts().strings.contains("development_settings_enabled")
                && calls(m,"Landroid/provider/Settings$Secure;","getInt"));
        DexIndex.MethodData adb=unique(index,"ADB root collector",m -> m.isStatic()
                && m.ref.owner.equals(debug.ref.owner) && m.ref.type.equals("()I")
                && m.facts().text("isAdbRoot error") && m.facts().text("isadbRoot:")
                && calls(m,"Ljava/lang/String;","contains"));
        List<DexIndex.MethodData> modernSockets=new ArrayList<>();
        for(DexIndex.MethodData m:index.methods.values()) if(m.isStatic()
                && m.ref.type.equals("()Ljava/lang/Boolean;")
                && m.facts().text("detectFridaUnixSocket error")
                && calls(m,"Landroid/text/TextUtils;","isEmpty")) modernSockets.add(m);
        if(modernSockets.size()>1)throw new IOException("Ambiguous Unix socket collector");
        DexIndex.MethodData socket=modernSockets.isEmpty() ? unique(index,"legacy Frida network collector",m -> m.isStatic()
                && m.ref.type.equals("()Z") && m.facts().strings.contains("re.frida.server")
                && m.facts().text("checkByNetstat:") && calls(m,"Ljava/lang/String;","contains")) : modernSockets.get(0);
        DexIndex.MethodData credit=unique(index,"device credit API",m -> !m.isStatic()
                && m.ref.type.equals("(Ljava/lang/String;Ljava/lang/String;)I")
                && m.facts().text("getDeviceCredit return cloud risk")
                && m.facts().text("getDeviceCredit return end risk"));
        // Prove the dispatcher's debug result and the selected raw settings/root
        // functions are actually used by the collector, not unrelated helpers.
        Set<DexIndex.Ref> raw=new HashSet<>(Arrays.asList(debug.ref,developer.ref,adb.ref,socket.ref));
        Set<DexIndex.Ref> reached=new HashSet<>(),visited=new HashSet<>();
        ArrayDeque<DexIndex.Ref> work=new ArrayDeque<>();
        Set<String> collectorOwners=new HashSet<>();
        for(DexIndex.MethodData m:index.methods.values())if(m.facts().text("toCollectData"))collectorOwners.add(m.ref.owner);
        for(DexIndex.MethodData m:index.methods.values())if(collectorOwners.contains(m.ref.owner))work.add(m.ref);
        while(!work.isEmpty()) {
            DexIndex.Ref ref=work.removeFirst();if(!visited.add(ref))continue;
            if(raw.contains(ref))reached.add(ref);
            DexIndex.MethodData m=index.get(ref);
            if(m!=null)for(DexIndex.Ref call:m.facts().calls)if(index.get(call)!=null)work.addLast(call);
        }
        if(!reached.containsAll(raw)) throw new IOException("Raw risk inputs are not all reached by official collector: "+reached);
        DexIndex.MethodData init=unique(index,"credit manager initializer",m -> m.isStatic()
                && m.ref.owner.equals(credit.ref.owner) && m.ref.type.equals("()"+credit.ref.owner)
                && m.facts().calls.stream().anyMatch(r -> r.owner.equals(credit.ref.owner) && r.name.equals("<init>")));
        DexIndex.MethodData localInit=unique(index,"local task initialization",m -> !m.isStatic()
                && m.ref.type.equals("()V") && m.facts().strings.contains("DCEndCalcRiskT")
                && m.facts().calls.isEmpty() && m.facts().fields.size()==1);
        DexIndex.MethodData syncInit=unique(index,"sync task initialization",m -> !m.isStatic()
                && m.ref.type.equals("()V") && m.facts().strings.contains("DCSyncDataRiskT")
                && m.facts().calls.isEmpty() && m.facts().fields.size()==1);
        DexIndex.MethodData local=unique(index,"local task constructor",m -> m.ref.owner.equals(localInit.ref.owner)
                && m.ref.name.equals("<init>") && m.ref.type.equals("(Z)V"));
        DexIndex.MethodData sync=unique(index,"sync task constructor",m -> m.ref.owner.equals(syncInit.ref.owner)
                && m.ref.name.equals("<init>") && (m.ref.type.equals("()V") || m.ref.type.equals("(Lorg/json/JSONObject;)V")));
        return new Plan(debug.ref,developer.ref,adb.ref,socket.ref,credit.ref,init.ref,local.ref,sync.ref);
    }
    static DexIndex.Ref cloud(DexIndex index) throws IOException {
        return CloudIdentityResolver.discover(index).normalizer;
    }
    static boolean calls(DexIndex.MethodData method,String owner,String name) throws IOException {
        for(DexIndex.Ref r:method.facts().calls) if(owner.equals(r.owner)&&name.equals(r.name))return true;
        return false;
    }
    static DexIndex.MethodData unique(DexIndex index,String role,Match match) throws IOException {
        List<DexIndex.MethodData> found=new ArrayList<>();
        for(DexIndex.MethodData m:index.methods.values())if(match.accepts(m))found.add(m);
        if(found.size()!=1)throw new IOException("Missing/ambiguous "+role+": "+found.size());
        return found.get(0);
    }
}
