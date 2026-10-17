package com.axuan.vivoe2eeprover;

import java.io.IOException;
import java.util.*;

/** Resolve the storage comparator's actual producer/normalizer/equals flow. */
final class CloudIdentityResolver {
    private static final String STRING = "Ljava/lang/String;";
    private static final String NORMALIZE = "(Ljava/lang/String;)Ljava/lang/String;";
    private static final String EQUALS = "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z";
    static final class Plan {
        final DexIndex.Ref normalizer, comparator, producer;
        final Set<DexIndex.Ref> storageSources, comparators;
        Plan(DexIndex.Ref n, DexIndex.Ref c, DexIndex.Ref p, Set<DexIndex.Ref> s) {
            this(n,c,p,s,Collections.singleton(c));
        }
        Plan(DexIndex.Ref n,DexIndex.Ref c,DexIndex.Ref p,Set<DexIndex.Ref> s,Set<DexIndex.Ref> callers) {
            normalizer=n;comparator=c;producer=p;storageSources=Collections.unmodifiableSet(new LinkedHashSet<>(s));comparators=Collections.unmodifiableSet(new LinkedHashSet<>(callers));
        }
        String describe() { return "normalizer="+normalizer+" comparators="+comparators+" producer="+producer+" storage="+storageSources; }
    }
    static Plan discover(DexIndex index) throws IOException {
        Map<DexIndex.Ref,List<DexIndex.MethodData>> comparators=new LinkedHashMap<>();
        Set<DexIndex.Ref> seenComparators=new HashSet<>();
        for(DexIndex.MethodData method:index.methods.values()) {
            if(!method.isStatic()||!method.ref.type.equals("(Ljava/lang/String;)Z")
                    ||!RiskResolver.calls(method,"Landroid/text/TextUtils;","equals"))continue;
            if(!seenComparators.add(method.ref))throw new IOException("Duplicate comparator declaration");
            for(DexIndex.Ref call:method.facts().calls) if(call.type.equals(NORMALIZE))
                comparators.computeIfAbsent(call,k->new ArrayList<>()).add(method);
        }
        List<Plan> found=new ArrayList<>();
        for(DexIndex.MethodData normalize:index.methods.values()) {
            if(!normalize.isStatic()||!normalize.ref.type.equals(NORMALIZE)
                    ||!RiskResolver.calls(normalize,"Landroid/text/TextUtils;","isEmpty")
                    ||!RiskResolver.calls(normalize,STRING,"length")
                    ||!RiskResolver.calls(normalize,STRING,"substring"))continue;
            List<DexIndex.MethodData> callers=comparators.get(normalize.ref);
            if(callers==null)continue;
            Plan corroborated=null;
            for(DexIndex.MethodData comparator:callers) {
                Plan plan=flow(index,normalize,comparator);
                if(plan==null)continue;
                if(corroborated==null)corroborated=plan;
                else {
                    if(!corroborated.producer.equals(plan.producer))throw new IOException("Conflicting storage providers for one normalizer");
                    Set<DexIndex.Ref> confirmed=new LinkedHashSet<>(corroborated.comparators);confirmed.addAll(plan.comparators);
                    Set<DexIndex.Ref> sources=new LinkedHashSet<>(corroborated.storageSources);sources.addAll(plan.storageSources);
                    corroborated=new Plan(normalize.ref,corroborated.comparator,plan.producer,sources,confirmed);
                }
            }
            if(corroborated!=null)found.add(corroborated);
        }
        if(found.size()!=1)throw new IOException("Missing/ambiguous storage identity flow: "+found.size()+" "+describe(found));
        return found.get(0);
    }
    private static String describe(List<Plan> plans) {List<String> descriptions=new ArrayList<>();for(Plan plan:plans)descriptions.add(plan.describe());return descriptions.toString();}
    private static Plan flow(DexIndex index,DexIndex.MethodData normalize,DexIndex.MethodData comparator)throws IOException {
        DexOrigins graph=new DexOrigins(comparator);
        Plan result=null;
        for(int pc:graph.states.keySet()) {
            if((graph.code[pc]&255)!=0x0f)continue;
            DexOrigins.Value returned=graph.at(pc,graph.code[pc]>>8);
            if(!kind(returned,"call"))continue;
            DexIndex.Ref equals=comparator.invokedAt(returned.index);
            if(!equals.owner.equals("Landroid/text/TextUtils;")||!equals.name.equals("equals")||!equals.type.equals(EQUALS))continue;
            int[] args=graph.arguments(returned.index);
            if(args.length!=2)continue;
            DexOrigins.Value first=graph.at(returned.index,args[0]),second=graph.at(returned.index,args[1]);
            DexOrigins.Value normalized=arg(first)?second:arg(second)?first:null;
            if(!kind(normalized,"call")||!comparator.invokedAt(normalized.index).equals(normalize.ref))continue;
            int[] normalizeArgs=graph.arguments(normalized.index);
            if(normalizeArgs.length!=1)continue;
            DexOrigins.Value raw=graph.at(normalized.index,normalizeArgs[0]);
            if(!kind(raw,"call"))continue;
            DexIndex.Ref producer=comparator.invokedAt(raw.index);
            DexIndex.MethodData body=index.get(producer);
            if(body==null||!body.isStatic()||!producer.type.equals("()Ljava/lang/String;")||graph.arguments(raw.index).length!=0)continue;
            Set<DexIndex.Ref> sources=storageSources(index,producer);
            if(sources==null)continue;
            if(result!=null)throw new IOException("Multiple returned storage comparison flows");
            result=new Plan(normalize.ref,comparator.ref,producer,sources);
        }
        return result;
    }
    private static boolean kind(DexOrigins.Value value,String kind) { return value!=null&&value.kind.equals(kind); }
    private static boolean arg(DexOrigins.Value value) { return kind(value,"arg")&&value.index==0&&value.text.equals(STRING); }
    private static Set<DexIndex.Ref> storageSources(DexIndex index,DexIndex.Ref producer)throws IOException {
        Set<DexIndex.Ref> visited=new LinkedHashSet<>(),sources=new LinkedHashSet<>();
        Set<String> paths=new LinkedHashSet<>();ArrayDeque<DexIndex.Ref> queue=new ArrayDeque<>();queue.add(producer);
        while(!queue.isEmpty()) {
            DexIndex.Ref ref=queue.removeFirst();if(!visited.add(ref))continue;
            if(visited.size()>256)throw new IOException("Unbounded storage producer graph");
            DexIndex.MethodData method=index.get(ref);
            if(method==null||!method.isStatic()||!ref.type.equals("()Ljava/lang/String;"))continue;
            DexOrigins graph=new DexOrigins(method);
            boolean pathCandidate=method.facts().strings.contains("/sys/ufs/ufsid")
                    ||method.facts().strings.contains("/sys/block/mmcblk0/device/cid");
            if(pathCandidate) {
                for(int pc:graph.states.keySet()) if(DexOrigins.invoke(graph.code[pc]&255)) {
                    DexIndex.Ref call=method.invokedAt(pc);
                    if(!call.owner.equals("Ljava/io/File;")||!call.name.equals("<init>")||!call.type.equals("(Ljava/lang/String;)V"))continue;
                    int[] args=graph.arguments(pc);if(args.length!=2)continue;
                    DexOrigins.Value value=graph.at(pc,args[1]);
                    if(!kind(value,"string"))continue;
                    if(value.text.equals("/sys/ufs/ufsid")||value.text.equals("/sys/block/mmcblk0/device/cid")) {
                        paths.add(value.text);sources.add(method.ref);
                    }
                }
            }
            for(int pc:graph.states.keySet()) {
                if(!DexOrigins.invoke(graph.code[pc]&255))continue;
                DexIndex.Ref call=method.invokedAt(pc);
                DexIndex.MethodData next=index.get(call);
                if(next!=null&&next.isStatic()&&call.type.equals("()Ljava/lang/String;"))queue.add(call);
            }
        }
        return paths.contains("/sys/ufs/ufsid")&&paths.contains("/sys/block/mmcblk0/device/cid")?sources:null;
    }
}
