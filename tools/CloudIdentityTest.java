package com.axuan.vivoe2eeprover;
import java.io.*;
import java.util.*;

/** Actual DEX mutations, including source and returned-value miswiring. */
public final class CloudIdentityTest {
    interface Check { void run()throws Exception; }
    static void expect(boolean value,String why) { if(!value)throw new AssertionError(why); }
    static void reject(DexIndex index,String why)throws Exception {
        try {CloudIdentityResolver.discover(index);}catch(IOException expected){return;}
        throw new AssertionError("Accepted "+why);
    }
    static DexIndex copy(DexIndex source) { DexIndex out=new DexIndex();out.methods.putAll(source.methods);out.parents.putAll(source.parents);return out; }
    static void units(DexIndex index,DexIndex.MethodData method,int pc,int[] replacement,Check check)throws Exception {
        byte[] bytes=(byte[])RawCodeNames.field(RawCodeNames.reader(method),"bytes");
        int at=method.code+16+pc*2;byte[] before=Arrays.copyOfRange(bytes,at,at+replacement.length*2);
        for(int i=0;i<replacement.length;i++){bytes[at+i*2]=(byte)replacement[i];bytes[at+i*2+1]=(byte)(replacement[i]>>8);}
        expect(!Arrays.equals(before,Arrays.copyOfRange(bytes,at,at+before.length)),"Mutation did not change executable code");
        RawCodeNames.clear(index);
        try {check.run();} finally {System.arraycopy(before,0,bytes,at,before.length);RawCodeNames.clear(index);}
    }
    static int invokePc(DexOrigins graph,DexIndex.Ref ref)throws Exception {
        for(int pc:graph.states.keySet())if(DexOrigins.invoke(graph.code[pc]&255)&&graph.method.invokedAt(pc).equals(ref))return pc;
        throw new AssertionError("Missing invocation "+ref);
    }
    static int[] reargument(DexOrigins graph,int pc,int slot,int register) {
        int[] result=Arrays.copyOfRange(graph.code,pc,pc+3);int op=result[0]&255;
        expect(op>=0x6e&&op<=0x72&&slot<4&&register<16,"Expected bounded 35c mutation");
        result[2]=(result[2]&~(15<<(slot*4)))|(register<<(slot*4));return result;
    }
    public static void main(String[] args)throws Exception {
        File apk=new File(args[0]);DexIndex complete=DexIndex.readApks(Collections.singletonList(apk));
        CloudIdentityResolver.Plan plan=CloudIdentityResolver.discover(complete);
        System.out.println(plan.describe());
        for(DexIndex.Ref comparator:plan.comparators)
            verify(apk,complete,new CloudIdentityResolver.Plan(plan.normalizer,comparator,plan.producer,plan.storageSources,plan.comparators));
    }
    static void verify(File apk,DexIndex complete,CloudIdentityResolver.Plan plan)throws Exception {
        DexIndex index=copy(complete);
        for(DexIndex.Ref other:plan.comparators)if(!other.equals(plan.comparator))index.methods.remove(other.key());
        expect(CloudIdentityResolver.discover(index).normalizer.equals(plan.normalizer),"Independent comparator cannot identify target");
        DexIndex renamed=RawCodeNames.renamed(DexIndex.readApks(Collections.singletonList(apk)));
        CloudIdentityResolver.Plan changed=CloudIdentityResolver.discover(renamed);
        expect(changed.normalizer.owner.startsWith("Lchanged/")&&!changed.normalizer.name.equals(plan.normalizer.name),"Raw private names did not change");
        for(DexIndex.Ref missing:Arrays.asList(plan.normalizer,plan.comparator,plan.producer)) {
            DexIndex test=copy(index);test.methods.remove(missing.key());reject(test,"missing role "+missing);
        }
        for(DexIndex.Ref missing:plan.storageSources) {DexIndex test=copy(index);test.methods.remove(missing.key());reject(test,"missing storage source");}
        DexIndex ambiguous=copy(index);ambiguous.methods.put("duplicate-normalizer",index.get(plan.normalizer));reject(ambiguous,"ambiguous normalizer");
        ambiguous=copy(index);ambiguous.methods.put("duplicate-comparator",index.get(plan.comparator));reject(ambiguous,"ambiguous comparator");
        DexIndex.MethodData normalizer=index.get(plan.normalizer);
        int[] body=normalizer.codeUnits();int changedDigits=0;
        for(int pc=0;pc<body.length;pc+=DexIndex.width(body[pc]&255)) {
            int op=body[pc]&255;if(op!=0x13)continue;
            int number=(short)body[pc+1];if(!Arrays.asList(32,30,18,20).contains(number))continue;
            final int newValue=number+8;
            units(index,normalizer,pc+1,new int[]{newValue},()->expect(CloudIdentityResolver.discover(index).normalizer.equals(plan.normalizer),"Numeric literal was treated as identity"));changedDigits++;
        }
        expect(changedDigits>=4,"Actual numeric gates were not mutated");
        DexIndex.MethodData comparator=index.get(plan.comparator);DexOrigins graph=new DexOrigins(comparator);
        int normalizePc=invokePc(graph,plan.normalizer),producerPc=invokePc(graph,plan.producer),parameter=graph.registers-1;
        units(index,comparator,normalizePc,reargument(graph,normalizePc,0,parameter),()->reject(index,"normalizer consumes caller input rather than storage producer"));
        int equalsPc=-1;
        for(int pc:graph.states.keySet())if(DexOrigins.invoke(graph.code[pc]&255)&&comparator.invokedAt(pc).name.equals("equals"))equalsPc=pc;
        expect(equalsPc>=0,"Missing equals");
        int[] equalArgs=graph.arguments(equalsPc);
        units(index,comparator,normalizePc+3,new int[]{0},()->reject(index,"equals consumes raw storage while normalized result is discarded"));
        units(index,comparator,equalsPc,reargument(graph,equalsPc,1,equalArgs[0]),()->reject(index,"equals does not compare caller input"));
        int returnPc=-1;for(int pc:graph.states.keySet())if((graph.code[pc]&255)==0x0f)returnPc=pc;
        expect(returnPc>=0,"Missing comparison return");
        int otherReturn=-1,actualReturn=graph.code[returnPc]>>8;
        for(int register=0;register<graph.registers;register++)if(register!=actualReturn&&graph.at(returnPc,register)!=null
                &&!graph.at(returnPc,register).equals(graph.at(returnPc,actualReturn))){otherReturn=register;break;}
        expect(otherReturn>=0,"No independent return register to mutate");
        units(index,comparator,returnPc,new int[]{0x0f|(otherReturn<<8)},()->reject(index,"unrelated returned value"));
        for(DexIndex.Ref source:plan.storageSources) {
            DexIndex.MethodData method=index.get(source);DexOrigins sourceGraph=new DexOrigins(method);boolean mutated=false;
            for(int pc:sourceGraph.states.keySet())if(DexOrigins.invoke(sourceGraph.code[pc]&255)) {
                DexIndex.Ref call=method.invokedAt(pc);
                if(call.owner.equals("Ljava/io/File;")&&call.name.equals("<init>")&&call.type.equals("(Ljava/lang/String;)V")) {
                    units(index,method,pc,new int[]{0,0,0},()->reject(index,"storage path is only a string, not a File constructor argument"));mutated=true;break;
                }
            }
            expect(mutated,"Storage constructor not mutated");
        }
        // Move only the normalizer owner; comparator/source owners stay intact.
        DexIndex moved=copy(index);DexIndex.Ref relocated=new DexIndex.Ref("Lchanged/SeparateNormalizer;","renamed",plan.normalizer.type);
        moved.methods.remove(plan.normalizer.key());moved.methods.put(relocated.key(),normalizer.withRef(relocated));
        Object reader=RawCodeNames.reader(comparator);DexIndex.Ref[] refs=(DexIndex.Ref[])RawCodeNames.field(reader,"methodIds");
        List<Integer> slots=new ArrayList<>();for(int i=0;i<refs.length;i++)if(refs[i].equals(plan.normalizer)){slots.add(i);refs[i]=relocated;}
        RawCodeNames.clear(moved);
        try {expect(CloudIdentityResolver.discover(moved).normalizer.equals(relocated),"Required same owner for comparator and normalizer");}
        finally {for(int slot:slots)refs[slot]=plan.normalizer;RawCodeNames.clear(index);}
        expect(CloudIdentityResolver.discover(index).normalizer.equals(plan.normalizer),"Mutation restoration failed");
        System.out.println("PASS "+plan.comparator+": original, raw private references renamed, normalizer independently relocated, changed numeric literals, missing/ambiguous roles, producer/equals/return miswiring and storage constructor refusal");
    }
}
