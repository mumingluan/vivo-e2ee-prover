package com.axuan.vivoe2eeprover;
import java.io.*;
import java.util.*;
public final class RiskResolverProbe {
 public static void main(String[] args)throws Exception {
  DexIndex index=DexIndex.readApks(Collections.singletonList(new File(args[1])));
  if(args[0].equals("inspect")) {
   for(DexIndex.MethodData m:index.methods.values()) {
    boolean hit=false;for(String text:m.facts().strings) if(text.toLowerCase().contains("frida")) hit=true;
    if(hit)System.out.println(m.ref+" STRINGS="+m.facts().strings+" CALLS="+m.facts().calls);
   }
   return;
  }
  long start=System.nanoTime();
  System.out.println(args[0].equals("vms") ? RiskResolver.vms(index).describe() : RiskResolver.cloud(index));
  System.out.println("discoveryMs="+(System.nanoTime()-start)/1000000);
 }
}
