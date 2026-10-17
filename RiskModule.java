package com.axuan.vivoe2eeprover;
import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import de.robv.android.xposed.*;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public final class RiskModule implements IXposedHookLoadPackage {
 private static final AtomicBoolean attempted=new AtomicBoolean(false),refreshQueued=new AtomicBoolean(false);
 public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lp)throws Throwable {
  if(!"com.vivo.vms".equals(lp.packageName)&&!"com.bbk.cloud".equals(lp.packageName))return;
  XposedHelpers.findAndHookMethod(Application.class,"attach",Context.class,new XC_MethodHook(){
   protected void afterHookedMethod(MethodHookParam p)throws Throwable {
    Context context=(Context)p.args[0];
    if(context==null||!lp.packageName.equals(context.getPackageName())||!attempted.compareAndSet(false,true))return;
    try {
     ApplicationInfo info=context.getApplicationInfo();List<File> files=new ArrayList<>();files.add(new File(info.sourceDir));
     if(info.splitSourceDirs!=null)for(String path:info.splitSourceDirs)files.add(new File(path));
     DexIndex index=DexIndex.readApks(files);
     if("com.bbk.cloud".equals(lp.packageName))installCloud(DexMembers.method(RiskResolver.cloud(index),lp.classLoader));
     else installVms(RiskResolver.vms(index),lp.classLoader);
    } catch(Throwable error){XposedBridge.log("VivoE2EEProver: semantic discovery disabled: "+error);}
   }
  });
 }
 private static void installCloud(Method identity) {
  XposedBridge.hookMethod(identity,new XC_MethodHook(){
   protected void afterHookedMethod(MethodHookParam p)throws Throwable {
    if(p.hasThrowable()||!(p.getResult() instanceof String))return;
    String value=(String)p.getResult();
    if(value.length()<=64||!value.matches("[0-9a-fA-F]+"))return;
    byte[] digest=java.security.MessageDigest.getInstance("MD5").digest(value.getBytes("UTF-8"));
    StringBuilder normalized=new StringBuilder(32);
    for(byte part:digest){normalized.append(Character.forDigit((part>>>4)&15,16));normalized.append(Character.forDigit(part&15,16));}
    p.setResult(normalized.toString());
    XposedBridge.log("VivoE2EEProver: cloud-emmcid normalized input-length="+value.length()+" output-length=32");
   }
  });
  XposedBridge.log("VivoE2EEProver: cloud semantic normalizer="+identity);
 }
 private static void installVms(RiskResolver.Plan plan,ClassLoader loader)throws Throwable {
  final Method debug=DexMembers.method(plan.debug,loader),developer=DexMembers.method(plan.developer,loader),
   adb=DexMembers.method(plan.adb,loader),socket=DexMembers.method(plan.socket,loader),
   credit=DexMembers.method(plan.credit,loader),init=DexMembers.method(plan.init,loader);
  final Constructor<?> local=DexMembers.constructor(plan.localTask,loader),sync=DexMembers.constructor(plan.syncTask,loader);
  if(!Runnable.class.isAssignableFrom(local.getDeclaringClass())||!Runnable.class.isAssignableFrom(sync.getDeclaringClass()))
   throw new NoSuchMethodException("Discovered risk tasks must implement Runnable");
  List<XC_MethodHook.Unhook> hooks=new ArrayList<>();
  try {
   hooks.add(XposedBridge.hookMethod(debug,new XC_MethodHook(){protected void beforeHookedMethod(MethodHookParam p){
    if("debuging".equals(p.args[0]))p.setResult(Boolean.FALSE);
   }}));
   hooks.add(XposedBridge.hookMethod(developer,XC_MethodReplacement.returnConstant(false)));
   hooks.add(XposedBridge.hookMethod(adb,XC_MethodReplacement.returnConstant(0)));
   hooks.add(XposedBridge.hookMethod(socket,XC_MethodReplacement.returnConstant(Boolean.FALSE)));
   hooks.add(XposedBridge.hookMethod(credit,new XC_MethodHook(){protected void afterHookedMethod(MethodHookParam p){
    if(!p.hasThrowable()){Object original=p.getResult();p.setResult(3);
     XposedBridge.log("VivoE2EEProver: original="+original+" returned=3 scope=all-authorized-callers");}
   }}));
   hooks.add(XposedBridge.hookMethod(init,new XC_MethodHook(){protected void afterHookedMethod(MethodHookParam p){
    if(p.hasThrowable()||p.getResult()==null||!refreshQueued.compareAndSet(false,true))return;
    new Thread(new Runnable(){public void run(){try {
     Thread.sleep(15000);((Runnable)local.newInstance(true)).run();((Runnable)(sync.getParameterTypes().length==0 ? sync.newInstance() : sync.newInstance(new Object[]{null}))).run();
     XposedBridge.log("VivoE2EEProver: official local calculation and cloud sync tasks returned; server acceptance not inferred");
    }catch(Throwable error){XposedBridge.log("VivoE2EEProver: refresh-error="+error);}}},"VMS-four-signals-refresh").start();
   }}));
  }catch(Throwable failure){for(XC_MethodHook.Unhook hook:hooks)hook.unhook();throw failure;}
  XposedBridge.log("VivoE2EEProver: semantic plan installed "+plan.describe());
 }
}
