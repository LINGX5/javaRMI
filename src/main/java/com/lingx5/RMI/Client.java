package com.lingx5.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Client {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        registry.lookup("exploit"); // 触发反序列化漏洞
    }
}