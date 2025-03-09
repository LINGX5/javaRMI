package com.lingx5;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Calculator extends Remote {
    int add(int a, int b) throws RemoteException;  // 所有方法必须声明抛出RemoteException
    String sayHello(String name) throws RemoteException;
    void sayGood(Object o) throws RemoteException;
    Object getObject() throws RemoteException;
}