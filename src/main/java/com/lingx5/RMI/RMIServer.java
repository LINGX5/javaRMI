package com.lingx5.RMI;

import com.lingx5.Caculatorimpl;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * RMI服务启动类
 * 该类的主要作用是初始化RMI注册表，并绑定一个计算器服务实现
 */
public class RMIServer {
    /**
     * 主函数
     * 尝试创建并启动RMI注册表，然后绑定计算器服务实现
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        try {
            // 创建计算器服务实现实例
            Caculatorimpl caculator = new Caculatorimpl();
            // 创建RMI注册表，监听端口为1099
            Registry registry = LocateRegistry.createRegistry(1099);
            // 在注册表中绑定计算器服务实现，供远程调用
            registry.rebind("caculator", caculator);

            // 打印服务启动成功信息和RMI注册地址
            System.out.println("RMI服务已启动");
            System.out.println("RMI注册地址: rmi://192.168.52.1:1099/caculator");
        } catch (Exception e) {
            // 打印异常信息
            System.out.println(e.getMessage());
        }
    }
}

