package com.lingx5.RMI;

import com.lingx5.Calculator;

import java.rmi.Naming;

/**
 * RMI客户端主类
 * 该类包含主方法，用于演示如何通过RMI调用远程计算器服务
 */
public class RMIClient {

    /**
     * 主方法
     * 尝试查找并连接到远程计算器服务，然后调用加法方法
     * @param args 命令行参数，未使用
     */
    public static void main(String[] args) {
        try {
            // 通过RMI URL查找远程计算器对象
             Naming.lookup("rmi://127.0.0.1:1099/exploit");

            // 调用远程计算器对象的加法方法，并接收结果

//            System.out.println(calculator.sayHello("lingx5"));
//            int res = calculator.add(12, 34);

            // 打印加法方法的结果
//            System.out.println(res);
        } catch (Exception e) {
            // 捕获并打印异常信息
            System.out.println(e.getMessage());
        }
    }
}

