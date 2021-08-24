# Java API 手册


## 类

```Java
import com.bytedance.android.bytehook.ByteHook;
```


## 初始化

```Java
public static synchronized int init();
public static synchronized int init(Config config);
```

返回 0 表示成功，非 0 表示失败。详见 [状态码](status_code.zh-CN.md)。

* ByteHook 需要初始化后才能使用。
* ByteHook 内部有保护逻辑，在同一个 APP 进程中，只有第一次初始化有效，后续的初始化调用是无效的，也不会产生其他的副作用。(因此，各个使用 ByteHook 的 SDK 都可以在自身的初始化逻辑中初始化 ByteHook，集成到 APP 后彼此不会有冲突)
* ByteHook 初始化时，或运行时（通过 `setDebug()`）可以开启 debug 模式。此时 ByteHook 会向 logcat 写大量的调试信息，这会降低 ByteHook 的运行性能。建议线上 release 版本不要开启 debug 模式。

> 举例 1：

```Java
import com.bytedance.android.bytehook.ByteHook;

public class MySdk {
    public static synchronized void init() {

        // 初始化 bytehook。返回 0 表示成功，其他表示失败（详见status code）
        int status_code = ByteHook.init();

        if(status_code != 0) {
            Log.d("tag", "bytehook init FAILED, status_code: " + status_code);
        }
                
        // 其他初始化逻辑
        // ......
    }
}
```

> 举例 2：

```Java
import com.bytedance.android.bytehook.ByteHook;
import com.bytedance.android.bytehook.ILibLoader;

public class MySdk {
    public static synchronized void init() {

        // 初始化 bytehook。返回 0 表示成功，其他表示失败（详见status code）
        int status_code = ByteHook.init(new ByteHook.ConfigBuilder()
            // 指定一个外部的so loader，默认System.loadLibrary
            .setLibLoader(new ILibLoader() {
                @Override
                public void loadLibrary(String libName) {
                    MySoLoader.loadLibrary(libName);
               }
           })
           // 指定运行模式（可设置自动模式或手动模式），默认自动模式
           .setMode(ByteHook.Mode.AUTOMATIC)
           // 输出内部调试日志到logcat（tag：bytehook_tag），默认false
           .setDebug(true)
           .build());

        if(status_code != 0) {
            Log.d("tag", "bytehook init FAILED, status_code: " + status_code);
        }
                
        // 其他初始化逻辑
        // ......
    }
}
```


## 自动模式和手动模式

* ByteHook 默认使用自动模式。
* 自动模式：ByteHook 内部通过 trampoline + proxy list 的形式，自动管理“同一个 hook 点的多个 proxy 函数”，任何一个 proxy 函数被 unhook 后，都不会影响其他的 proxy 函数。另外，自动模式还能自动避免 proxy 函数之间的递归调用和环形调用。**（正式发布的 SDK 请始终使用自动模式）**
* 手动模式：ByteHook 直接修改 hook 点的 GOT 表，将“原函数的地址”返回给调用者。unhook 时，如果同一个 hook 点又被其他 SDK hook 过，则会导致“proxy 函数丢失的问题”。**（手动模式仅用于特殊情况下本地测试使用）**


## 开启 / 关闭调试日志

```java
public static void setDebug(boolean debug);
```

* 可以通过 `setDebug()` 随时开启 / 关闭 ByteHook 的调试日志。
* 调试日志输出到 logcat，tag为：`bytehook_tag`。
* 使用默认参数初始化时，ByteHook 默认关闭调试日志。
