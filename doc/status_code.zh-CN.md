# 状态码


部分 API（包括 java 层的 init 初始化函数）会返回 status code。0 表示成功，非 0 表示失败。

## 0

成功。

## 1

未初始化。如果没有初始化就调用 hook / unhook 等 API 函数，会返回这个错误码。

## 2

初始化失败。原因是输入了非法参数。

## 3

初始化失败。原因是 ByteHook 没有找到某些内部需要使用的系统库符号。

## 4

初始化失败。原因是 ByteHook 内部初始化“ task 管理模块”时失败了。

## 5

初始化失败。原因是 ByteHook 内部初始化“ hook 管理模块”时失败了。

## 6

初始化失败。原因是 ByteHook 内部初始化“ ELF 管理模块”时失败了。

## 7

初始化失败。原因是 ByteHook 内部执行“ ELF 列表刷新”时失败了。（目前不再使用）

## 8

初始化失败。原因是 ByteHook 内部初始化“ trampoline 管理模块”时失败了。

## 9

初始化失败。原因是 ByteHook 内部初始化“ signal 管理模块”时失败了。

## 10

初始化失败。原因是 ByteHook 内部初始化“ DL monitor 管理模块”时失败了。

## 11

调用 API 时输入的参数非法。

## 12

只针对手动模式。执行 unhook 时，发现“原函数地址不唯一”，`bytehook_unhook()` 调用失败。举例：

hook 任务为“ hook 进程中所有 ELF 对 `libcutils.so` 中 `atrace_begin_body()` 的调用”，但是由于 android linker namespace的原因，进程中可能存在多个 `libcutils.so`：

```shell title="/proc/self/maps"
7a772e8000-7a772ef000 r--p 00000000 fd:04 2117  /system/lib64/libcutils.so
7a772ef000-7a772f7000 r-xp 00007000 fd:04 2117  /system/lib64/libcutils.so
7a772f7000-7a772f9000 r--p 0000f000 fd:04 2117  /system/lib64/libcutils.so
7a772f9000-7a772fa000 rw-p 00010000 fd:04 2117  /system/lib64/libcutils.so

77c7150000-77c7157000 r--p 00000000 07:38 537   /apex/com.android.vndk.v30/lib64/libcutils.so
77c7157000-77c715f000 r-xp 00007000 07:38 537   /apex/com.android.vndk.v30/lib64/libcutils.so
77c715f000-77c7161000 r--p 0000f000 07:38 537   /apex/com.android.vndk.v30/lib64/libcutils.so
77c7161000-77c7162000 rw-p 00010000 07:38 537   /apex/com.android.vndk.v30/lib64/libcutils.so
```

当出现这种情况时，这种类型的 hook 任务无法通过 `bytehook_unhook()` API 进行 unhook，只能手动逐个 unhook（在 hooked 回调中逐个保存原函数地址，然后使用原函数地址逐个再次执行 hook，以恢复 GOT 表）。

## 13
针对 hook 单个调用者库（single）的情况。如果该库中没有找到需要 hook 的目标符号，会返回这个错误码。（hook “全部”或“部分”调用者库时，如果发现某个库中没有找到目标符号，则不会返回错误）

## 14

获取 hook 位置（`.got` 或 `.data`）的内存权限时失败。

## 15

修改 hook 位置（`.got`）的内存权限时失败。

## 16

将新的函数地址写入 hook 位置（`.got` 或 `.data`）时失败。发生了 `SIGSEGV` 或 `SIGBUS`。ByteHook 内部会对这种情况做保护（类似 ART 对 NPE 的保护），不会引起进程的崩溃。

## 17

自动模式中。分配新的 trampoline 内存时失败。

## 18

自动模式中。在一个已经分配了 trampoline 的 hook list 中创建新的 proxy 函数时失败。

## 19

替换 GOT 值之前，通过 `dladdr()` 验证函数地址失败。

## 20

同一个 ELF caller 的同一个函数上，已经存在了一个相同的 proxy 函数。

## 21

读内存中的当前 ELF caller 数据时，曾经发生过 `SIGSEGV` 或 `SIGBUS`，触发过崩溃保护。再次尝试对该 ELF 执行 hook 时，会给出这个错误码。

## 22

绕过 ELF 中的 CFI 检测时失败了。

[Android 从 8.1 开始](https://source.android.com/devices/tech/debug/cfi)，在编译部分 arm64 和 x86_64 系统库时，开启了 [llvm 的 CFI 功能](https://clang.llvm.org/docs/ControlFlowIntegrity.html)，CFI 机制会在运行时检测部分 GOT 中地址的合法性，如果修改了 GOT 中的值，会导致程序崩溃。所以，当 ByteHook 遇到启用 CFI 功能的 ELF 时，需要首先绕过 CFI 检测机制，如果绕过失败，则不能继续对这个 ELF 执行任何 hook。

## 23

专为手动模式增加的状态码，用于在 `hooked` 回调函数中保存原函数地址。举例：

```C
static void *orig_func = NULL;

static void hooked_callback(bytehook_stub_t task_stub, 
                            int status_code,
                            const char *caller_path_name,
                            const char *sym_name,
                            void *new_func,
                            void *prev_func,
                            void *arg)
{
    if(status_code == BYTEHOOK_STATUS_CODE_ORIG_ADDR /* 23*/)
        orig_func = prev_func;
}
```

## 100

java 层错误。初始化时，`loadLibrary` 失败。

## 101

java 层错误。初始化时，调用 native 层初始化函数时发生异常。
