# Native API 手册


## 头文件

```C++
#include "bytehook.h"
```

## 初始化

```C++
#define BYTEHOOK_MODE_AUTOMATIC 0 //自动模式
#define BYTEHOOK_MODE_MANUAL    1 //手动模式

int bytehook_init(int mode, bool debug);
```

* 一般情况下不需要手动调用 `bytehook_init()`，建议调用 Java 层的初始化函数即可（Java 层的初始化函数会调用这里的 `bytehook_init()`）。
* 特殊情况下（比如需要在纯 Native 进程中初始化 ByteHook）可以使用 `bytehook_init()`。

## 开启 / 关闭调试日志

```C++
void bytehook_set_debug(bool debug);
```

作用和 Java 层 `setDebug()` 函数相同。

## hook

hook 执行后返回的存根（stub）的定义，用于后续调用 unhook：

```C++
typedef void* bytehook_stub_t;
```

### hook 某个调用者之后执行的回调函数的定义

```C++
typedef void (*bytehook_hooked_t)(
    bytehook_stub_t task_stub, //存根，全局唯一，用于unhook
    int status_code, //hook执行状态码
    const char *caller_path_name, //调用者的pathname或basename
    const char *sym_name, //函数名
    void *new_func, //新函数地址
    void *prev_func, //原函数地址
    void *arg); //添加hook回调时指定的hooked_arg值
```

`status_code` 定义详见 [状态码](status_code.zh-CN.md)。


### hook 单个调用者

```C++
//返回NULL表示添加任务失败，否则为成功。
bytehook_stub_t bytehook_hook_single(
    const char *caller_path_name, //调用者的pathname或basename（不可为NULL）
    const char *callee_path_name, //被调用者的pathname
    const char *sym_name, //需要hook的函数名（不可为NULL）
    void *new_func, //新函数（不可为NULL）
    bytehook_hooked_t hooked, //hook后的回调函数
    void *hooked_arg); //回调函数的自定义参数
```

### hook 部分调用者

```C++
//过滤器函数定义。返回true表示需要hook该调用者，返回false表示不需要。
typedef bool (*bytehook_caller_allow_filter_t)(
    const char *caller_path_name, //调用者的pathname或basename
    void *arg); //bytehook_hook_partial中传递的caller_allow_filter_arg值

//返回NULL表示添加任务失败，否则为成功。
bytehook_stub_t bytehook_hook_partial(
    bytehook_caller_allow_filter_t caller_allow_filter, //过滤器函数（不可为NULL）
    void *caller_allow_filter_arg, //过滤器函数的自定义参数
    const char *callee_path_name, //被调用者的pathname，NULL表示所有的被调用者
    const char *sym_name, //需要hook的函数名（不可为NULL）
    void *new_func, //新函数（不可为NULL）
    bytehook_hooked_t hooked, //hook后的回调函数
    void *hooked_arg); //回调函数的自定义参数
```

### hook 全部调用者

```C++
//返回NULL表示添加任务失败，否则为成功。
bytehook_stub_t bytehook_hook_all(
    const char *callee_path_name, //被调用者的pathname，NULL表示所有的被调用者
    const char *sym_name, //需要hook的函数名（不可为NULL）
    void *new_func, //新函数（不可为NULL）
    bytehook_hooked_t hooked, //hook后的回调函数
    void *hooked_arg); //回调函数的自定义参数
```

### proxy 函数概述

ByteHook 是针对“调用者”执行 hook 的 hook 方案。比如 `libart.so` 调用了 `libc.so` 中的 `malloc()` 函数，当 hook `malloc()` 时，`libart.so` 是调用者（caller），`libc.so` 是被调用者（callee）。ByteHook 的 hook 行为是在修改调用者（`libart.so`）的 GOT 表。

* ByteHook 以 task 为单位来管理和操作 hook 诉求（包括 hook 和 unhook）。
* 每个 task 包含一个函数符号（就是你需要 hook 哪个函数）。
* 每个 task 可以包含一个回调函数，用于通知 hook 执行成功或失败（以及失败的原因）。
* 从调用者的维度，task 分为三类：
  * hook 单个调用者（`bytehook_hook_single()`）
  * hook 部分调用者（`bytehook_hook_partial()`）
  * hook 全部调用者（`bytehook_hook_all()`）
* 这 3 个 hook 函数如果调用成功，都会返回一个stub（存根），后续可用于对该 task 执行 unhook；如果调用失败，会返回 `NULL`。
* 这 3 个 hook 函数都是同步执行的，ByteHook 内部没有创建任何其他的线程。

### 自动完成 hook task

ByteHook 会“自动的去尝试完成”各个“还未完成的 task”。

#### hook 单个调用者（`bytehook_hook_single()`）

* 在已加载的所有 ELF 中寻找目标调用者。如果找到，则执行 hook task，然后将 task 标记为已完成，最后执行 hooked 回调通知外部。
* 如果未找到调用者，则将 task 标记为未完成。
* 未来某一时刻，目标调用者被加载到内存中，此时 ByteHook 会自动对它执行 hook task，然后将 task 标记为已完成，最后执行 hooked 回调通知外部。

#### hook 部分调用者（`bytehook_hook_partial()`）

* 此类任务永远处于未完成状态。
* 在已加载的所有 ELF 中使用 `caller_allow_filter` 过滤函数进行匹配，对匹配成功的调用者们，逐个执行 hook task，同时逐个执行 hooked 回调通知外部。
* 未来有任何新的 ELF 被加载到内存时，ByteHook 都会自动的用 `caller_allow_filter` 过滤函数去尝试匹配，一旦匹配成功，就会对它执行 hook task，再执行 hooked 回调通知外部。

#### hook 全部调用者（`bytehook_hook_all()`）

* 和 hook 部分调用者（`bytehook_hook_partial()`）的情况类似，区别仅在于不需要过滤函数了，而是“来者不拒”的对“所有已加载的 ELF”和“未来加载的 ELF”都执行 hook task，以及 hooked 回调。

### pathname 还是 basename

* pathname 指：文件的绝对路径（包含文件名），以 `'/'` 开头。
* basename 指：文件名，不包含任何 `'/'` 字符。

> 举例：`/system/lib/libc.so` 是 pathname；`libc.so` 是 basename。

ByteHook 使用 `dl_iterate_phdr()` 来获取当前已加载的 ELF 信息。在 Android 5.x 和部分 Android 6.x 设备上，`dl_iterate_phdr()` 会返回 ELF 的 basename，而不是 pathname。Android 5.x / 6.x 还没有 linker namespace 机制，所以 5.x / 6.x 的 `dl_iterate_phdr()` 返回 basename 并不会引起 ELF 重名的问题。考虑到性能的原因，当 ByteHook 从 `dl_iterate_phdr()` 拿到的是 basename 的时候，并没有尝试从 `maps` 再去获取这些 ELF 对应的 pathname。这导致了一些不一致性，需要使用者注意：

* **`bytehook_caller_allow_filter_t` 中的 `caller_path_name` 可能是 pathname，也可能是 basename。使用者在做动态库名称过滤时，需要自己做兼容性处理。**
* `bytehook_hooked_t` 中的 `caller_path_name` 可能返回 pathname，也可能返回 basename。如果使用者依赖于 hooked 回调中的 `caller_path_name` 信息，需要自己做兼容性处理。

### `bytehook_hook_single()` 中的 `caller_path_name`

* 这里的 `caller_path_name` 可以传 pathname，也可以传 basename。
* 如果是 APP 中自己的 so 库，可以直接传 basename（名字一般不会和其他 so 或系统 so 冲突）。
* 如果是能够确定在系统中唯一的 so 库名称，也可以直接传 basename。比如 `libart.so`。
* 如果是系统中不唯一的 so 库名称（因为 linker namespace），请使用 pathname 来避免歧义，如果传递了 basename，ByteHook 不会报错，但只会用 `ends_with` 寻找第一个匹配到的 so。例如：

```C++
bytehook_hook_single(
    "libbinderthreadstate.so",
    NULL,
    "write",
    my_new_func,
    my_hooked_callback,
    my_hooked_callback_arg);
```

在 Android 10 中可能实际 hook 的调用者是 `/system/lib64/vndk-sp-29/libbinderthreadstate.so`，而不是预想的 `/system/lib64/libbinderthreadstate.so`。因为maps可能是这样的：

```shell title="/proc/self/maps"
756fb2f000-756fb31000 r--p 00000000 fd:03 2983  /system/lib64/vndk-sp-29/libbinderthreadstate.so
756fb31000-756fb33000 --xp 00002000 fd:03 2983  /system/lib64/vndk-sp-29/libbinderthreadstate.so
756fb33000-756fb34000 rw-p 00004000 fd:03 2983  /system/lib64/vndk-sp-29/libbinderthreadstate.so
756fb34000-756fb35000 r--p 00005000 fd:03 2983  /system/lib64/vndk-sp-29/libbinderthreadstate.so
......
76090f9000-76090fb000 r--p 00000000 fd:03 2424  /system/lib64/libbinderthreadstate.so
76090fb000-76090fd000 --xp 00002000 fd:03 2424  /system/lib64/libbinderthreadstate.so
76090fd000-76090fe000 rw-p 00004000 fd:03 2424  /system/lib64/libbinderthreadstate.so
76090fe000-76090ff000 r--p 00005000 fd:03 2424  /system/lib64/libbinderthreadstate.so
......
```

### 限定 hook 的被调用者

> https://android-developers.googleblog.com/2017/05/here-comes-treble-modular-base-for.html
> https://source.android.com/devices/architecture/vndk/linker-namespace

Android 从 8.0 开始引入了 linker namespace 机制。这会导致当前进程中加载多个 basename 相同，但是 pathname 不同的 ELF。并且这些 ELF 中存在大量的重复符号（函数名）。例如：

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

此时，仅仅使用符号（函数名）来限定的话，函数调用关系不再是“多对一”（多个调用者 + 一个被调用者），而是“多对多”（多个调用者 + 多个被调用者）。

ByteHook 支持在 hook 时指定被调用者的 pathname，以此来明确限定被调用者：

1. hook 部分调用者（`bytehook_hook_partial()`）和 hook 全部调用者（`bytehook_hook_all()`）：
  * 通过 `callee_path_name` 参数指定被调用者的 pathname。
  * `callee_path_name` 参数为 `NULL` 表示不限制被调用者。
2. hook 单个调用者（`bytehook_hook_single()`）：
  * 因为单个调用者只可能对应到单个被调用者，所以 `bytehook_hook_single()` 事实上不用考虑 linker namespace 的影响。
  * 可以通过 `callee_path_name` 传递被调用者的 pathname，这么做理论上可以稍微加快 hook 时查找符号（函数名）的速度，实际能快多少依赖于具体 ELF 中的符号数量。

举例：

```C++
bytehook_hook_all(
    "/system/lib64/libcutils.so",
    "atrace_begin_body",
    my_new_func,
    my_hooked_callback,
    my_hooked_callback_arg);
```

此时，只有针对 `/system/lib64/libcutils.so` 中的 `atrace_begin_body()` 函数的调用才会被 hook。而任何对对 `/apex/com.android.vndk.v30/lib64/libcutils.so` 中的 `atrace_begin_body()` 函数的调用都不会被 hook。

## unhook

```C++
int bytehook_unhook(bytehook_stub_t stub);
```

如果需要 unhook，在前面调用 hook 函数时需要保存返回值（stub / 存根），在 unhook 的时候需要用到。举例：

```C++
void my_unhook()
{
    int status_code = bytehook_unhook(stub);

    if(status_code != 0) {
         Log.d("tag", "bytehook unhook FAILED, status_code: " + status_code);
    }

    // unhook 之后，请将 stub 置为 NULL。
    stub = nullptr;
}
```

* unhook 会被立刻同步执行，返回0表示成功，非 `0` 表示失败，详见 [状态码](status_code.zh-CN.md)。
* unhook 之后，stub 不再有效，为避免在别处被误用，请将 stub 置为 `NULL`。

## BYTEHOOK\_CALL\_PREV

```C++
#ifdef __cplusplus
    #define BYTEHOOK_CALL_PREV(func, ...) ......
#else
    #define BYTEHOOK_CALL_PREV(func, func_sig, ...) ......
#endif
```

用于在 proxy 函数中调用原函数。在 proxy 函数中也可以不调用原函数，但请不要通过函数名来直接调用原函数。

在 C++ 源文件中的用法是：第一个参数传递当前的 proxy 函数地址，后面按照顺序依次传递函数的各个参数。

C++ 文件中使用 `BYTEHOOK_CALL_PREV` 举例：

```C++
size_t my_strlen(const char* const str)
{
    BYTEHOOK_STACK_SCOPE();

    size_t result = BYTEHOOK_CALL_PREV(my_strlen, str);
    return result;
}
```

在 C 源文件中的用法是：第一个参数传递当前的 proxy 函数地址，第二个参数传递目标函数的定义，后面按照顺序依次传递函数的各个参数。

C 文件中使用 `BYTEHOOK_CALL_PREV` 举例：

```C++
typedef size_t (*strlen_t)(const char* const);

size_t my_strlen(const char* const str)
{
    size_t result = BYTEHOOK_CALL_PREV(my_strlen, strlen_t, str);

    BYTEHOOK_POP_STACK();
    return result;
}
```

### proxy 函数中可以不调用原函数吗？

可以。例如在裁剪 hprof 时 hook `write()` 系列函数的场景。但是，不调用原函数会有一个副作用：就是其他 SDK 注册在同一个 hook 点上的其他 proxy 函数可能不会被调用到了，比如此时还有磁盘 IO 监控的SDK 也 hook 了 `write()`，就有可能不会被调用到了。对于这种情况，建议各 SDK 沟通协商，调整各 SDK对于同一个 hook 点的 hook task 添加顺序。

ByteHook 的内部逻辑是：**对于同一个调用者 ELF 的同一个函数，后注册的 hook task 中的 proxy 函数会被先执行。**因此，对应前面的例子，如果想要 hprof 不调用原函数，但是又不影响磁盘 IO 监控，就需要：先注册 hprof 的 hook task，再注册磁盘 IO 监控的 hook task。

## BYTEHOOK\_STACK\_SCOPE 和 BYTEHOOK\_POP\_STACK

```C++
// for C++
#define BYTEHOOK_STACK_SCOPE() ......

// for C
#define BYTEHOOK_POP_STACK() ......
```

* 这两个宏的作用是一样的，都是用于在 proxy 函数中执行 ByteHook 的 stack 清理逻辑。
* **每个 proxy 函数中都必须执行 ByteHook 的 stack 清理逻辑。有两种方式：**
  * **在 C++ 代码中：在“proxy 函数”开头调用一次 `BYTEHOOK_STACK_SCOPE` 宏。（其中会通过析构函数的方式，来保证 stack 清理逻辑一定会被执行）**
  * **在 C 代码中：请在“proxy 函数”的每一个“返回分支”末尾都调用 `BYTEHOOK_POP_STACK` 宏。**

C++ hook函数举例：

```C++
// C++ 函数
size_t my_strlen(const char* const str)
{
    // 执行 stack 清理（不可省略），只需调用一次
    BYTEHOOK_STACK_SCOPE();

    if(0 == strcmp(str, "ignore"))
        return 0;

    return BYTEHOOK_CALL_PREV(my_strlen, str);
}
```

C hook函数举例：

```C
typedef size_t (*strlen_t)(const char* const);

// C 函数
size_t my_strlen(const char* const str)
{
    if(0 == strcmp(str, "ignore"))
    {
        // 执行 stack 清理（不可省略）
        BYTEHOOK_POP_STACK();
        return 0;
    }

    size_t result = BYTEHOOK_CALL_PREV(my_strlen, strlen_t, str);

    // 执行 stack 清理（不可省略）
    BYTEHOOK_POP_STACK();
    return result;
}
```

* 在 C proxy 函数中，比较容易遗漏 `BYTEHOOK_POP_STACK` 调用。这点需要特别小心。
* 在 C++ proxy 函数中，也完全可以用 `BYTEHOOK_POP_STACK` 来执行清理 stack（用法和 C proxy 函数中的用法相同），但是显然使用 `BYTEHOOK_STACK_SCOPE` 会更友好一些。

## BYTEHOOK\_RETURN\_ADDRESS

```C++
#define BYTEHOOK_RETURN_ADDRESS()
```

* 在 ByteHook 的自动模式中，由于有 trampoline 的存在，直接调用 `__builtin_return_address(0)` 得到的 `LR` 将会落在 trampoline 中，而不是落在“原调用者函数”中。
* 如果你需要在 proxy 函数中使用 `__builtin_return_address(0)`，请改用 `BYTEHOOK_RETURN_ADDRESS` 宏来获取真正的 `LR`（落在“原调用者函数”中）。

## hook dlopen() 和 android\_dlopen\_ext()

有时候我们需要 hook `dlopen()` 和 `android_dlopen_ext()`，比如用来统计 so 库加载的耗时，或者在某些 so 库加载之前或之后做一些特别的事情。

ByteHook 内部也 hook 了 `dlopen()` 和 `android_dlopen_ext()`，用来感知新 so 库的加载，以便自动完成针对“全部”（`bytehook_hook_all()`）和“部分”（`bytehook_hook_partial()`）so 的 hook 任务。

由于 Android 7.0 开始有了 linker namespace 的限制，所以 hook `dlopen()` 和 `android_dlopen_ext()` 之后，如何调用原函数是个挑战。尤其在 Android 7.x 上，目前无法通过 `BYTEHOOK_CALL_PREV` 来调用原函数，这样无法绕过 linker namespace的限制。只能直接调用 linker 内部的一些非公开函数，来达到调用原函数的目的。

但是这样做会带来一个问题：如果不调用 `BYTEHOOK_CALL_PREV`，那么多个 `dlopen()` 和 `android_dlopen_ext()` 的 proxy 函数中，只能有一个被执行（ByteHook 内部通过 `BYTEHOOK_CALL_PREV` 来达到多个 proxy 函数链式调用的目的）。

如果你的需求只是监控一下 `dlopen()` 和 `android_dlopen_ext()` 的时间点和耗时，可以直接调用 ByteHook 提供的 API 来完成：

```C++
typedef void (*bytehook_pre_dlopen_t)(
    const char *filename,
    void *data);

typedef void (*bytehook_post_dlopen_t)(
    const char *filename,
    int result, // 0: OK  -1: Failed
    void *data);

void bytehook_add_dlopen_callback(
    bytehook_pre_dlopen_t pre,
    bytehook_post_dlopen_t post,
    void *data);

void bytehook_del_dlopen_callback(
    bytehook_pre_dlopen_t pre,
    bytehook_post_dlopen_t post,
    void *data);
```

* `bytehook_add_dlopen_callback()` 用于注册 `dlopen()` 和 `android_dlopen_ext()` 的 `pre` 和 `post` 回调（分别在 so 被加载之前和之后执行回调）。
* `bytehook_del_dlopen_callback()` 用于反注册。反注册时，请传入和注册时相同的 `pre`、`post`、`data` 参数。
* `pre` 和 `post` 回调可以都指定，也可以只指定其中任意一个。
* `pre` 回调中，`filename` 是当前 `dlopen()` 或 `android_dlopen_ext` 文件的 basename 或 pathname。`data` 为注册时传入的最后一个 `data` 参数。
* `post` 回调中，`filename` 和 `data` 参数与 `pre` 回调相同。`result` 参数用于返回 `dlopen()` 或 `android_dlopen_ext()` 的执行结果（`0` 表示成功，`-1` 表示失败）。
* 这里的注册的回调不区分 Android 版本，也不区分具体是 `dlopen()` 还是 `android_dlopen_ext()`。

如果你需要修改 `dlopen()` 或 `android_dlopen_ext()` 的参数或返回值，就需要自己 hook 了。在自动模式中，你可以和 hook 其他函数一样进行 hook，在 proxy 函数里正常的通过 `BYTEHOOK_CALL_PREV` 调用原函数（因为 ByteHook 内部对 `dlopen()` 和 `android_dlopen_ext()` hook 的 proxy 函数总是最后执行的，在其中会自动处理 caller_address 和 Android 7.x 调用 linker 内部函数的问题）。在手动模式中，Android 7.x 中会有问题，因为 ByteHook 内部对 `dlopen()` 和 `android_dlopen_ext()` hook 的 proxy 函数中，通过 `__builtin_return_address(0)` 拿到的 `LR` 已经不是原始的 `LR`，而是会指向你的 proxy 函数；在其他 Android 版本中不会有问题。