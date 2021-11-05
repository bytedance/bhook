# 操作记录


* ByteHook 会在内存中记录 hook / unhook 的操作信息。
* ByteHook 使用了一种比较精简的二进制 + 数据字典格式来记录信息，占用的内存会动态扩展，当操作记录使用的内存达到 1Mbytes 时，就停止继续记录。（1Mbytes估算可以记录 20000 次 hook / unhook 的操作信息）
* ByteHook 提供了 dump 这些数据的接口。以字符串形式返回操作信息的内容，或将内容写入指定的 FD（文件描述符）中。（其中写入 FD 的 API 是异步信号安全的，可以在 signal handler 中使用。例如，可以在捕获 app 崩溃的signal handler 中调用）

## native 层 API

```C
#include "bytehook.h"

char *bytehook_get_records(void);
void bytehook_dump_records(int fd);
```

* `bytehook_get_records` 返回一个用 `malloc` 分配的 buffer，其中包含操作记录。你需要自己调用 `free` 来释放这块内存。失败是返回 `NULL`。
* `bytehook_dump_records` 将操作记录写入参数 FD 指向的文件描述符中。此接口是异步信号安全的。

## java 层 API

```Java
package com.bytedance.android.bytehook;

public class ByteHook

public static String getRecords()
```

* `getRecords` 直接调用了 native 层的 `bytehook_get_records` 函数，返回操作记录。

## 操作记录格式

* 操作记录为字符串格式，一行为一条记录，`\n` 结尾。
* 每行中的数据项以 `,`（英文逗号）分隔。
* 操作记录可能有 3 种类型：
  * hook
  * unhook
  * error（表示bytehook的操作记录模块自身发生问题，无法继续记录信息了）

### 操作记录举例

```
2021-11-05T15:20:27.767+08:00,libbytehooksystest.so,hook,0,76891de8a0,78ace73fb0,75afdd31a4,writev,/system/lib64/libappfuse.so
2021-11-05T15:21:40.226+08:00,libbytehooksystest.so,unhook,0,76891db690,/system/lib64/libappfuse.so
9999-99-99T00:00:00.000+00:00,error,error,0,0
```

### 数据项说明

| # | 描述 | 备注 |
| :---------- | :-------------- | :---------------- |
| 1 | 时间戳 | 格式：YYYY-MM-DDThh:mm:ss.sss+hh:mm |
| 2 | 操作调用者动态库名称 | basename |
| 3 | 操作类型 | hook / unhook / error |
| 4 | 错误码 |  |
| 5 | stub 值 | 是个指针类型的数值，hook / unhook 可以通过这个值来配对 |
| 6 | hook 时，目标函数的地址 | （unhook记录中无此项） |
| 7 | hook 时，proxy函数的地址 | （unhook记录中无此项） |
| 8 | hook 时，目标函数的名称 | （unhook记录中无此项） |
| 9 | hook 时或 unhook 时，目标函数所在的动态库的 pathname | 注意，这个 pathname 是通过 `dl_iterate_phdr` 获取的，在 Android 5.x 上只能获取到 basename（不包含文件路径） |
