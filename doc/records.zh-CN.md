# 操作记录


* ByteHook 可以在内存中记录 hook / unhook 的操作信息。
* ByteHook 使用了一种比较精简的二进制 + 数据字典格式来记录信息，占用的内存会动态扩展，当操作记录使用的内存达到 1Mbytes 时，就停止继续记录。（1Mbytes估算可以记录 20000 次 hook / unhook 的操作信息）
* ByteHook 提供了 dump 这些数据的接口。以字符串形式返回操作信息的内容，或将内容写入指定的 FD（文件描述符）中。（其中写入 FD 的 API 是异步信号安全的，可以在 signal handler 中使用。例如，可以在捕获 app 崩溃的signal handler 中调用）
* 注意：ByteHook 默认关闭操作记录。需要的话，可以在初始化完成后通过 Java 函数 `setRecordable()` 或 Native 函数 `bytehook_set_recordable()` 开启。

## native 层 API

```C
#include "bytehook.h"

#define BYTEHOOK_RECORD_ITEM_ALL             0xFF // 0b11111111
#define BYTEHOOK_RECORD_ITEM_TIMESTAMP       (1 << 0)
#define BYTEHOOK_RECORD_ITEM_CALLER_LIB_NAME (1 << 1)
#define BYTEHOOK_RECORD_ITEM_OP              (1 << 2)
#define BYTEHOOK_RECORD_ITEM_LIB_NAME        (1 << 3)
#define BYTEHOOK_RECORD_ITEM_SYM_NAME        (1 << 4)
#define BYTEHOOK_RECORD_ITEM_NEW_ADDR        (1 << 5)
#define BYTEHOOK_RECORD_ITEM_ERRNO           (1 << 6)
#define BYTEHOOK_RECORD_ITEM_STUB            (1 << 7)

char *bytehook_get_records(uint32_t item_flags);
void bytehook_dump_records(int fd, uint32_t item_flags);
```

* `bytehook_get_records` 返回一个用 `malloc` 分配的 buffer，其中包含操作记录。你需要自己调用 `free` 来释放这块内存。失败是返回 `NULL`。
* `bytehook_dump_records` 将操作记录写入参数 FD 指向的文件描述符中。此接口是异步信号安全的。
* 可以使用 `item_flags` 参数来控制需要输出哪些数据项。

## java 层 API

```Java
package com.bytedance.android.bytehook;

public class ByteHook

public enum RecordItem {
  TIMESTAMP,
  CALLER_LIB_NAME,
  OP,
  LIB_NAME,
  SYM_NAME,
  NEW_ADDR,
  ERRNO,
  STUB
}

public static String getRecords(RecordItem... recordItems)
```

* `getRecords` 直接调用了 native 层的 `bytehook_get_records` 函数，返回操作记录。
* 可以使用 `recordItems` 参数来控制需要输出哪些数据项。

## 操作记录格式

* 操作记录为字符串格式，一行为一条记录，`\n` 结尾。
* 每行中的数据项以 `,`（英文逗号）分隔。
* 操作记录可能有 3 种类型：
  * hook
  * unhook
  * error（表示bytehook的操作记录模块自身发生问题，无法继续记录信息了）

### 操作记录举例

```
2021-11-05T15:20:27.767+08:00,libbytehooksystest.so,hook,libappfuse.so,writev,78ace73fb0,0,76891db690
2021-11-05T15:21:40.226+08:00,libbytehooksystest.so,unhook,0,76891db690
9999-99-99T00:00:00.000+00:00,error,error,0,0
```

### 数据项说明

| # | 描述 | 备注 |
| :---------- | :-------------- | :---------------- |
| 1 | 时间戳 | 格式：YYYY-MM-DDThh:mm:ss.sss+hh:mm |
| 2 | 操作调用者动态库名称 | basename |
| 3 | 操作类型 | hook / unhook / error |
| 4 | hook 时，调用者动态库名称 | basename。unhook记录中无此项 |
| 5 | hook 时，目标函数的名称 | unhook记录中无此项 |
| 6 | hook 时，proxy函数的地址 | unhook记录中无此项 |
| 7 | 错误码 |  |
| 8 | stub 值 | 是个指针类型的数值，hook / unhook 可以通过这个值来配对 |
