# 快速开始


## 接入

### 1. 在 build.gradle 中增加依赖

ByteHook 发布在 [Maven Central](https://search.maven.org/) 上。为了使用 [native 依赖项](https://developer.android.com/studio/build/native-dependencies)，ByteHook 使用了从 [Android Gradle Plugin 4.0+](https://developer.android.com/studio/releases/gradle-plugin?buildsystem=cmake#native-dependencies) 开始支持的 [Prefab](https://google.github.io/prefab/) 包格式。

```Gradle
allprojects {
    repositories {
        mavenCentral()
    }
}
```

```Gradle
android {
    buildFeatures {
        prefab true
    }
}

dependencies {
    implementation 'com.bytedance:bytehook:x.y.z'
}
```

`x.y.z` 请替换成版本号，建议使用最新的 [release](https://github.com/bytedance/bhook/releases) 版本。

### 2. 在 CMakeLists.txt 或 Android.mk 中增加依赖

> CMakeLists.txt

```CMake
find_package(bytehook REQUIRED CONFIG)

add_library(mylib SHARED mylib.c)
target_link_libraries(mylib bytehook::bytehook)
```

> Android.mk

```
include $(CLEAR_VARS)
LOCAL_MODULE           := mylib
LOCAL_SRC_FILES        := mylib.c
LOCAL_SHARED_LIBRARIES += bytehook
include $(BUILD_SHARED_LIBRARY)

$(call import-module,prefab/bytehook)
```

### 3. 指定一个或多个你需要的 ABI

```Gradle
android {
    defaultConfig {
        ndk {
            abiFilters 'armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64'
        }
    }
}
```

### 4. 增加打包选项

如果你是在一个 SDK 工程里使用 ByteHook，你可能需要避免把 libbytehook.so 打包到你的 AAR 里，以免 app 工程打包时遇到重复的 libbytehook.so 文件。

```Gradle
android {
    packagingOptions {
        exclude '**/libbytehook.so'
    }
}
```

另一方面, 如果你是在一个 APP 工程里使用 ByteHook，你可以需要增加一些选项，用来处理重复的 libbytehook.so 文件引起的冲突。

```Gradle
android {
    packagingOptions {
        pickFirst '**/libbytehook.so'
    }
}
```


## 在 Java 层初始化

详细信息请参考：[Java API 手册](java_manual.zh-CN.md)。

ByteHook 初始化之后才能使用。

```java
import com.bytedance.android.bytehook.ByteHook;

public class MySdk {
    public static synchronized void init() {
        ByteHook.init();
    }
}
```


## 在 Native 层执行 hook 和 unhook

详细信息请参考：[Native API 手册](native_manual.zh-CN.md)。

### 包含头文件

```C++
#include "bytehook.h"
```

### hook 单个 so

举例，hook “`libsample.so`” 中对 `strlen()` 函数的调用：

```C++
bytehook_stub_t stub = nullptr; // hook 的存根，用于后续 unhook

void my_hook()
{
    stub = bytehook_hook_single(
        "libsample.so",
        nullptr,
        "strlen",
        reinterpret_cast<void *>(my_strlen),
        nullptr,
        nullptr);
}
```

### hook 所有 so

举例，hook 进程中“所有 so” 中对 `strlen()` 函数的调用：

```C++
bytehook_stub_t stub = nullptr; // hook 的存根，用于后续 unhook

void my_hook()
{
    stub = bytehook_hook_all(
        nullptr,
        "strlen",
        reinterpret_cast<void *>(my_strlen),
        nullptr,
        nullptr);
}
```

### hook 部分 so

举例，hook 进程中“除了 `libbase.so` 和 `liblog.so` 以外的所有 so” 中对 `strlen()` 函数的调用：

```C++
// 过滤器函数。返回 true 表示需要 hook 这个 so；返回 false 表示不需要 hook 这个 so。
bool my_allow_filter(const char *caller_path_name, void *arg)
{
    // 不 hook libbase.so
    if(nullptr != strstr(caller_path_name, "libbase.so")) return false;

    // 不 hook liblog.so
    if(nullptr != strstr(caller_path_name, "liblog.so")) return false;

    // 其他 so 都 hook
    return true;
}

bytehook_stub_t stub = nullptr; // hook 的存根，用于后续 unhook

void my_hook()
{
    stub = bytehook_hook_partial(
        my_allow_filter,
        nullptr,
        nullptr,
        "strlen",
        reinterpret_cast<void *>(my_strlen),
        nullptr,
        nullptr);
}
```

`my_allow_filter()` 回调中的 `caller_path_name` 参数，可能是 pathname，也可能是 basename。详见：[Native API 手册](native_manual.zh-CN.md)。

> 我怎么知道可以 hook 哪些函数？
>
> ByteHook 属于 PLT hook 的类型。也就是修改函数的调用方。（可以想象调用方 so 中保存了一张表（我们称为“导入表”），其中包含了当前 so 中要调用的所有外部函数的“名称”和“函数地址”，ByteHook 修改的就是这个“函数地址”的值） 
>
> 通过 NDK 中的 `readelf` 可以查看 so 中的导入表，其中列出的函数都是可以被 ByteHook hook 的。建议使用 `adb pull` 将设备上的 so 拿到本地，然后通过 `readelf` 结合 AOSP 源码来确认（注意某些符号的 Android 系统兼容性）。`readelf` 举例：

```
// arm32 动态库：
arm-linux-androideabi-readelf -rW ./libsample.so

// arm64 动态库：
aarch64-linux-android-readelf -rW ./libsample.so
```

### 编写 proxy 函数（代理函数）

举例，上面例子中的 `my_strlen()` 函数，对 `strlen()` 的调用将被 hook 到 `my_strlen()`：

```C++
// C++ 函数
size_t my_strlen(const char* const str)
{
    // 执行 stack 清理（不可省略）
    BYTEHOOK_STACK_SCOPE();

    // 在调用原函数之前，做点什么....
    __android_log_print(ANDROID_LOG_DEBUG, "tag", "pre strlen");

    // 调用原函数（也可以不调用）（一般在这里传入原参数，也可以根据需要改变参数）
    size_t result = BYTEHOOK_CALL_PREV(my_strlen, str);

    // 在调用原函数之后，做点什么....
    __android_log_print(ANDROID_LOG_DEBUG, "tag", "post strlen");

    // 返回原函数的返回值（当然，也可以返回其他的值）
    return result;
}
```

* 在 proxy 函数中可以不调用原函数，也可以通过 `BYTEHOOK_CALL_PREV` 宏来调用原函数，但请不要通过函数名来直接调用原函数。
* `BYTEHOOK_CALL_PREV` 宏在 C++ 源文件中的用法是：第一个参数传递当前的 proxy 函数名（上例中为 `my_strlen()`），后面按照顺序依次传递函数的各个参数。（`BYTEHOOK_CALL_PREV` 宏在 C 源文件中的用法稍有不同，详见：[Native API 手册](native_manual.zh-CN.md)）
* 每个 proxy 函数中都必须执行 ByteHook 的 stack 清理逻辑。有两种方式：

1. 在 C++ 代码中：在“proxy 函数”开头调用一次 `BYTEHOOK_STACK_SCOPE` 宏。（其中会通过析构函数的方式，来保证 stack 清理逻辑一定会被执行）
2. 在 C 代码中：请在“proxy 函数”的每一个“返回分支”末尾都调用 `BYTEHOOK_POP_STACK` 宏。例如：

```C
typedef size_t (*strlen_t)(const char* const);

// C 函数
size_t my_strlen(const char* const str)
{
    size_t result;

    if(0 == strcmp(str, "ignore"))
    {
        // 执行 stack 清理（不可省略）
        BYTEHOOK_POP_STACK();
        return 0;
    }

    result = BYTEHOOK_CALL_PREV(my_strlen, strlen_t, str);

    // 执行 stack 清理（不可省略）
    BYTEHOOK_POP_STACK();
    return result;
}
```

### unhook

如果需要 unhook，在前面调用 hook 函数时需要保存返回值（stub / 存根），在 unhook 的时候需要用到。举例：

```cpp
void my_unhook()
{
    bytehook_unhook(stub);

    // unhook 之后，请将 stub 置为 NULL。
    stub = nullptr;
}
```

unhook 之后，stub 不再有效，为避免在别处被误用，请将 stub 置为 `NULL`。

