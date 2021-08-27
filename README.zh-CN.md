# ByteHook

![](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)
![](https://img.shields.io/badge/release-1.0.1-red.svg?style=flat)
![](https://img.shields.io/badge/Android-4.1%20--%2012-blue.svg?style=flat)
![](https://img.shields.io/badge/arch-armeabi--v7a%20%7C%20arm64--v8a%20%7C%20x86%20%7C%20x86__64-blue.svg?style=flat)

[README English Version](README.md)

ByteHook 是一个针对 Android app 的 PLT hook 框架。

字节跳动的大多数 Android app 在线上使用了 ByteHook 作为 PLT hook 方案。

> 如果你有任何 bug 报告，建议，或问题。请通过 GitHub [Issues](https://github.com/bytedance/bhook/issues) 或 [Discussions](https://github.com/bytedance/bhook/discussions) 和我们沟通。😀


## 特征

* 对同一个函数的多个 hook 和 unhook 互相不冲突。
* 可以 hook 进程中单个、部分或全部的动态库。
* 自动 hook 新加载的动态库。
* 自动避免代理函数之间的递归调用和环形调用。
* 代理函数中支持回溯调用栈。
* 支持 Android 4.1 - 12 (API level 16 - 31)。
* 支持 armeabi-v7a, arm64-v8a, x86 和 x86_64。
* 使用 MIT 许可证授权。


## 文档

[ByteHook Documentation](doc)


## 快速开始

你可以参考 [bytehook-sample](bytehook_sample) 中的示例 app。

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
    implementation 'com.bytedance:bytehook:1.0.1'
}
```

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

### 5. 初始化

```Java
import com.bytedance.android.bytehook.ByteHook;

public class MySdk {
    public static synchronized void init() {
        ByteHook.init();
    }
}
```

### 6. Hook 和 Unhook

```C
#include "bytehook.h"
```

```C
bytehook_stub_t bytehook_hook_single(
    const char *caller_path_name,
    const char *callee_path_name,
    const char *sym_name,
    void *new_func,
    bytehook_hooked_t hooked,
    void *hooked_arg);

bytehook_stub_t bytehook_hook_partial(
    bytehook_caller_allow_filter_t caller_allow_filter,
    void *caller_allow_filter_arg,
    const char *callee_path_name,
    const char *sym_name,
    void *new_func,
    bytehook_hooked_t hooked,
    void *hooked_arg);

bytehook_stub_t bytehook_hook_all(
    const char *callee_path_name,
    const char *sym_name,
    void *new_func,
    bytehook_hooked_t hooked,
    void *hooked_arg);

int bytehook_unhook(bytehook_stub_t stub);
```

这里的三个 hook 函数分别用于 hook 进程中的单个、部分和全部的调用者动态库。

注意：

* 如果需要在代理函数中调用原函数，请始终使用 `BYTEHOOK_CALL_PREV()` 宏来完成。
* 确保在代理函数返回前调用 `BYTEHOOK_POP_STACK()` 宏。在 CPP 源文件中，也可以改为在代理函数的开头调用 `BYTEHOOK_STACK_SCOPE()` 宏。


## 贡献

[ByteHook Contributing Guide](CONTRIBUTING.md)


## 许可证

[MIT License](LICENSE)
