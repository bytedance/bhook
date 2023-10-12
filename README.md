# ByteHook

![](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)
![](https://img.shields.io/badge/release-1.0.9-red.svg?style=flat)
![](https://img.shields.io/badge/Android-4.1%20--%2014-blue.svg?style=flat)
![](https://img.shields.io/badge/arch-armeabi--v7a%20%7C%20arm64--v8a%20%7C%20x86%20%7C%20x86__64-blue.svg?style=flat)

[**简体中文**](README.zh-CN.md)

**ByteHook** is an Android PLT hook library which supports armeabi-v7a, arm64-v8a, x86 and x86_64.

ByteHook is now used in TikTok, Douyin, Toutiao, Xigua Video, Lark.

If you need an Android inline hook library, please move to [ShadowHook](https://github.com/bytedance/android-inline-hook).


## Features

* Support Android 4.1 - 14 (API level 16 - 34).
* Support armeabi-v7a, arm64-v8a, x86 and x86_64.
* Multiple hooks and unhooks for the same function do not conflict with each other.
* Hook a single, partial or all of the dynamic libraries in the process.
* Hook the newly loaded dynamic libraries automatically.
* Avoid recursive-calls and circular-calls between proxy functions automatically.
* Support unwinding backtrace in proxy function.
* MIT licensed.


## Documentation

[ByteHook Documentation](doc#readme)


## Quick Start

There is a sample app in the [bytehook-sample](bytehook_sample) you can refer to.

### 1. Add dependency in build.gradle

ByteHook is published on [Maven Central](https://search.maven.org/), and uses [Prefab](https://google.github.io/prefab/) package format for [native dependencies](https://developer.android.com/studio/build/native-dependencies), which is supported by [Android Gradle Plugin 4.0+](https://developer.android.com/studio/releases/gradle-plugin?buildsystem=cmake#native-dependencies).

```Gradle
android {
    buildFeatures {
        prefab true
    }
}

dependencies {
    implementation 'com.bytedance:bytehook:1.0.9'
}
```

**Note**: ByteHook uses the [prefab package schema v2](https://github.com/google/prefab/releases/tag/v2.0.0), which is configured by default since [Android Gradle Plugin 7.1.0](https://developer.android.com/studio/releases/gradle-plugin?buildsystem=cmake#7-1-0). If you are using Android Gradle Plugin earlier than 7.1.0, please add the following configuration to `gradle.properties`:

```
android.prefabVersion=2.0.0
```

### 2. Add dependency in CMakeLists.txt or Android.mk

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

### 3. Specify one or more ABI(s) you need

```Gradle
android {
    defaultConfig {
        ndk {
            abiFilters 'armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64'
        }
    }
}
```

### 4. Add packaging options

If you are using ByteHook in an SDK project, you may need to avoid packaging libbytehook.so into your AAR, so as not to encounter duplicate libbytehook.so file when packaging the app project.

```Gradle
android {
    packagingOptions {
        exclude '**/libbytehook.so'
    }
}
```

On the other hand, if you are using ByteHook in an APP project, you may need to add some options to deal with conflicts caused by duplicate libbytehook.so file.

```Gradle
android {
    packagingOptions {
        pickFirst '**/libbytehook.so'
    }
}
```

### 5. Initialize

```Java
import com.bytedance.android.bytehook.ByteHook;

public class MySdk {
    public static synchronized void init() {
        ByteHook.init();
    }
}
```

### 6. Hook and Unhook

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

These three hook functions are used to hook single, partial, and all caller dynamic libraries in the process.

Notice:

* If you need to call the original function in the proxy function, please always use the `BYTEHOOK_CALL_PREV()` macro.
* Make sure to call `BYTEHOOK_POP_STACK()` macro before proxy function returning. In the CPP source file, you can also call `BYTEHOOK_STACK_SCOPE()` macro at the beginning of the proxy function instead.


## Contributing

* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Contributing Guide](CONTRIBUTING.md)
* [Reporting Security vulnerabilities](SECURITY.md)


## License

ByteHook is licensed by [MIT License](LICENSE).

ByteHook uses the following third-party source code or libraries:

* [queue.h](bytehook/src/main/cpp/third_party/bsd/queue.h)  
  BSD 3-Clause License  
  Copyright (c) 1991, 1993 The Regents of the University of California.
* [tree.h](bytehook/src/main/cpp/third_party/bsd/tree.h)  
  BSD 2-Clause License  
  Copyright (c) 2002 Niels Provos <provos@citi.umich.edu>
* [linux-syscall-support](https://chromium.googlesource.com/linux-syscall-support/)  
  BSD 3-Clause License  
  Copyright (c) 2005-2011 Google Inc.
