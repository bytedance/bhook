cmake_minimum_required(VERSION 4.0.2)
project(systest)

if((${ANDROID_ABI} STREQUAL "arm64-v8a") OR (${ANDROID_ABI} STREQUAL "x86_64"))
    set(ARCH_LINK_FLAGS "-Wl,-z,max-page-size=16384")
else()
    set(ARCH_LINK_FLAGS "")
endif()

# bytehook
if(DEPENDENCY_ON_LOCAL_LIBRARY)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../../../bytehook/local_dependency.cmake)
else()
    find_package(bytehook REQUIRED CONFIG)
endif()

# libbytehooksystest.so
file(GLOB SYSTEST_SRC *.c)
add_library(bytehooksystest SHARED ${SYSTEST_SRC})
target_compile_features(bytehooksystest PRIVATE c_std_11)
target_compile_options(bytehooksystest PRIVATE -Weverything -Werror -Wno-unused-function -Wno-unused-macros)
target_include_directories(bytehooksystest PRIVATE .)
target_link_libraries(bytehooksystest log bytehook::bytehook)

if(DEPENDENCY_ON_LOCAL_LIBRARY)
    target_compile_options(bytehooksystest PRIVATE -DDEPENDENCY_ON_LOCAL_LIBRARY)
endif()

if(USEASAN)
    target_compile_options(bytehooksystest PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(bytehooksystest PRIVATE ${ARCH_LINK_FLAGS} -fsanitize=address)
else()
    target_compile_options(bytehooksystest PRIVATE -Os -ffunction-sections -fdata-sections)
    target_link_options(bytehooksystest PRIVATE ${ARCH_LINK_FLAGS} -Os -Wl,--exclude-libs,ALL -Wl,--gc-sections -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/systest.map.txt)
endif()
