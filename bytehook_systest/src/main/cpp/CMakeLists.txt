cmake_minimum_required(VERSION 3.30.5)
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
target_compile_features(bytehooksystest PUBLIC c_std_17)
target_compile_options(bytehooksystest PUBLIC -Weverything -Werror -Wno-unused-function -Wno-unused-macros)
target_include_directories(bytehooksystest PUBLIC .)
target_link_libraries(bytehooksystest log bytehook::bytehook)


if(DEPENDENCY_ON_LOCAL_LIBRARY)
    target_compile_options(bytehooksystest PUBLIC -DDEPENDENCY_ON_LOCAL_LIBRARY)
endif()

if(DEPENDENCY_ON_LOCAL_LIBRARY)
    target_compile_options(bytehooksystest PUBLIC -DDEPENDENCY_ON_LOCAL_LIBRARY)
endif()

if(USEASAN)
    target_compile_options(bytehooksystest PUBLIC -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(bytehooksystest PUBLIC ${ARCH_LINK_FLAGS} -fsanitize=address)
else()
    target_compile_options(bytehooksystest PUBLIC -Oz -ffunction-sections -fdata-sections)
    target_link_options(bytehooksystest PUBLIC ${ARCH_LINK_FLAGS} -Oz -Wl,--exclude-libs,ALL -Wl,--gc-sections -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/systest.map.txt)
endif()
