cmake_minimum_required(VERSION 3.30.5)
if((${ANDROID_ABI} STREQUAL "arm64-v8a") OR (${ANDROID_ABI} STREQUAL "x86_64") OR (${ANDROID_ABI} STREQUAL "riscv64"))
    set(ARCH_LINK_FLAGS "-Wl,-z,max-page-size=16384")
else()
    set(ARCH_LINK_FLAGS "")
endif()

string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_DIRNAME)
if(${BUILD_TYPE_DIRNAME} STREQUAL "relwithdebinfo")
    set(BUILD_TYPE_DIRNAME "release")
endif()

# bytehook
if(DEPENDENCY_ON_LOCAL_LIBRARY)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../../../bytehook/local_dependency.cmake)
else()
    find_package(bytehook REQUIRED CONFIG)
endif()

# libhacker.so
add_library(hacker SHARED hacker.c hacker_bytehook.cpp)
target_compile_features(hacker PUBLIC c_std_17 cxx_std_17)
target_compile_options(hacker PUBLIC -Weverything -Werror -Wno-c++98-compat-pedantic -Wno-zero-as-null-pointer-constant -Wno-old-style-cast)
target_include_directories(hacker PUBLIC .)
set_target_properties(hacker PROPERTIES LINK_FLAGS "${ARCH_LINK_FLAGS}")
target_link_libraries(hacker log bytehook::bytehook)

# libsample.so
add_library(sample SHARED sample.c)
target_compile_features(sample PUBLIC c_std_17)
target_compile_options(sample PUBLIC -Weverything -Werror)
target_include_directories(hacker PUBLIC .)
set_target_properties(sample PROPERTIES LINK_FLAGS "${ARCH_LINK_FLAGS}")
target_link_libraries(sample log)
