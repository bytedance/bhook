cmake_minimum_required(VERSION 3.18.1)
project(sample)

if(DEPENDENCY_ON_LOCAL_LIBRARY)
    set(BYTEHOOK_BASE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../bytehook)
    if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(BYTEHOOK_LIB_BASE ${BYTEHOOK_BASE}/build/intermediates/merged_native_libs/debug)
    else()
        set(BYTEHOOK_LIB_BASE ${BYTEHOOK_BASE}/build/intermediates/stripped_native_libs/release)
    endif()
    add_library(bytehook::bytehook SHARED IMPORTED)
    set_target_properties(bytehook::bytehook PROPERTIES
            IMPORTED_LOCATION ${BYTEHOOK_LIB_BASE}/out/lib/${ANDROID_ABI}/libbytehook.so
            INTERFACE_INCLUDE_DIRECTORIES ${BYTEHOOK_BASE}/src/main/cpp/include)
else()
    find_package(bytehook REQUIRED CONFIG)
endif()

# libhacker.so
add_library(hacker SHARED hacker.c)
target_compile_features(hacker PUBLIC c_std_11)
target_compile_options(hacker PUBLIC -Weverything -Werror)
target_link_libraries(hacker bytehook::bytehook log)

# libhookee.so
add_library(hookee SHARED hookee.c)
target_compile_features(hookee PUBLIC c_std_11)
target_compile_options(hookee PUBLIC -Weverything -Werror)
target_link_libraries(hookee log)
