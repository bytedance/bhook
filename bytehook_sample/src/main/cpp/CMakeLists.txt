cmake_minimum_required(VERSION 3.18.1)
project(sample)

if(DEPENDENCY_ON_LOCAL_LIBRARY)
    # import bytehook from local-project
    string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_DIRNAME)
    if(${BUILD_TYPE_DIRNAME} STREQUAL "relwithdebinfo")
        set(BUILD_TYPE_DIRNAME "release")
    endif()
    set(BYTEHOOK_BASE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../bytehook)
    add_library(bytehook::bytehook SHARED IMPORTED)
    set_target_properties(bytehook::bytehook PROPERTIES
            IMPORTED_LOCATION ${BYTEHOOK_BASE}/build/intermediates/stripped_native_libs/${BUILD_TYPE_DIRNAME}/out/lib/${ANDROID_ABI}/libbytehook.so
            INTERFACE_INCLUDE_DIRECTORIES ${BYTEHOOK_BASE}/src/main/cpp/include)
else()
    # import bytehook from maven
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
