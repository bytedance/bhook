cmake_minimum_required(VERSION 3.22.1)
project(sample)

find_package(bytehook REQUIRED CONFIG)

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
