cmake_minimum_required(VERSION 3.18.1)
project(bytehook)

enable_language(ASM)

file(GLOB SRC *.c)
add_library(bytehook SHARED ${SRC})
target_compile_features(bytehook PUBLIC c_std_11)
target_compile_options(bytehook PUBLIC -Weverything -Werror)
target_include_directories(bytehook PUBLIC . include)
target_link_libraries(bytehook log)

if(USEASAN)
    target_compile_options(bytehook PUBLIC -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(bytehook PUBLIC -fsanitize=address)
else()
    target_compile_options(bytehook PUBLIC -Oz -flto -ffunction-sections -fdata-sections)
    target_link_options(bytehook PUBLIC -Oz -flto -Wl,--exclude-libs,ALL -Wl,--gc-sections -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/bytehook.map.txt)
endif()
