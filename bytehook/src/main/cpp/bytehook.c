// Copyright (c) 2020-present, ByteDance, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Created by Kelun Cai (caikelun@bytedance.com) on 2020-06-02.

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include "bytehook.h"
#include "bh_core.h"
#include "bh_recorder.h"

int bytehook_init(int mode, bool debug)
{
    return bh_core_init(mode, debug);
}

bytehook_stub_t bytehook_hook_single(
    const char *caller_path_name,
    const char *callee_path_name,
    const char *sym_name,
    void *new_func,
    bytehook_hooked_t hooked,
    void *hooked_arg)
{
    const void *caller_addr = __builtin_return_address(0);
    return bh_core_hook_single(
        caller_path_name,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
        (uintptr_t)caller_addr);
}

bytehook_stub_t bytehook_hook_partial(
    bytehook_caller_allow_filter_t caller_allow_filter,
    void *caller_allow_filter_arg,
    const char *callee_path_name,
    const char *sym_name,
    void *new_func,
    bytehook_hooked_t hooked,
    void *hooked_arg)
{
    const void *caller_addr = __builtin_return_address(0);
    return bh_core_hook_partial(
        caller_allow_filter,
        caller_allow_filter_arg,
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
        (uintptr_t)caller_addr);
}

bytehook_stub_t bytehook_hook_all(
    const char *callee_path_name,
    const char *sym_name,
    void *new_func,
    bytehook_hooked_t hooked,
    void *hooked_arg)
{
    const void *caller_addr = __builtin_return_address(0);
    return bh_core_hook_all(
        callee_path_name,
        sym_name,
        new_func,
        hooked,
        hooked_arg,
        (uintptr_t)caller_addr);
}

int bytehook_unhook(bytehook_stub_t stub)
{
    const void *caller_addr = __builtin_return_address(0);
    return bh_core_unhook(stub, (uintptr_t)caller_addr);
}

void bytehook_set_debug(bool debug)
{
    bh_core_set_debug(debug);
}

char *bytehook_get_records(void)
{
    return bh_recorder_get();
}

void bytehook_dump_records(int fd)
{
    bh_recorder_dump(fd);
}

void *bytehook_get_prev_func(void *func)
{
    return bh_core_get_prev_func(func);
}

void *bytehook_get_return_address(void)
{
    return bh_core_get_return_address();
}

void bytehook_pop_stack(void *return_address)
{
    bh_core_pop_stack(return_address);
}

int bytehook_get_mode(void)
{
    return bh_core_get_mode();
}

void bytehook_add_dlopen_callback(bytehook_pre_dlopen_t pre, bytehook_post_dlopen_t post, void *data)
{
    bh_core_add_dlopen_callback(pre, post, data);
}

void bytehook_del_dlopen_callback(bytehook_pre_dlopen_t pre, bytehook_post_dlopen_t post, void *data)
{
    bh_core_del_dlopen_callback(pre, post, data);
}
