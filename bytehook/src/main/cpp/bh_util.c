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

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <android/api-level.h>
#include "bh_util.h"

#define PAGE_START(addr) ((addr) & (uintptr_t)PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr + sizeof(uintptr_t) - 1) + PAGE_SIZE)
#define PAGE_COVER(addr) (PAGE_END(addr) - PAGE_START(addr))

int bh_util_set_addr_protect(void *addr, int prot)
{
    if(0 != mprotect((void *)PAGE_START((uintptr_t)addr), PAGE_COVER((uintptr_t)addr), prot)) return -1;

    return 0;
}

bool bh_util_starts_with(const char *str, const char* start)
{
    while(*str && *str == *start)
    {
        str++;
        start++;
    }

    return '\0' == *start;
}

bool bh_util_ends_with(const char* str, const char* ending)
{
    size_t str_len = strlen(str);
    size_t ending_len = strlen(ending);

    if(ending_len > str_len) return 0;

    return 0 == strcmp(str + (str_len - ending_len), ending) ? true : false;
}

size_t bh_util_trim_ending(char *start)
{
    char *end = start + strlen(start);
    while(start < end && isspace((int)(*(end - 1))))
    {
        end--;
        *end = '\0';
    }
    return (size_t)(end - start);
}

static int bh_util_get_api_level_from_build_prop(void)
{
    char buf[128];
    int api_level = -1;

    FILE *fp = fopen("/system/build.prop", "r");
    if(NULL == fp) goto end;

    while(fgets(buf, sizeof(buf), fp))
    {
        if(bh_util_starts_with(buf, "ro.build.version.sdk="))
        {
            api_level = atoi(buf + 21);
            break;
        }
    }
    fclose(fp);

 end:
    return (api_level > 0) ? api_level : -1;
}

int bh_util_get_api_level(void)
{
    static int bh_util_api_level = -1;

    if(bh_util_api_level < 0)
    {
        int api_level = android_get_device_api_level();
        if(api_level < 0)
            api_level = bh_util_get_api_level_from_build_prop(); // compatible with unusual models
        if(api_level < __ANDROID_API_J__)
            api_level = __ANDROID_API_J__;

        __atomic_store_n(&bh_util_api_level, api_level, __ATOMIC_SEQ_CST);
    }

    return bh_util_api_level;
}
