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

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <android/api-level.h>
#include "bh_dl_iterate.h"
#include "bh_dl.h"
#include "bh_linker.h"
#include "bh_util.h"
#include "bh_const.h"
#include "bh_log.h"

/*
 * ====================================================================
 * API-LEVEL  ANDROID-VERSION  SOLUTION
 * ====================================================================
 * 16         4.1              /proc/self/maps
 * 17         4.2              /proc/self/maps
 * 18         4.3              /proc/self/maps
 * 19         4.4              /proc/self/maps
 * 20         4.4W             /proc/self/maps
 * --------------------------------------------------------------------
 * 21         5.0              dl_iterate_phdr() + __dl__ZL10g_dl_mutex
 * 22         5.1              dl_iterate_phdr() + __dl__ZL10g_dl_mutex
 * --------------------------------------------------------------------
 * >= 23      >= 6.0           dl_iterate_phdr()
 * ====================================================================
 */

extern __attribute((weak)) int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);

static int bh_dl_iterate_by_linker_cb(struct dl_phdr_info *info, size_t size, void *arg)
{
    // ignore invalid ELF
    if(0 == info->dlpi_addr || NULL == info->dlpi_name || '\0' == info->dlpi_name[0]) return 0;

    // callback
    uintptr_t *pkg = (uintptr_t *)arg;
    int (*callback)(struct dl_phdr_info *, size_t, void *) = (int (*)(struct dl_phdr_info *, size_t, void *))*pkg++;
    void *data = (void *)*pkg;
    return callback(info, size, data);
}

static int bh_dl_iterate_by_linker(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data)
{
    BH_LOG_INFO("DL iterate: iterate by dl_iterate_phdr");

    if(NULL == dl_iterate_phdr) return -1;

    int api_level = bh_util_get_api_level();

    if(__ANDROID_API_L__ == api_level || __ANDROID_API_L_MR1__ == api_level) bh_linker_lock();
    uintptr_t pkg[2] = {(uintptr_t)callback, (uintptr_t)data};
    dl_iterate_phdr(bh_dl_iterate_by_linker_cb, pkg);
    if(__ANDROID_API_L__ == api_level || __ANDROID_API_L_MR1__ == api_level) bh_linker_unlock();

    return 0;
}

#if (defined(__arm__) || defined(__i386__)) && __ANDROID_API__ < __ANDROID_API_L__

static uintptr_t bh_dl_iterate_get_min_vaddr(struct dl_phdr_info *info)
{
    uintptr_t min_vaddr = UINTPTR_MAX;
    for(size_t i = 0; i < info->dlpi_phnum; i++)
    {
        const ElfW(Phdr) *phdr = &(info->dlpi_phdr[i]);
        if(PT_LOAD == phdr->p_type)
        {
            if(min_vaddr > phdr->p_vaddr) min_vaddr = phdr->p_vaddr;
        }
    }
    return min_vaddr;
}

static int bh_dl_iterate_by_maps(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data)
{
    BH_LOG_INFO("DL iterate: iterate by maps");

    FILE *maps = fopen("/proc/self/maps", "r");
    if(NULL == maps) return 0;

    char line[1024];
    while(fgets(line, sizeof(line), maps))
    {
        // Try to find an ELF which loaded by linker. This is almost always correct in android 4.x.
        uintptr_t base, offset;
        if(2 != sscanf(line, "%"SCNxPTR"-%*"SCNxPTR" r-xp %"SCNxPTR" ", &base, &offset)) continue;
        if(0 != offset) continue;
        if(0 != memcmp((void *)base, ELFMAG, SELFMAG)) continue;

        // get pathname
        char *pathname = strchr(line, '/');
        if(NULL == pathname) break;
        bh_util_trim_ending(pathname);

        ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base;
        struct dl_phdr_info info;
        info.dlpi_name = pathname;
        info.dlpi_phdr = (const ElfW(Phdr) *)(base + ehdr->e_phoff);
        info.dlpi_phnum = ehdr->e_phnum;

        // get load bias
        uintptr_t min_vaddr = bh_dl_iterate_get_min_vaddr(&info);
        if(UINTPTR_MAX == min_vaddr) continue; // ignore invalid ELF
        info.dlpi_addr = (ElfW(Addr))(base - min_vaddr);

        // callback
        if(0 != callback(&info, sizeof(struct dl_phdr_info), data)) break;
    }

    fclose(maps);
    return 0;
}

#endif

int bh_dl_iterate(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data)
{
    // iterate by /proc/self/maps in Android 4.x (Android 4.x only supports arm32 and x86)
#if (defined(__arm__) || defined(__i386__)) && __ANDROID_API__ < __ANDROID_API_L__
    if(bh_util_get_api_level() < __ANDROID_API_L__)
        return bh_dl_iterate_by_maps(callback, data);
#endif

    // iterate by dl_iterate_phdr()
    return bh_dl_iterate_by_linker(callback, data);
}
