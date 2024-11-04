// Copyright (c) 2020-2024 ByteDance, Inc.
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

#include "bh_dl_iterate.h"

#include <android/api-level.h>
#include <ctype.h>
#include <dlfcn.h>
#include <elf.h>
#include <inttypes.h>
#include <link.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bh_const.h"
#include "bh_dl.h"
#include "bh_linker.h"
#include "bh_log.h"
#include "bh_util.h"

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
extern __attribute((weak)) unsigned long int getauxval(unsigned long int);

static uintptr_t bh_dl_iterate_get_min_vaddr(struct dl_phdr_info *info) {
  uintptr_t min_vaddr = UINTPTR_MAX;
  for (size_t i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *phdr = &(info->dlpi_phdr[i]);
    if (PT_LOAD == phdr->p_type) {
      if (min_vaddr > phdr->p_vaddr) min_vaddr = phdr->p_vaddr;
    }
  }
  return min_vaddr;
}

static int bh_dl_find_from_auxv(unsigned long type, const char *pathname, struct dl_phdr_info *info) {
  if (NULL == getauxval) return -1;  // API level < 18
  uintptr_t val = (uintptr_t)getauxval(type);
  if (0 == val) return -1;

  // get base
  uintptr_t base = (AT_PHDR == type ? (val & (~0xffful)) : val);
  if (0 != memcmp((void *)base, ELFMAG, SELFMAG)) return -1;

  // get ELF info
  ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base;
  info->dlpi_phdr = (const ElfW(Phdr) *)(base + ehdr->e_phoff);
  info->dlpi_phnum = ehdr->e_phnum;

  // get load_bias
  uintptr_t min_vaddr = bh_dl_iterate_get_min_vaddr(info);
  if (UINTPTR_MAX == min_vaddr || base < min_vaddr) return -1;
  info->dlpi_addr = base - min_vaddr;

  info->dlpi_name = pathname;
  return 0;
}

static int bh_dl_iterate_by_linker_cb(struct dl_phdr_info *info, size_t size, void *arg) {
  // ignore invalid ELF
  if (0 == info->dlpi_addr || NULL == info->dlpi_name || '\0' == info->dlpi_name[0]) return 0;

  uintptr_t *pkg = (uintptr_t *)arg;
  bh_dl_iterate_phdr_cb_t callback = (bh_dl_iterate_phdr_cb_t)*pkg++;
  void *data = (void *)*pkg++;
  uintptr_t linker_load_bias = *pkg++;
  uintptr_t app_process_load_bias = *pkg++;

  // ignore linker and app_process
  if (linker_load_bias == info->dlpi_addr || app_process_load_bias == info->dlpi_addr) return 0;

  // do callback
  return callback(info, size, data);
}

static int bh_dl_iterate_by_linker(bh_dl_iterate_phdr_cb_t callback, void *data) {
  BH_LOG_INFO("DL iterate: iterate by dl_iterate_phdr");
  if (NULL == dl_iterate_phdr) return -1;
  int r;

  // always get linker and app_process form auxv, and do callback
  struct dl_phdr_info info;
  uintptr_t linker_load_bias = UINTPTR_MAX;
  if (0 == bh_dl_find_from_auxv(AT_BASE, BH_CONST_PATHNAME_LINKER, &info)) {
    r = callback(&info, sizeof(struct dl_phdr_info), data);
    if (0 != r) return r;
    linker_load_bias = info.dlpi_addr;
  }
  uintptr_t app_process_load_bias = UINTPTR_MAX;
  if (0 == bh_dl_find_from_auxv(AT_PHDR, BH_CONST_PATHNAME_APP_PROCESS, &info)) {
    r = callback(&info, sizeof(struct dl_phdr_info), data);
    if (0 != r) return r;
    app_process_load_bias = info.dlpi_addr;
  }

  int api_level = bh_util_get_api_level();
  if (__ANDROID_API_L__ == api_level || __ANDROID_API_L_MR1__ == api_level) bh_linker_lock();
  uintptr_t pkg[4] = {(uintptr_t)callback, (uintptr_t)data, linker_load_bias, app_process_load_bias};
  r = dl_iterate_phdr(bh_dl_iterate_by_linker_cb, pkg);
  if (__ANDROID_API_L__ == api_level || __ANDROID_API_L_MR1__ == api_level) bh_linker_unlock();

  return r;
}

#if (defined(__arm__) || defined(__i386__)) && __ANDROID_API__ < __ANDROID_API_L__

static int bh_dl_iterate_by_maps(bh_dl_iterate_phdr_cb_t callback, void *data) {
  BH_LOG_INFO("DL iterate: iterate by maps");

  bh_linker_lock();

  FILE *maps = fopen("/proc/self/maps", "r");
  if (NULL == maps) goto end;

  char buf1[1024], buf2[1024];
  char *line = buf1;
  uintptr_t prev_base = 0;
  bool try_next_line = false;

  while (fgets(line, sizeof(buf1), maps)) {
    bh_util_trim_ending(line);
    // Parsing maps directly has too much uncertainty, so it needs to be strict.
    if (!bh_util_ends_with(line, BH_CONST_BASENAME_APP_PROCESS) && !bh_util_ends_with(line, ".so")) continue;

    uintptr_t base, offset;
    char exec;
    if (3 != sscanf(line, "%" SCNxPTR "-%*" SCNxPTR " r%*c%cp %" SCNxPTR " ", &base, &exec, &offset))
      goto clean;

    if ('-' == exec && 0 == offset) {
      // r--p
      prev_base = base;
      line = (line == buf1 ? buf2 : buf1);
      try_next_line = true;
      continue;
    } else if (exec == 'x') {
      // r-xp
      char *pathname = NULL;
      if (try_next_line && 0 != offset) {
        char *prev = (line == buf1 ? buf2 : buf1);
        char *prev_pathname = strchr(prev, '/');
        if (NULL == prev_pathname) goto clean;

        pathname = strchr(line, '/');
        if (NULL == pathname) goto clean;

        bh_util_trim_ending(prev_pathname);
        bh_util_trim_ending(pathname);
        if (0 != strcmp(prev_pathname, pathname)) goto clean;

        // we found the line with r-xp in the next line
        base = prev_base;
        offset = 0;
      }

      if (0 != offset) goto clean;

      // get pathname
      if (NULL == pathname) {
        pathname = strchr(line, '/');
        if (NULL == pathname) goto clean;
        bh_util_trim_ending(pathname);
      }

      if (0 != memcmp((void *)base, ELFMAG, SELFMAG)) goto clean;
      ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base;
      struct dl_phdr_info info;
      info.dlpi_name = pathname;
      info.dlpi_phdr = (const ElfW(Phdr) *)(base + ehdr->e_phoff);
      info.dlpi_phnum = ehdr->e_phnum;

      // get load bias
      uintptr_t min_vaddr = bh_dl_iterate_get_min_vaddr(&info);
      if (UINTPTR_MAX == min_vaddr) goto clean;
      info.dlpi_addr = (ElfW(Addr))(base - min_vaddr);

      // callback
      if (0 != callback(&info, sizeof(struct dl_phdr_info), data)) break;
    }

  clean:
    try_next_line = false;
  }

  fclose(maps);

end:
  bh_linker_unlock();
  return 0;
}

#endif

int bh_dl_iterate(bh_dl_iterate_phdr_cb_t callback, void *data) {
  // iterate by /proc/self/maps in Android 4.x (Android 4.x only supports arm32 and x86)
#if (defined(__arm__) || defined(__i386__)) && __ANDROID_API__ < __ANDROID_API_L__
  if (bh_util_get_api_level() < __ANDROID_API_L__) return bh_dl_iterate_by_maps(callback, data);
#endif

  // iterate by dl_iterate_phdr()
  return bh_dl_iterate_by_linker(callback, data);
}
