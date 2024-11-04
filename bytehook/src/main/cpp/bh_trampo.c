// Copyright (c) 2020-2024 ByteDance Inc.
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

// Created by Kelun Cai (caikelun@bytedance.com) on 2024-09-11.

#include "bh_trampo.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/time.h>

#include "bh_util.h"
#include "queue.h"

#define BH_TRAMPO_ALIGN 4

void bh_trampo_init_mgr(bh_trampo_mgr_t *mgr, const char *page_name, size_t trampo_size, time_t delay_sec) {
  SLIST_INIT(&mgr->pages);
  pthread_mutex_init(&mgr->pages_lock, NULL);
  mgr->page_name = page_name;
  mgr->trampo_size = BH_UTIL_ALIGN_END(trampo_size, BH_TRAMPO_ALIGN);
  mgr->delay_sec = delay_sec;
}

uintptr_t bh_trampo_alloc(bh_trampo_mgr_t *mgr) {
  uintptr_t trampo = 0;
  uintptr_t new_ptr;
  uintptr_t new_ptr_prctl = (uintptr_t)MAP_FAILED;
  size_t trampo_page_size = bh_util_get_page_size();
  size_t count = trampo_page_size / mgr->trampo_size;

  struct timeval now;
  if (mgr->delay_sec > 0) gettimeofday(&now, NULL);

  pthread_mutex_lock(&mgr->pages_lock);

  // try to find an unused trampo
  bh_trampo_page_t *page;
  SLIST_FOREACH(page, &mgr->pages, link) {
    for (uintptr_t i = 0; i < count; i++) {
      size_t flags_idx = i / 32;
      uint32_t mask = (uint32_t)1 << (i % 32);
      if (0 == (page->flags[flags_idx] & mask))  // check flag
      {
        // check timestamp
        if (mgr->delay_sec > 0 &&
            (now.tv_sec <= page->timestamps[i] || now.tv_sec - page->timestamps[i] <= mgr->delay_sec))
          continue;

        // OK
        page->flags[flags_idx] |= mask;
        trampo = page->ptr + (mgr->trampo_size * i);
        memset((void *)trampo, 0, mgr->trampo_size);
        goto end;
      }
    }
  }

  // alloc a new memory page
  new_ptr = (uintptr_t)(mmap(NULL, trampo_page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if ((uintptr_t)MAP_FAILED == new_ptr) goto err;
  new_ptr_prctl = new_ptr;

  // create a new trampo-page info
  if (NULL == (page = calloc(1, sizeof(bh_trampo_page_t)))) goto err;
  memset((void *)new_ptr, 0, trampo_page_size);
  page->ptr = new_ptr;
  new_ptr = (uintptr_t)MAP_FAILED;
  if (NULL == (page->flags = calloc(1, BH_UTIL_ALIGN_END(count, 32) / 8))) goto err;
  page->timestamps = NULL;
  if (mgr->delay_sec > 0) {
    if (NULL == (page->timestamps = calloc(1, count * sizeof(time_t)))) goto err;
  }
  SLIST_INSERT_HEAD(&mgr->pages, page, link);

  // alloc trampo from the new memory page
  page->flags[0] |= (uint32_t)1;
  trampo = page->ptr;

end:
  pthread_mutex_unlock(&mgr->pages_lock);
  if ((uintptr_t)MAP_FAILED != new_ptr_prctl)
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, new_ptr_prctl, trampo_page_size, mgr->page_name);
  return trampo;

err:
  pthread_mutex_unlock(&mgr->pages_lock);
  if (NULL != page) {
    if (0 != page->ptr) munmap((void *)page->ptr, trampo_page_size);
    if (NULL != page->flags) free(page->flags);
    if (NULL != page->timestamps) free(page->timestamps);
    free(page);
  }
  if ((uintptr_t)MAP_FAILED != new_ptr) munmap((void *)new_ptr, trampo_page_size);
  return 0;
}

void bh_trampo_free(bh_trampo_mgr_t *mgr, uintptr_t trampo) {
  struct timeval now;
  if (mgr->delay_sec > 0) gettimeofday(&now, NULL);

  pthread_mutex_lock(&mgr->pages_lock);

  size_t trampo_page_size = bh_util_get_page_size();
  bh_trampo_page_t *page;
  SLIST_FOREACH(page, &mgr->pages, link) {
    if (page->ptr <= trampo && trampo < page->ptr + trampo_page_size) {
      uintptr_t i = (trampo - page->ptr) / mgr->trampo_size;
      size_t flags_idx = i / 32;
      uint32_t mask = (uint32_t)1 << (i % 32);
      if (mgr->delay_sec > 0) page->timestamps[i] = now.tv_sec;
      page->flags[flags_idx] &= ~mask;
      break;
    }
  }

  pthread_mutex_unlock(&mgr->pages_lock);
}
