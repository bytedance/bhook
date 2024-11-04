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

#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#include "queue.h"

typedef struct bh_trampo_page {
  uintptr_t ptr;
  uint32_t *flags;
  time_t *timestamps;
  SLIST_ENTRY(bh_trampo_page, ) link;
} bh_trampo_page_t;
typedef SLIST_HEAD(bh_trampo_page_list, bh_trampo_page, ) bh_trampo_page_list_t;

typedef struct bh_trampo_mgr {
  bh_trampo_page_list_t pages;
  pthread_mutex_t pages_lock;
  const char *page_name;
  size_t trampo_size;
  time_t delay_sec;
} bh_trampo_mgr_t;

void bh_trampo_init_mgr(bh_trampo_mgr_t *mgr, const char *page_name, size_t trampo_size, time_t delay_sec);

uintptr_t bh_trampo_alloc(bh_trampo_mgr_t *mgr);
void bh_trampo_free(bh_trampo_mgr_t *mgr, uintptr_t trampo);
