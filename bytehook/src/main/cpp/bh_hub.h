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

// Created by Li Zhang (zhangli.foxleezh@bytedance.com) on 2020-06-21.
// Refactored by Kelun Cai (caikelun@bytedance.com) on 2024-09-11.

#pragma once
#include <stdbool.h>
#include <stdint.h>

int bh_hub_init(void);

typedef struct bh_hub bh_hub_t;

bh_hub_t *bh_hub_create(uintptr_t *trampo);
void bh_hub_destroy(bh_hub_t *self, bool with_delay);

uintptr_t bh_hub_get_orig_addr(bh_hub_t *self);
uintptr_t *bh_hub_get_orig_addr_addr(bh_hub_t *self);

int bh_hub_add_proxy(bh_hub_t *self, uintptr_t proxy_func);
int bh_hub_del_proxy(bh_hub_t *self, uintptr_t proxy_func, bool *have_enabled_proxy);

void *bh_hub_get_prev_func(void *func);
void bh_hub_pop_stack(void *return_address);
void *bh_hub_get_return_address(void);
