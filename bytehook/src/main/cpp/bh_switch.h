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
#include <link.h>
#include <stdint.h>

#include "bh_array.h"
#include "bh_elf.h"
#include "bh_task.h"

typedef struct bh_switch_manager bh_switch_manager_t;

bh_switch_manager_t *bh_switch_manager_create(void);
void bh_switch_manager_destroy(bh_switch_manager_t *mgr);

int bh_switch_hook(bh_elf_t *elf, bh_task_t *task, ElfW(Sym) *sym, bh_array_t *gots, bh_array_t *prots,
                   uintptr_t new_addr, uintptr_t *orig_addr);
int bh_switch_unhook(bh_elf_t *elf, ElfW(Sym) *sym, bh_array_t *gots, bh_array_t *prots, uintptr_t new_addr);

int bh_switch_hook_invisible(bh_elf_t *elf, bh_task_t *task, ElfW(Sym) *sym, bh_array_t *gots,
                             bh_array_t *prots, uintptr_t new_addr, uintptr_t *orig_addr);
