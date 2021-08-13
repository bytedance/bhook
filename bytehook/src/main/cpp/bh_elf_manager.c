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
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <pthread.h>
#include <android/api-level.h>
#include "tree.h"
#include "bh_elf_manager.h"
#include "bh_elf.h"
#include "bh_linker.h"
#include "bh_dl_iterate.h"
#include "bh_util.h"
#include "bh_const.h"
#include "bh_log.h"
#include "bh_dl_monitor.h"

// RB-tree for ELF info (bh_elf_t)
static __inline__ int bh_elf_cmp(bh_elf_t *a, bh_elf_t *b)
{
    return strcmp(a->pathname, b->pathname);
}
typedef RB_HEAD(bh_elf_tree, bh_elf) bh_elf_tree_t;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
RB_GENERATE_STATIC(bh_elf_tree, bh_elf, link, bh_elf_cmp)
#pragma clang diagnostic pop

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
struct bh_elf_manager
{
    bool             contain_pathname;
    bool             contain_basename;
    bh_elf_tree_t    elfs;
    size_t           elfs_cnt;
    bh_elf_list_t    abandoned_elfs;
    pthread_rwlock_t elfs_lock;
};
#pragma clang diagnostic pop

bh_elf_manager_t *bh_elf_manager_create(void)
{
    bh_elf_manager_t *self;
    if(NULL == (self = malloc(sizeof(bh_elf_manager_t)))) return NULL;
    self->contain_pathname = false;
    self->contain_basename = false;
    RB_INIT(&self->elfs);
    self->elfs_cnt = 0;
    TAILQ_INIT(&self->abandoned_elfs);
    pthread_rwlock_init(&self->elfs_lock, NULL);

    return self;
}

static int bh_elf_manager_iterate_cb(struct dl_phdr_info *info, size_t size, void *arg)
{
    (void)size;

    uintptr_t *pkg = (uintptr_t *)arg;
    bh_elf_manager_t *self = (bh_elf_manager_t *)*pkg++;
    uintptr_t val = *pkg++;
    bool clean = (1 == val ? true : false);
    bh_elf_list_t *new_elfs = (bh_elf_list_t *)*pkg;

    // ignore invalid or unwanted ELF
    if(bh_util_ends_with(info->dlpi_name, BH_CONST_BASENAME_BYTEHOOK)) return 0;
    if(!bh_util_ends_with(info->dlpi_name, BH_CONST_BASENAME_APP_PROCESS) && !bh_util_ends_with(info->dlpi_name, ".so")) return 0;

    bh_elf_t elf_key = {.pathname = info->dlpi_name};
    bh_elf_t *elf = RB_FIND(bh_elf_tree, &self->elfs, &elf_key);
    if(NULL == elf)
    {
        // create new ELF object
        if(NULL != (elf = bh_elf_create(info)))
        {
            RB_INSERT(bh_elf_tree, &self->elfs, elf);
            self->elfs_cnt++;

            if(NULL != new_elfs) TAILQ_INSERT_TAIL(new_elfs, elf, link_list);

            if((!self->contain_pathname) && ('/' == info->dlpi_name[0])) self->contain_pathname = true;
            if((!self->contain_basename) && ('/' != info->dlpi_name[0])) self->contain_basename = true;

            BH_LOG_INFO("ELF manager: add %"BH_UTIL_PRIxADDR" %s", elf->load_bias, elf->pathname);
        }
    }

    // ELF object set exist
    if(NULL != elf && clean) bh_elf_set_exist(elf);

    return 0;
}

void bh_elf_manager_refresh(bh_elf_manager_t *self, bool clean, bh_elf_manager_post_add_cb_t cb, void *cb_arg)
{
    bh_elf_list_t new_elfs = TAILQ_HEAD_INITIALIZER(new_elfs);

    uintptr_t pkg[3];
    pkg[0] = (uintptr_t)self;
    pkg[1] = clean ? 1 : 0;
    pkg[2] = (NULL == cb ? (uintptr_t)NULL : (uintptr_t)(&new_elfs));

    // lock ELFs-tree
    if(0 != pthread_rwlock_wrlock(&self->elfs_lock)) return;

    // iterate ELFs
    bh_dl_iterate(bh_elf_manager_iterate_cb, (void *)pkg);

    bh_elf_t *elf, *elf_tmp;
    if(clean)
    {
        // remove and destroy all ELF which not exist in linker's solist
        RB_FOREACH_SAFE(elf, bh_elf_tree, &self->elfs, elf_tmp)
        {
            if(!bh_elf_is_exist(elf))
            {
                RB_REMOVE(bh_elf_tree, &self->elfs, elf);
                self->elfs_cnt--;
                bh_elf_destroy(&elf);
            }
            else
            {
                // waiting for the next round of checking existence
                bh_elf_unset_exist(elf);
            }
        }
    }

    // unlock ELFs-tree
    pthread_rwlock_unlock(&self->elfs_lock);

    // do callback for newborn ELFs (no need to lock)
    if(NULL != cb)
    {
        TAILQ_FOREACH_SAFE(elf, &new_elfs, link_list, elf_tmp)
        {
            TAILQ_REMOVE(&new_elfs, elf, link_list);
            cb(elf, cb_arg);
        }
    }
}

void bh_elf_manager_iterate(bh_elf_manager_t *self, bh_elf_manager_iterate_cb_t cb, void *cb_arg)
{
    if(0 == self->elfs_cnt) return;

    // get a copy of ELFs (only the pointers)
    bh_elf_t **copy_elfs = NULL;
    size_t copy_elfs_cnt = 0;
    pthread_rwlock_rdlock(&self->elfs_lock);
    if(self->elfs_cnt > 0)
    {
        if(NULL != (copy_elfs = malloc(sizeof(bh_elf_t *) * self->elfs_cnt)))
        {
            copy_elfs_cnt = self->elfs_cnt;
            size_t i = 0;
            bh_elf_t *elf;
            RB_FOREACH(elf, bh_elf_tree, &self->elfs)
            {
                copy_elfs[i++] = elf;
                // memory overflow
                if(i > copy_elfs_cnt)
                {
                    assert(0);
                    goto err;
                }
            }
            // ELF dirty count
            if(i != copy_elfs_cnt)
            {
                assert(0);
                goto err;
            }
        }
    }
    pthread_rwlock_unlock(&self->elfs_lock);

    // do callback copy ELFs (no need to lock)
    if(NULL != copy_elfs)
    {
        bool cb_next = true;
        for(size_t i = 0; i < copy_elfs_cnt; i++)
        {
            if(cb_next) cb_next = cb(copy_elfs[i], cb_arg);
        }
        free(copy_elfs);
    }

    return;
    
err:
    pthread_rwlock_unlock(&self->elfs_lock);
    free(copy_elfs);
}

bh_elf_t *bh_elf_manager_find_elf(bh_elf_manager_t *self, const char *pathname)
{
    bh_elf_t *elf = NULL;

    pthread_rwlock_rdlock(&self->elfs_lock);

    if(('/' == pathname[0] && self->contain_pathname && !self->contain_basename) ||
       ('/' != pathname[0] && self->contain_basename && !self->contain_pathname))
    {
        bh_elf_t elf_key = {.pathname = pathname};
        elf = RB_FIND(bh_elf_tree, &self->elfs, &elf_key);
    }
    else
    {
        RB_FOREACH(elf, bh_elf_tree, &self->elfs)
            if(bh_elf_is_match(elf, pathname))
                break;
    }

    pthread_rwlock_unlock(&self->elfs_lock);

    return elf;
}

void *bh_elf_manager_find_export_addr(bh_elf_manager_t *self, const char *pathname, const char *sym_name)
{
    bh_elf_t *elf = bh_elf_manager_find_elf(self, pathname);
    if(NULL == elf) return NULL;

    return bh_elf_find_export_func_addr_by_symbol_name(elf, sym_name);
}
