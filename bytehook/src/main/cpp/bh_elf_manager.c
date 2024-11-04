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

#include "bh_elf_manager.h"

#include <android/api-level.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <link.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bh_const.h"
#include "bh_dl_iterate.h"
#include "bh_dl_monitor.h"
#include "bh_elf.h"
#include "bh_linker.h"
#include "bh_log.h"
#include "bh_util.h"
#include "queue.h"

#define BH_ELF_MANAGER_EXPIRED_S 30

// block list
typedef struct bh_elfs_block {
  char *caller_path_name;
  TAILQ_ENTRY(bh_elfs_block, ) link;
} bh_elfs_block_t;
typedef TAILQ_HEAD(bh_elfs_block_list, bh_elfs_block, ) bh_elfs_block_list_t;

// block list object
static bh_elfs_block_list_t bh_elfs_blocks = TAILQ_HEAD_INITIALIZER(bh_elfs_blocks);
static pthread_rwlock_t bh_elfs_blocks_lock = PTHREAD_RWLOCK_INITIALIZER;

// elf list object
static bh_elf_list_t bh_elfs = TAILQ_HEAD_INITIALIZER(bh_elfs);
static pthread_rwlock_t bh_elfs_lock = PTHREAD_RWLOCK_INITIALIZER;

int bh_elf_manager_add_ignore(const char *caller_path_name) {
  bh_elfs_block_t *block;
  if (NULL == (block = malloc(sizeof(bh_elfs_block_t)))) return -1;
  if (NULL == (block->caller_path_name = strdup(caller_path_name))) {
    free(block);
    return -1;
  }

  bh_elfs_block_t *tmp;
  pthread_rwlock_wrlock(&bh_elfs_blocks_lock);
  TAILQ_FOREACH(tmp, &bh_elfs_blocks, link) {
    if (0 == strcmp(tmp->caller_path_name, caller_path_name)) break;
  }
  if (NULL == tmp) {
    TAILQ_INSERT_TAIL(&bh_elfs_blocks, block, link);
    block = NULL;
  }
  pthread_rwlock_unlock(&bh_elfs_blocks_lock);

  if (NULL != block) {
    free(block->caller_path_name);
    free(block);
  }
  return 0;
}

static bool bh_elf_manager_check_ignore(const char *pathname) {
  bool need_to_be_ignore = false;

  pthread_rwlock_rdlock(&bh_elfs_blocks_lock);
  bh_elfs_block_t *block;
  TAILQ_FOREACH(block, &bh_elfs_blocks, link) {
    if (bh_linker_elf_is_match(pathname, block->caller_path_name)) {
      need_to_be_ignore = true;
      break;
    }
  }
  pthread_rwlock_unlock(&bh_elfs_blocks_lock);

  return need_to_be_ignore;
}

static bool bh_elf_manager_need_to_be_ignore(const char *pathname) {
  if (__predict_false('[' == pathname[0])) return true;
  if (__predict_false(bh_util_ends_with(pathname, BH_CONST_BASENAME_BYTEHOOK))) return true;
  if (__predict_false(bh_util_ends_with(pathname, BH_CONST_BASENAME_SHADOWHOOK))) return true;
  if (__predict_false(bh_util_ends_with(pathname, BH_CONST_BASENAME_SHADOWHOOK_NOTHING))) return true;
  if (__predict_false(bh_elf_manager_check_ignore(pathname))) return true;
  return false;
}

static int bh_elf_manager_iterate_cb(struct dl_phdr_info *info, size_t size, void *arg) {
  (void)size;
  bh_elf_list_t *new_elfs = (bh_elf_list_t *)arg;

  // ignore invalid or unwanted ELF
  if (bh_elf_manager_need_to_be_ignore(info->dlpi_name)) return 0;

  bh_elf_t *elf = NULL;
  TAILQ_FOREACH(elf, &bh_elfs, link_list) {
    if (0 == elf->abandoned_ts && elf->load_bias == info->dlpi_addr) break;
  }
  if (__predict_false(NULL == elf)) {
    // create new ELF object
    if (NULL != (elf = bh_elf_create(info))) {
      TAILQ_INSERT_TAIL(&bh_elfs, elf, link_list);
      if (NULL != new_elfs) {
        TAILQ_INSERT_TAIL(new_elfs, elf, link_list_new);
        bh_elf_increment_ref_count(elf);
      }
      BH_LOG_INFO("ELF manager: add %" BH_UTIL_PRIxADDR " %s", elf->load_bias, elf->pathname);
    }
  }

  // ELF object set exist
  if (NULL != elf) bh_elf_set_exist(elf);

  return 0;
}

void bh_elf_manager_refresh(bool sync_clean, bh_elf_manager_post_add_cb_t cb, void *cb_arg) {
  bh_elf_list_t new_elfs = TAILQ_HEAD_INITIALIZER(new_elfs);
  bh_elf_list_t expired_elfs = TAILQ_HEAD_INITIALIZER(expired_elfs);

  if (0 != pthread_rwlock_wrlock(&bh_elfs_lock)) return;

  // iterate ELFs
  bh_dl_iterate(bh_elf_manager_iterate_cb, NULL == cb ? NULL : (void *)(&new_elfs));

  struct timeval now;
  gettimeofday(&now, NULL);

  bh_elf_t *elf = NULL, *elf_tmp = NULL;
  TAILQ_FOREACH_SAFE(elf, &bh_elfs, link_list, elf_tmp) {
    if (0 == elf->abandoned_ts && !bh_elf_is_exist(elf)) {
      // (1) mark non-existent-ELFs as "abandoned"
      elf->abandoned_ts = now.tv_sec;
      BH_LOG_INFO("ELF manager: del %" BH_UTIL_PRIxADDR " %s", elf->load_bias, elf->pathname);
    } else if (sync_clean && elf->abandoned_ts > 0 &&
               now.tv_sec - elf->abandoned_ts > BH_ELF_MANAGER_EXPIRED_S && 0 == elf->ref_count) {
      // (2) pick expired-ELFs to another ELF-list (expired_elfs)
      TAILQ_REMOVE(&bh_elfs, elf, link_list);
      TAILQ_INSERT_TAIL(&expired_elfs, elf, link_list);
    }

    // waiting for the next round of checking existence
    bh_elf_unset_exist(elf);
  }

  // free all expired ELF objects
  if (sync_clean) {
    bh_elf_t *expired_elf;
    TAILQ_FOREACH_SAFE(expired_elf, &expired_elfs, link_list, elf_tmp) {
      TAILQ_REMOVE(&expired_elfs, expired_elf, link_list);
      BH_LOG_INFO("ELF manager: destroy %" BH_UTIL_PRIxADDR " %s", expired_elf->load_bias,
                  expired_elf->pathname);
      bh_elf_destroy(&expired_elf);
    }
  }

  pthread_rwlock_unlock(&bh_elfs_lock);

  // do callback for newborn ELFs (no need to lock)
  if (NULL != cb) {
    bh_elf_t *new_elf;
    TAILQ_FOREACH(new_elf, &new_elfs, link_list_new) {
      cb(new_elf, cb_arg);
    }
  }
}

static bh_elf_t *bh_elf_manager_iterate_next(bh_elf_t *elf) {
  pthread_rwlock_rdlock(&bh_elfs_lock);
  elf = __predict_false(NULL == elf) ? TAILQ_FIRST(&bh_elfs) : TAILQ_NEXT(elf, link_list);
  while (NULL != elf && (elf->abandoned_ts > 0 || elf->error)) elf = TAILQ_NEXT(elf, link_list);
  if (__predict_true(NULL != elf)) bh_elf_increment_ref_count(elf);
  pthread_rwlock_unlock(&bh_elfs_lock);
  return elf;
}

void bh_elf_manager_iterate(bh_elf_manager_iterate_cb_t cb, void *cb_arg) {
  bh_elf_t *elf = NULL;
  while (NULL != (elf = bh_elf_manager_iterate_next(elf))) {
    cb(elf, cb_arg);
    bh_elf_decrement_ref_count(elf);
  }
}

bh_elf_t *bh_elf_manager_find_elf(const char *pathname) {
  bh_elf_t *elf = NULL;

  pthread_rwlock_rdlock(&bh_elfs_lock);
  TAILQ_FOREACH(elf, &bh_elfs, link_list) {
    if (0 == elf->abandoned_ts && !elf->error && bh_elf_is_match(elf, pathname)) break;
  }
  if (NULL != elf) bh_elf_increment_ref_count(elf);
  pthread_rwlock_unlock(&bh_elfs_lock);

  return elf;
}

void *bh_elf_manager_find_export_addr(const char *pathname, const char *sym_name) {
  bh_elf_t *elf = bh_elf_manager_find_elf(pathname);
  if (NULL == elf) return NULL;

  void *addr = bh_elf_find_export_func_addr_by_symbol_name(elf, sym_name);
  bh_elf_decrement_ref_count(elf);
  return addr;
}

static bh_elf_t *bh_elf_manager_add_impl(struct dl_phdr_info *info, bool increment_ref_count) {
  // ignore invalid or unwanted ELF
  if (bh_elf_manager_need_to_be_ignore(info->dlpi_name)) return NULL;

  // create new ELF
  bh_elf_t *elf = bh_elf_create(info);
  if (__predict_false(NULL == elf)) return NULL;
  if (increment_ref_count) bh_elf_increment_ref_count(elf);

  // insert new ELF to ELF-list
  bool exists = false;
  if (__predict_false(0 != pthread_rwlock_wrlock(&bh_elfs_lock))) goto err;
  bh_elf_t *elf_tmp;
  TAILQ_FOREACH(elf_tmp, &bh_elfs, link_list) {
    if (0 == elf_tmp->abandoned_ts && elf_tmp->load_bias == info->dlpi_addr) {
      exists = true;
      break;
    }
  }
  if (__predict_true(!exists)) TAILQ_INSERT_TAIL(&bh_elfs, elf, link_list);
  pthread_rwlock_unlock(&bh_elfs_lock);
  if (__predict_false(exists)) goto err;

  BH_LOG_INFO("ELF manager: add %" BH_UTIL_PRIxADDR " %s", elf->load_bias, elf->pathname);
  return elf;

err:
  bh_elf_destroy(&elf);
  return NULL;
}

static int bh_elf_manager_load_iterate_cb(struct dl_phdr_info *info, size_t size, void *arg) {
  (void)size, (void)arg;
  bh_elf_manager_add_impl(info, false);
  return 0;
}

void bh_elf_manager_load(void) {
  bh_dl_iterate(bh_elf_manager_load_iterate_cb, NULL);
}

bh_elf_t *bh_elf_manager_add(struct dl_phdr_info *info) {
  return bh_elf_manager_add_impl(info, true);
}

void bh_elf_manager_del(struct dl_phdr_info *info) {
  bh_elf_list_t expired_elfs = TAILQ_HEAD_INITIALIZER(expired_elfs);
  struct timeval now;
  gettimeofday(&now, NULL);

  // iterate ELF-list
  bh_elf_t *elf = NULL, *elf_tmp = NULL, *target_elf = NULL;
  if (__predict_false(0 != pthread_rwlock_wrlock(&bh_elfs_lock))) return;
  TAILQ_FOREACH_SAFE(elf, &bh_elfs, link_list, elf_tmp) {
    if (0 == elf->abandoned_ts && elf->load_bias == info->dlpi_addr) {
      // (1) mark the target-ELF as "abandoned"
      elf->abandoned_ts = now.tv_sec;
      BH_LOG_INFO("ELF manager: del %" BH_UTIL_PRIxADDR " %s", elf->load_bias, elf->pathname);
      target_elf = elf;
    } else if (elf->abandoned_ts > 0 && now.tv_sec - elf->abandoned_ts > BH_ELF_MANAGER_EXPIRED_S &&
               0 == elf->ref_count) {
      // (2) pick expired-ELFs to another ELF-list (expired_elfs)
      TAILQ_REMOVE(&bh_elfs, elf, link_list);
      TAILQ_INSERT_TAIL(&expired_elfs, elf, link_list);
    }
  }
  pthread_rwlock_unlock(&bh_elfs_lock);

  // free all expired ELF objects
  bh_elf_t *expired_elf;
  TAILQ_FOREACH_SAFE(expired_elf, &expired_elfs, link_list, elf_tmp) {
    TAILQ_REMOVE(&expired_elfs, expired_elf, link_list);
    BH_LOG_INFO("ELF manager: destroy %" BH_UTIL_PRIxADDR " %s", expired_elf->load_bias,
                expired_elf->pathname);
    bh_elf_destroy(&expired_elf);
  }

  // wait for target-ELF's all references (for hook or unhook) to be released
  if (__predict_true(NULL != target_elf)) {
    pthread_mutex_lock(&target_elf->ref_mutex);
    __atomic_fetch_add(&target_elf->waiter_count, 1, __ATOMIC_RELAXED);
    int ref_count;
    while ((ref_count = __atomic_load_n(&target_elf->ref_count, __ATOMIC_RELAXED)) > 0) {
      BH_LOG_INFO("ELF manager: del, wait cond signal, ref_count: %d", ref_count);
      pthread_cond_wait(&(target_elf->ref_cond), &(target_elf->ref_mutex));
    }
    __atomic_fetch_sub(&target_elf->waiter_count, 1, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&target_elf->ref_mutex);
  }
}
