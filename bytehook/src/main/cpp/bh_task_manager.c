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

#include "bh_task_manager.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "bh_dl_monitor.h"
#include "bh_elf_manager.h"
#include "bh_linker.h"
#include "bh_log.h"
#include "bh_switch.h"
#include "bh_task.h"
#include "bh_util.h"
#include "queue.h"
#if defined(__arm__) || defined(__aarch64__)
#include "shadowhook.h"
#endif

typedef TAILQ_HEAD(bh_task_queue, bh_task, ) bh_task_queue_t;

static bh_task_queue_t bh_tasks = TAILQ_HEAD_INITIALIZER(bh_tasks);
static pthread_rwlock_t bh_tasks_lock = PTHREAD_RWLOCK_INITIALIZER;

void bh_task_manager_add(bh_task_t *task) {
  pthread_rwlock_wrlock(&bh_tasks_lock);
  TAILQ_INSERT_TAIL(&bh_tasks, task, link);
  pthread_rwlock_unlock(&bh_tasks_lock);
}

void bh_task_manager_del(bh_task_t *task) {
  pthread_rwlock_wrlock(&bh_tasks_lock);
  TAILQ_REMOVE(&bh_tasks, task, link);
  pthread_rwlock_unlock(&bh_tasks_lock);
}

static void bh_task_manager_hook_elf(bh_elf_t *elf) {
  BH_LOG_INFO("task manager: try hook in new ELF: %s", elf->pathname);
  pthread_rwlock_rdlock(&bh_tasks_lock);
  bh_task_t *task;
  TAILQ_FOREACH(task, &bh_tasks, link) {
    bh_task_hook_elf(task, elf);
  }
  pthread_rwlock_unlock(&bh_tasks_lock);
}

#if BH_LINKER_MAYBE_NOT_SUPPORT_DL_INIT_FINI_MONITOR
static void bh_task_manager_post_new_elf(bh_elf_t *elf, void *arg) {
  (void)arg;
  bh_task_manager_hook_elf(elf);
}

static void bh_task_manager_post_dlopen(void *arg) {
  BH_LOG_INFO("task manager: post dlopen() OK");

  bh_dl_monitor_dlclose_rdlock();
  bh_elf_manager_refresh(false, bh_task_manager_post_new_elf, arg);
  bh_dl_monitor_dlclose_unlock();
}

static void bh_task_manager_post_dlclose(bool sync_refresh, void *arg) {
  (void)arg;
  BH_LOG_INFO("task manager: post dlclose() OK, sync_refresh: %d", sync_refresh);

  if (sync_refresh) {
    // in the range of dl_monitor's write-lock
    bh_elf_manager_refresh(true, NULL, NULL);
  } else {
    bh_dl_monitor_dlclose_rdlock();
    bh_elf_manager_refresh(false, NULL, NULL);
    bh_dl_monitor_dlclose_unlock();
  }
}

static int bh_task_manager_init_dl_open_close_monitor(void) {
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  static bool inited = false;
  static bool inited_ok = false;
  static bool initing = false;

  if (inited || initing) return (inited_ok || initing) ? 0 : -1;  // Do not repeat the initialization.

  pthread_mutex_lock(&lock);
  if (!inited) {
    inited = true;
    initing = true;
    bh_elf_manager_load();
    bh_dl_monitor_set_post_dlopen(bh_task_manager_post_dlopen, NULL);
    bh_dl_monitor_set_post_dlclose(bh_task_manager_post_dlclose, NULL);
    if (0 == bh_dl_monitor_init()) inited_ok = true;
    initing = false;
  }
  pthread_mutex_unlock(&lock);
  return inited_ok ? 0 : -1;
}
#endif

#if BH_LINKER_MAYBE_SUPPORT_DL_INIT_FINI_MONITOR
static void bh_task_manager_dl_init_pre(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size, (void)data;
  BH_LOG_INFO("task manager: dl_init, load_bias %" PRIxPTR ", %s", (uintptr_t)info->dlpi_addr,
              info->dlpi_name);
  bh_elf_t *elf = bh_elf_manager_add(info);
  if (NULL != elf) {
    bh_task_manager_hook_elf(elf);
    bh_elf_decrement_ref_count(elf);
  }
}

static void bh_task_manager_dl_fini_post(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size, (void)data;
  BH_LOG_INFO("task manager: dl_fini, load_bias %" PRIxPTR ", %s", (uintptr_t)info->dlpi_addr,
              info->dlpi_name);

  // free ELF, switch(es), hub(s)
  bh_elf_manager_del(info);

  // reset "status flag" for finished single-type task
  pthread_rwlock_rdlock(&bh_tasks_lock);
  bh_task_t *task;
  TAILQ_FOREACH(task, &bh_tasks, link) {
    if (BH_TASK_TYPE_SINGLE == task->type && BH_TASK_STATUS_FINISHED == task->status && !task->is_invisible &&
        0 != task->caller_load_bias && info->dlpi_addr == task->caller_load_bias) {
      task->caller_load_bias = 0;
      task->status_code = BYTEHOOK_STATUS_CODE_MAX;
      task->status = BH_TASK_STATUS_UNFINISHED;
      BH_LOG_INFO("task manager: reset finished flag for: caller_path_name %s, sym_name %s",
                  task->caller_path_name, task->sym_name);
    }
  }
  pthread_rwlock_unlock(&bh_tasks_lock);
}

static int bh_task_manager_init_dl_init_fini_monitor(void) {
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  static bool inited = false;
  static bool inited_ok = false;

  if (inited) return inited_ok ? 0 : -1;

  pthread_mutex_lock(&lock);
  if (!inited) {
    inited = true;
    bh_elf_manager_load();
    if (0 == shadowhook_register_dl_init_callback(bh_task_manager_dl_init_pre, NULL, NULL) &&
        0 == shadowhook_register_dl_fini_callback(NULL, bh_task_manager_dl_fini_post, NULL))
      inited_ok = true;
  }
  pthread_mutex_unlock(&lock);
  return inited_ok ? 0 : -1;
}
#endif

void bh_task_manager_hook(bh_task_t *task) {
#if BH_LINKER_MAYBE_SUPPORT_DL_INIT_FINI_MONITOR
  if (bh_linker_is_support_dl_init_fini_monitor()) {
    if (0 != bh_task_manager_init_dl_init_fini_monitor()) {
      bh_task_do_hooked_callback(task, BYTEHOOK_STATUS_CODE_INITERR_DLMTR, NULL, NULL);
      return;
    }
  }
#endif

#if BH_LINKER_MAYBE_NOT_SUPPORT_DL_INIT_FINI_MONITOR
  if (!bh_linker_is_support_dl_init_fini_monitor()) {
    if (0 != bh_task_manager_init_dl_open_close_monitor()) {
      // For internal tasks in the DL monitor, this is not an error.
      // But these internal tasks do not set callbacks, so there will be no side effects.
      bh_task_do_hooked_callback(task, BYTEHOOK_STATUS_CODE_INITERR_DLMTR, NULL, NULL);
      return;
    }
  }
#endif

#if BH_LINKER_MAYBE_NOT_SUPPORT_DL_INIT_FINI_MONITOR
  bh_dl_monitor_dlclose_rdlock();
#endif
  bh_task_hook(task);
#if BH_LINKER_MAYBE_NOT_SUPPORT_DL_INIT_FINI_MONITOR
  bh_dl_monitor_dlclose_unlock();
#endif
}

int bh_task_manager_unhook(bh_task_t *task) {
#if BH_LINKER_MAYBE_NOT_SUPPORT_DL_INIT_FINI_MONITOR
  bh_dl_monitor_dlclose_rdlock();
#endif
  int r = bh_task_unhook(task);
#if BH_LINKER_MAYBE_NOT_SUPPORT_DL_INIT_FINI_MONITOR
  bh_dl_monitor_dlclose_unlock();
#endif
  return r;
}
