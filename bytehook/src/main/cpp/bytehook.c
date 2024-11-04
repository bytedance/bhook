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

#include "bytehook.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bh_cfi.h"
#include "bh_dl_monitor.h"
#include "bh_elf_manager.h"
#include "bh_hub.h"
#include "bh_linker.h"
#include "bh_log.h"
#include "bh_recorder.h"
#include "bh_safe.h"
#include "bh_task.h"
#include "bh_task_manager.h"
#include "bytesig.h"

static int bytehook_init_errno = BYTEHOOK_STATUS_CODE_UNINIT;
static int bytehook_mode = -1;

const char *bytehook_get_version(void) {
  return "bytehook version " BYTEHOOK_VERSION;
}

int bytehook_init(int mode, bool debug) {
#define GOTO_END(errnum)          \
  do {                            \
    bytehook_init_errno = errnum; \
    goto end;                     \
  } while (0)

  bool do_init = false;
  if (__predict_true(BYTEHOOK_STATUS_CODE_UNINIT == bytehook_init_errno)) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);
    if (__predict_true(BYTEHOOK_STATUS_CODE_UNINIT == bytehook_init_errno)) {
      do_init = true;
      bh_log_set_debug(debug);
      if (__predict_false(BYTEHOOK_MODE_AUTOMATIC != mode && BYTEHOOK_MODE_MANUAL != mode))
        GOTO_END(BYTEHOOK_STATUS_CODE_INITERR_INVALID_ARG);
      bytehook_mode = mode;
      if (__predict_false(0 != bh_linker_init())) GOTO_END(BYTEHOOK_STATUS_CODE_INITERR_SYM);
      if (__predict_false(0 != bytesig_init(SIGSEGV))) GOTO_END(BYTEHOOK_STATUS_CODE_INITERR_SIG);
      if (__predict_false(0 != bytesig_init(SIGBUS))) GOTO_END(BYTEHOOK_STATUS_CODE_INITERR_SIG);
      if (__predict_false(0 != bh_cfi_disable_slowpath())) GOTO_END(BYTEHOOK_STATUS_CODE_INITERR_CFI);
      if (__predict_false(0 != bh_safe_init())) GOTO_END(BYTEHOOK_STATUS_CODE_INITERR_SAFE);
      if (BYTEHOOK_IS_AUTOMATIC_MODE) {
        if (__predict_false(0 != bh_hub_init())) GOTO_END(BYTEHOOK_STATUS_CODE_INITERR_HUB);
      }

#undef GOTO_END

      bytehook_init_errno = BYTEHOOK_STATUS_CODE_OK;
    }
  end:
    pthread_mutex_unlock(&lock);
  }

  BH_LOG_ALWAYS_SHOW("%s: bytehook init(mode: %s, debuggable: %s), return: %d, real-init: %s",
                     bytehook_get_version(), BYTEHOOK_MODE_AUTOMATIC == mode ? "AUTOMATIC" : "MANUAL",
                     debug ? "true" : "false", bytehook_init_errno, do_init ? "yes" : "no");
  return bytehook_init_errno;
}

bytehook_stub_t bytehook_hook_single(const char *caller_path_name, const char *callee_path_name,
                                     const char *sym_name, void *new_func, bytehook_hooked_t hooked,
                                     void *hooked_arg) {
  const void *caller_addr = __builtin_return_address(0);
  if (NULL == caller_path_name || NULL == sym_name || NULL == new_func) return NULL;
  if (BYTEHOOK_STATUS_CODE_OK != bytehook_init_errno) return NULL;

  bh_task_t *task = bh_task_create_single(caller_path_name, callee_path_name, sym_name, new_func, hooked,
                                          hooked_arg, false);
  if (NULL != task) {
    bh_task_manager_add(task);
    bh_task_manager_hook(task);
    bh_recorder_add_hook(task->status_code, caller_path_name, sym_name, (uintptr_t)new_func, (uintptr_t)task,
                         (uintptr_t)caller_addr);
  }
  return (bytehook_stub_t)task;
}

bytehook_stub_t bytehook_hook_partial(bytehook_caller_allow_filter_t caller_allow_filter,
                                      void *caller_allow_filter_arg, const char *callee_path_name,
                                      const char *sym_name, void *new_func, bytehook_hooked_t hooked,
                                      void *hooked_arg) {
  const void *caller_addr = __builtin_return_address(0);
  if (NULL == caller_allow_filter || NULL == sym_name || NULL == new_func) return NULL;
  if (BYTEHOOK_STATUS_CODE_OK != bytehook_init_errno) return NULL;

  bh_task_t *task = bh_task_create_partial(caller_allow_filter, caller_allow_filter_arg, callee_path_name,
                                           sym_name, new_func, hooked, hooked_arg, false);
  if (NULL != task) {
    bh_task_manager_add(task);
    bh_task_manager_hook(task);
    bh_recorder_add_hook(BYTEHOOK_STATUS_CODE_MAX, "PARTIAL", sym_name, (uintptr_t)new_func, (uintptr_t)task,
                         (uintptr_t)caller_addr);
  }
  return (bytehook_stub_t)task;
}

bytehook_stub_t bytehook_hook_all(const char *callee_path_name, const char *sym_name, void *new_func,
                                  bytehook_hooked_t hooked, void *hooked_arg) {
  const void *caller_addr = __builtin_return_address(0);
  if (NULL == sym_name || NULL == new_func) return NULL;
  if (BYTEHOOK_STATUS_CODE_OK != bytehook_init_errno) return NULL;

  bh_task_t *task = bh_task_create_all(callee_path_name, sym_name, new_func, hooked, hooked_arg, false);
  if (NULL != task) {
    bh_task_manager_add(task);
    bh_task_manager_hook(task);
    bh_recorder_add_hook(BYTEHOOK_STATUS_CODE_MAX, "ALL", sym_name, (uintptr_t)new_func, (uintptr_t)task,
                         (uintptr_t)caller_addr);
  }
  return (bytehook_stub_t)task;
}

int bytehook_unhook(bytehook_stub_t stub) {
  const void *caller_addr = __builtin_return_address(0);
  if (NULL == stub) return BYTEHOOK_STATUS_CODE_INVALID_ARG;
  if (BYTEHOOK_STATUS_CODE_OK != bytehook_init_errno) return bytehook_init_errno;

  bh_task_t *task = (bh_task_t *)stub;
  bh_task_manager_del(task);
  int status_code = bh_task_manager_unhook(task);
  bh_recorder_add_unhook(status_code, (uintptr_t)task, (uintptr_t)caller_addr);
  bh_task_destroy(&task);

  return status_code;
}

int bytehook_add_ignore(const char *caller_path_name) {
  int r = bh_elf_manager_add_ignore(caller_path_name);
  return 0 == r ? 0 : BYTEHOOK_STATUS_CODE_IGNORE;
}

bool bytehook_get_debug(void) {
  return bh_log_get_debug();
}

void bytehook_set_debug(bool debug) {
  bh_log_set_debug(debug);
}

bool bytehook_get_recordable(void) {
  return bh_recorder_get_recordable();
}

void bytehook_set_recordable(bool recordable) {
  bh_recorder_set_recordable(recordable);
}

char *bytehook_get_records(uint32_t item_flags) {
  return bh_recorder_get(item_flags);
}

void bytehook_dump_records(int fd, uint32_t item_flags) {
  bh_recorder_dump(fd, item_flags);
}

void *bytehook_get_prev_func(void *func) {
  if (__predict_false(BYTEHOOK_IS_MANUAL_MODE)) abort();
  return bh_hub_get_prev_func(func);
}

void *bytehook_get_return_address(void) {
  if (__predict_false(BYTEHOOK_IS_MANUAL_MODE)) abort();
  return bh_hub_get_return_address();
}

void bytehook_pop_stack(void *return_address) {
  if (__predict_false(BYTEHOOK_IS_MANUAL_MODE)) abort();
  bh_hub_pop_stack(return_address);
}

int bytehook_get_mode(void) {
  return bytehook_mode;
}

void bytehook_add_dlopen_callback(bytehook_pre_dlopen_t pre, bytehook_post_dlopen_t post, void *data) {
  bh_dl_monitor_add_dlopen_callback(pre, post, data);
}

void bytehook_del_dlopen_callback(bytehook_pre_dlopen_t pre, bytehook_post_dlopen_t post, void *data) {
  bh_dl_monitor_del_dlopen_callback(pre, post, data);
}
