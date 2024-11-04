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

// Created by Kelun Cai (caikelun@bytedance.com) on 2024-09-20.

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#define _GNU_SOURCE
#pragma clang diagnostic push
#include "systest.h"

#include <android/log.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "bytehook.h"

#define LOG_TAG "bytehook_tag"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define LOG(fmt, ...)             __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##__VA_ARGS__)
#define LOG_ALWAYS_SHOW(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__)
#pragma clang diagnostic pop

#define DELIMITER_TITLE  "======================================================="
#define DELIMITER_SUB    "-------------------------------------------------"
#define TO_STR_HELPER(x) #x
#define TO_STR(x)        TO_STR_HELPER(x)

#define GLOBAL_VARIABLES(sym)               \
  static void *orig_##sym = NULL;           \
  static uintptr_t target_##sym = 0;        \
  static bytehook_stub_t stub_##sym = NULL; \
  static size_t count_##sym = 0

#define HOOK_ALL(sym)                                                                                      \
  do {                                                                                                     \
    if (NULL != stub_##sym) break;                                                                         \
    if (NULL == (stub_##sym = bytehook_hook_all(                                                           \
                     NULL, TO_STR(sym),                                                                    \
                     BYTEHOOK_IS_MANUAL_MODE ? (void *)manual_proxy_##sym : (void *)automatic_proxy_##sym, \
                     hooked, (void *)(&orig_##sym))))                                                      \
      LOG_ALWAYS_SHOW("hook_all FAILED:" TO_STR(sym));                                                     \
  } while (0)

#define HOOK_PARTIAL(sym)                                                                                  \
  do {                                                                                                     \
    if (NULL != stub_##sym) break;                                                                         \
    if (NULL == (stub_##sym = bytehook_hook_partial(                                                       \
                     allow_filter, NULL, NULL, TO_STR(sym),                                                \
                     BYTEHOOK_IS_MANUAL_MODE ? (void *)manual_proxy_##sym : (void *)automatic_proxy_##sym, \
                     hooked, (void *)(&orig_##sym))))                                                      \
      LOG_ALWAYS_SHOW("hook_partial FAILED:" TO_STR(sym));                                                 \
  } while (0)

#define HOOK_SINGLE(lib, sym)                                                                              \
  do {                                                                                                     \
    if (NULL != stub_##sym) break;                                                                         \
    if (NULL == (stub_##sym = bytehook_hook_single(                                                        \
                     TO_STR(lib), NULL, TO_STR(sym),                                                       \
                     BYTEHOOK_IS_MANUAL_MODE ? (void *)manual_proxy_##sym : (void *)automatic_proxy_##sym, \
                     hooked, (void *)(&orig_##sym))))                                                      \
      LOG_ALWAYS_SHOW("hook_single FAILED:" TO_STR(lib) ", " TO_STR(sym));                                 \
  } while (0)

#define UNHOOK(sym)                                                             \
  do {                                                                          \
    if (NULL == stub_##sym) break;                                              \
    int r = bytehook_unhook(stub_##sym);                                        \
    if (0 != r) LOG_ALWAYS_SHOW("unhook FAILED:" TO_STR(sym) ", return %d", r); \
    stub_##sym = NULL;                                                          \
  } while (0)

#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
#define COUNT(sym) __atomic_add_fetch(&count_##sym, 1, __ATOMIC_RELAXED)
#else
#define COUNT(sym)
#endif

#define SHOW2(sym, readable_sym) LOG("%-32s  %zu", TO_STR(readable_sym), count_##sym)
#define SHOW(sym)                SHOW2(sym, sym)

static void hooked(bytehook_stub_t task_stub, int status_code, const char *caller_path_name,
                   const char *sym_name, void *new_func, void *prev_func, void *arg) {
  if (BYTEHOOK_STATUS_CODE_ORIG_ADDR == status_code) {
    if (NULL == prev_func) {
      LOG_ALWAYS_SHOW(">>>>> hook FAILED (NULL == prev_func). stub: %" PRIxPTR
                      ", status: %d, caller_path_name: %s, sym_name: %s, new_func: %" PRIxPTR
                      ", prev_func: %" PRIxPTR ", arg: %" PRIxPTR,
                      (uintptr_t)task_stub, status_code, caller_path_name, sym_name, (uintptr_t)new_func,
                      (uintptr_t)prev_func, (uintptr_t)arg);
      abort();
    }
    if (NULL == *((void **)arg)) {
      *((void **)arg) = prev_func;  // OK, save the original address for manual mode
    } else if (*((void **)arg) != prev_func) {
      LOG_ALWAYS_SHOW(">>>>> hook FAILED (orig_func != prev_func). stub: %" PRIxPTR
                      ", status: %d, caller_path_name: %s, sym_name: %s, new_func: %" PRIxPTR
                      ", prev_func: %" PRIxPTR ", arg: %" PRIxPTR ", orig_func: %" PRIxPTR,
                      (uintptr_t)task_stub, status_code, caller_path_name, sym_name, (uintptr_t)new_func,
                      (uintptr_t)prev_func, (uintptr_t)arg, (uintptr_t)(*((void **)arg)));
      LOG("You are running into problems with linker namespace. You can either use automatic mode instead, "
          "or specify an explicit callee_path_name when hooking.");
      abort();
    }
  } else if (BYTEHOOK_STATUS_CODE_OK != status_code) {
    LOG_ALWAYS_SHOW(">>>>> hook FAILED. stub: %" PRIxPTR
                    ", status: %d, caller_path_name: %s, sym_name: %s, new_func: %" PRIxPTR
                    ", prev_func: %" PRIxPTR ", arg: %" PRIxPTR,
                    (uintptr_t)task_stub, status_code, caller_path_name, sym_name, (uintptr_t)new_func,
                    (uintptr_t)prev_func, (uintptr_t)arg);
  }
}

static bool allow_filter(const char *caller_path_name, void *arg) {
  (void)arg;
  if (NULL != strstr(caller_path_name, "libc.so")) return false;
  if (NULL != strstr(caller_path_name, "libbase.so")) return false;
  if (NULL != strstr(caller_path_name, "liblog.so")) return false;
  return true;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"

// pthread_create
GLOBAL_VARIABLES(pthread_create);
typedef int (*type_pthread_create)(pthread_t *, pthread_attr_t const *, void *(*)(void *), void *);
static int manual_proxy_pthread_create(pthread_t *pthread_ptr, pthread_attr_t const *attr,
                                       void *(*start_routine)(void *), void *arg) {
  COUNT(pthread_create);
  return ((type_pthread_create)orig_pthread_create)(pthread_ptr, attr, start_routine, arg);
}
static int automatic_proxy_pthread_create(pthread_t *pthread_ptr, pthread_attr_t const *attr,
                                          void *(*start_routine)(void *), void *arg) {
  COUNT(pthread_create);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pthread_create, type_pthread_create, pthread_ptr, attr,
                             start_routine, arg);
  BYTEHOOK_POP_STACK();
  return r;
}

// pthread_exit
GLOBAL_VARIABLES(pthread_exit);
typedef void (*type_pthread_exit)(void *);
static void manual_proxy_pthread_exit(void *return_value) {
  COUNT(pthread_exit);
  ((type_pthread_exit)orig_pthread_exit)(return_value);
}
static void automatic_proxy_pthread_exit(void *return_value) {
  COUNT(pthread_exit);
  BYTEHOOK_CALL_PREV(automatic_proxy_pthread_exit, type_pthread_exit, return_value);
  BYTEHOOK_POP_STACK();
}

// pthread_mutex_lock
GLOBAL_VARIABLES(pthread_mutex_lock);
typedef int (*type_pthread_mutex_lock)(pthread_mutex_t *);
static int manual_proxy_pthread_mutex_lock(pthread_mutex_t *mutex) {
  COUNT(pthread_mutex_lock);
  return ((type_pthread_mutex_lock)orig_pthread_mutex_lock)(mutex);
}
static int automatic_proxy_pthread_mutex_lock(pthread_mutex_t *mutex) {
  COUNT(pthread_mutex_lock);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pthread_mutex_lock, type_pthread_mutex_lock, mutex);
  BYTEHOOK_POP_STACK();
  return r;
}

// pthread_mutex_unlock
GLOBAL_VARIABLES(pthread_mutex_unlock);
typedef int (*type_pthread_mutex_unlock)(pthread_mutex_t *);
static int manual_proxy_pthread_mutex_unlock(pthread_mutex_t *mutex) {
  COUNT(pthread_mutex_unlock);
  return ((type_pthread_mutex_unlock)orig_pthread_mutex_unlock)(mutex);
}
static int automatic_proxy_pthread_mutex_unlock(pthread_mutex_t *mutex) {
  COUNT(pthread_mutex_unlock);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pthread_mutex_unlock, type_pthread_mutex_unlock, mutex);
  BYTEHOOK_POP_STACK();
  return r;
}

// pthread_rwlock_rdlock
GLOBAL_VARIABLES(pthread_rwlock_rdlock);
typedef int (*type_pthread_rwlock_rdlock)(pthread_rwlock_t *);
static int manual_proxy_pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
  COUNT(pthread_rwlock_rdlock);
  return ((type_pthread_rwlock_rdlock)orig_pthread_rwlock_rdlock)(rwlock);
}
static int automatic_proxy_pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
  COUNT(pthread_rwlock_rdlock);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pthread_rwlock_rdlock, type_pthread_rwlock_rdlock, rwlock);
  BYTEHOOK_POP_STACK();
  return r;
}

// pthread_rwlock_timedrdlock
GLOBAL_VARIABLES(pthread_rwlock_timedrdlock);
typedef int (*type_pthread_rwlock_timedrdlock)(pthread_rwlock_t *, const struct timespec *);
static int manual_proxy_pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock, const struct timespec *timeout) {
  COUNT(pthread_rwlock_timedrdlock);
  return ((type_pthread_rwlock_timedrdlock)orig_pthread_rwlock_timedrdlock)(rwlock, timeout);
}
static int automatic_proxy_pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock,
                                                      const struct timespec *timeout) {
  COUNT(pthread_rwlock_timedrdlock);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pthread_rwlock_timedrdlock, type_pthread_rwlock_timedrdlock,
                             rwlock, timeout);
  BYTEHOOK_POP_STACK();
  return r;
}

// pthread_rwlock_wrlock
GLOBAL_VARIABLES(pthread_rwlock_wrlock);
typedef int (*type_pthread_rwlock_wrlock)(pthread_rwlock_t *);
static int manual_proxy_pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
  COUNT(pthread_rwlock_wrlock);
  return ((type_pthread_rwlock_wrlock)orig_pthread_rwlock_wrlock)(rwlock);
}
static int automatic_proxy_pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
  COUNT(pthread_rwlock_wrlock);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pthread_rwlock_wrlock, type_pthread_rwlock_wrlock, rwlock);
  BYTEHOOK_POP_STACK();
  return r;
}

// pthread_rwlock_timedwrlock
GLOBAL_VARIABLES(pthread_rwlock_timedwrlock);
typedef int (*type_pthread_rwlock_timedwrlock)(pthread_rwlock_t *, const struct timespec *);
static int manual_proxy_pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock, const struct timespec *timeout) {
  COUNT(pthread_rwlock_timedwrlock);
  return ((type_pthread_rwlock_timedwrlock)orig_pthread_rwlock_timedwrlock)(rwlock, timeout);
}
static int automatic_proxy_pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock,
                                                      const struct timespec *timeout) {
  COUNT(pthread_rwlock_timedwrlock);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pthread_rwlock_timedwrlock, type_pthread_rwlock_timedwrlock,
                             rwlock, timeout);
  BYTEHOOK_POP_STACK();
  return r;
}

// pthread_rwlock_unlock
GLOBAL_VARIABLES(pthread_rwlock_unlock);
typedef int (*type_pthread_rwlock_unlock)(pthread_rwlock_t *);
static int manual_proxy_pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
  COUNT(pthread_rwlock_unlock);
  return ((type_pthread_rwlock_unlock)orig_pthread_rwlock_unlock)(rwlock);
}
static int automatic_proxy_pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
  COUNT(pthread_rwlock_unlock);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pthread_rwlock_unlock, type_pthread_rwlock_unlock, rwlock);
  BYTEHOOK_POP_STACK();
  return r;
}

// malloc
GLOBAL_VARIABLES(malloc);
typedef void *(*type_malloc)(size_t);
static void *manual_proxy_malloc(size_t sz) {
  COUNT(malloc);
  return ((type_malloc)orig_malloc)(sz);
}
static void *automatic_proxy_malloc(size_t sz) {
  COUNT(malloc);
  void *r = BYTEHOOK_CALL_PREV(automatic_proxy_malloc, type_malloc, sz);
  BYTEHOOK_POP_STACK();
  return r;
}

// calloc
GLOBAL_VARIABLES(calloc);
typedef void *(*type_calloc)(size_t, size_t);
static void *manual_proxy_calloc(size_t cnt, size_t sz) {
  COUNT(calloc);
  return ((type_calloc)orig_calloc)(cnt, sz);
}
static void *automatic_proxy_calloc(size_t cnt, size_t sz) {
  COUNT(calloc);
  void *r = BYTEHOOK_CALL_PREV(automatic_proxy_calloc, type_calloc, cnt, sz);
  BYTEHOOK_POP_STACK();
  return r;
}

// realloc
GLOBAL_VARIABLES(realloc);
typedef void *(*type_realloc)(void *, size_t);
static void *manual_proxy_realloc(void *ptr, size_t sz) {
  COUNT(realloc);
  return ((type_realloc)orig_realloc)(ptr, sz);
}
static void *automatic_proxy_realloc(void *ptr, size_t sz) {
  COUNT(realloc);
  void *r = BYTEHOOK_CALL_PREV(automatic_proxy_realloc, type_realloc, ptr, sz);
  BYTEHOOK_POP_STACK();
  return r;
}

// memalign
GLOBAL_VARIABLES(memalign);
typedef void *(*type_memalign)(size_t, size_t);
static void *manual_proxy_memalign(size_t align, size_t sz) {
  COUNT(memalign);
  return ((type_memalign)orig_memalign)(align, sz);
}
static void *automatic_proxy_memalign(size_t align, size_t sz) {
  COUNT(memalign);
  void *r = BYTEHOOK_CALL_PREV(automatic_proxy_memalign, type_memalign, align, sz);
  BYTEHOOK_POP_STACK();
  return r;
}

// free
GLOBAL_VARIABLES(free);
typedef void (*type_free)(void *);
static void manual_proxy_free(void *ptr) {
  COUNT(free);
  ((type_free)orig_free)(ptr);
}
static void automatic_proxy_free(void *ptr) {
  COUNT(free);
  BYTEHOOK_CALL_PREV(automatic_proxy_free, type_free, ptr);
  BYTEHOOK_POP_STACK();
}

// mmap
GLOBAL_VARIABLES(mmap);
typedef void *(*type_mmap)(void *, size_t, int, int, int, off_t);
static void *manual_proxy_mmap(void *addr, size_t sz, int prot, int flags, int fd, off_t offset) {
  COUNT(mmap);
  return ((type_mmap)orig_mmap)(addr, sz, prot, flags, fd, offset);
}
static void *automatic_proxy_mmap(void *addr, size_t sz, int prot, int flags, int fd, off_t offset) {
  COUNT(mmap);
  void *r = BYTEHOOK_CALL_PREV(automatic_proxy_mmap, type_mmap, addr, sz, prot, flags, fd, offset);
  BYTEHOOK_POP_STACK();
  return r;
}

// mmap64
GLOBAL_VARIABLES(mmap64);
typedef void *(*type_mmap64)(void *, size_t, int, int, int, off64_t);
static void *manual_proxy_mmap64(void *addr, size_t sz, int prot, int flags, int fd, off64_t offset) {
  COUNT(mmap64);
  return ((type_mmap64)orig_mmap64)(addr, sz, prot, flags, fd, offset);
}
static void *automatic_proxy_mmap64(void *addr, size_t sz, int prot, int flags, int fd, off64_t offset) {
  COUNT(mmap64);
  void *r = BYTEHOOK_CALL_PREV(automatic_proxy_mmap64, type_mmap64, addr, sz, prot, flags, fd, offset);
  BYTEHOOK_POP_STACK();
  return r;
}

// __mmap2
GLOBAL_VARIABLES(__mmap2);
typedef void *(*type___mmap2)(void *, size_t, int, int, int, size_t);
static void *manual_proxy___mmap2(void *addr, size_t sz, int prot, int flags, int fd, size_t pages) {
  COUNT(__mmap2);
  return ((type___mmap2)orig___mmap2)(addr, sz, prot, flags, fd, pages);
}
static void *automatic_proxy___mmap2(void *addr, size_t sz, int prot, int flags, int fd, size_t pages) {
  COUNT(__mmap2);
  void *r = BYTEHOOK_CALL_PREV(automatic_proxy___mmap2, type___mmap2, addr, sz, prot, flags, fd, pages);
  BYTEHOOK_POP_STACK();
  return r;
}

// mremap
GLOBAL_VARIABLES(mremap);
typedef void *(*type_mremap)(void *, size_t, size_t, int, void *);
static void *manual_proxy_mremap(void *old_addr, size_t old_size, size_t new_size, int flags,
                                 void *new_addr) {
  COUNT(mremap);
  return ((type_mremap)orig_mremap)(old_addr, old_size, new_size, flags, new_addr);
}
static void *automatic_proxy_mremap(void *old_addr, size_t old_size, size_t new_size, int flags,
                                    void *new_addr) {
  COUNT(mremap);
  void *r =
      BYTEHOOK_CALL_PREV(automatic_proxy_mremap, type_mremap, old_addr, old_size, new_size, flags, new_addr);
  BYTEHOOK_POP_STACK();
  return r;
}

// munmap
GLOBAL_VARIABLES(munmap);
typedef int (*type_munmap)(void *, size_t);
static int manual_proxy_munmap(void *addr, size_t sz) {
  COUNT(munmap);
  return ((type_munmap)orig_munmap)(addr, sz);
}
static int automatic_proxy_munmap(void *addr, size_t sz) {
  COUNT(munmap);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_munmap, type_munmap, addr, sz);
  BYTEHOOK_POP_STACK();
  return r;
}

// open
GLOBAL_VARIABLES(open);
typedef int (*type_open)(const char *, int, mode_t);
static int manual_proxy_open(const char *pathname, int flags, mode_t modes) {
  COUNT(open);
  return ((type_open)orig_open)(pathname, flags, modes);
}
static int automatic_proxy_open(const char *pathname, int flags, mode_t modes) {
  COUNT(open);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_open, type_open, pathname, flags, modes);
  BYTEHOOK_POP_STACK();
  return r;
}

// __open_real
GLOBAL_VARIABLES(__open_real);
typedef int (*type___open_real)(const char *, int, mode_t);
static int manual_proxy___open_real(const char *pathname, int flags, mode_t modes) {
  COUNT(__open_real);
  return ((type___open_real)orig___open_real)(pathname, flags, modes);
}
static int automatic_proxy___open_real(const char *pathname, int flags, mode_t modes) {
  COUNT(__open_real);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy___open_real, type___open_real, pathname, flags, modes);
  BYTEHOOK_POP_STACK();
  return r;
}

// __open_2
GLOBAL_VARIABLES(__open_2);
typedef int (*type___open_2)(const char *, int);
static int manual_proxy___open_2(const char *pathname, int flags) {
  COUNT(__open_2);
  return ((type___open_2)orig___open_2)(pathname, flags);
}
static int automatic_proxy___open_2(const char *pathname, int flags) {
  COUNT(__open_2);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy___open_2, type___open_2, pathname, flags);
  BYTEHOOK_POP_STACK();
  return r;
}

// close
GLOBAL_VARIABLES(close);
typedef int (*type_close)(int);
static int manual_proxy_close(int fd) {
  COUNT(close);
  return ((type_close)orig_close)(fd);
}
static int automatic_proxy_close(int fd) {
  COUNT(close);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_close, type_close, fd);
  BYTEHOOK_POP_STACK();
  return r;
}

// pipe
GLOBAL_VARIABLES(pipe);
typedef int (*type_pipe)(int *);
static int manual_proxy_pipe(int *fds) {
  COUNT(pipe);
  return ((type_pipe)orig_pipe)(fds);
}
static int automatic_proxy_pipe(int *fds) {
  COUNT(pipe);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pipe, type_pipe, fds);
  BYTEHOOK_POP_STACK();
  return r;
}

// pipe2
GLOBAL_VARIABLES(pipe2);
typedef int (*type_pipe2)(int *, int);
static int manual_proxy_pipe2(int *fds, int flags) {
  COUNT(pipe2);
  return ((type_pipe2)orig_pipe2)(fds, flags);
}
static int automatic_proxy_pipe2(int *fds, int flags) {
  COUNT(pipe2);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_pipe2, type_pipe2, fds, flags);
  BYTEHOOK_POP_STACK();
  return r;
}

// dup
GLOBAL_VARIABLES(dup);
typedef int (*type_dup)(int);
static int manual_proxy_dup(int oldfd) {
  COUNT(dup);
  return ((type_dup)orig_dup)(oldfd);
}
static int automatic_proxy_dup(int oldfd) {
  COUNT(dup);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_dup, type_dup, oldfd);
  BYTEHOOK_POP_STACK();
  return r;
}

// dup2
GLOBAL_VARIABLES(dup2);
typedef int (*type_dup2)(int, int);
static int manual_proxy_dup2(int oldfd, int newfd) {
  COUNT(dup2);
  return ((type_dup2)orig_dup2)(oldfd, newfd);
}
static int automatic_proxy_dup2(int oldfd, int newfd) {
  COUNT(dup2);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_dup2, type_dup2, oldfd, newfd);
  BYTEHOOK_POP_STACK();
  return r;
}

// socket
GLOBAL_VARIABLES(socket);
typedef int (*type_socket)(int, int, int);
static int manual_proxy_socket(int af, int type, int protocol) {
  COUNT(socket);
  return ((type_socket)orig_socket)(af, type, protocol);
}
static int automatic_proxy_socket(int af, int type, int protocol) {
  COUNT(socket);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_socket, type_socket, af, type, protocol);
  BYTEHOOK_POP_STACK();
  return r;
}

// socketpair
GLOBAL_VARIABLES(socketpair);
typedef int (*type_socketpair)(int, int, int, int *);
static int manual_proxy_socketpair(int af, int type, int protocol, int *fds) {
  COUNT(socketpair);
  return ((type_socketpair)orig_socketpair)(af, type, protocol, fds);
}
static int automatic_proxy_socketpair(int af, int type, int protocol, int *fds) {
  COUNT(socketpair);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_socketpair, type_socketpair, af, type, protocol, fds);
  BYTEHOOK_POP_STACK();
  return r;
}

// eventfd
GLOBAL_VARIABLES(eventfd);
typedef int (*type_eventfd)(unsigned int, int);
static int manual_proxy_eventfd(unsigned int initial_value, int flags) {
  COUNT(eventfd);
  return ((type_eventfd)orig_eventfd)(initial_value, flags);
}
static int automatic_proxy_eventfd(unsigned int initial_value, int flags) {
  COUNT(eventfd);
  int r = BYTEHOOK_CALL_PREV(automatic_proxy_eventfd, type_eventfd, initial_value, flags);
  BYTEHOOK_POP_STACK();
  return r;
}

// read
GLOBAL_VARIABLES(read);
typedef ssize_t (*type_read)(int, void *const, size_t);
static ssize_t manual_proxy_read(int fd, void *const buf, size_t count) {
  COUNT(read);
  return ((type_read)orig_read)(fd, buf, count);
}
static ssize_t automatic_proxy_read(int fd, void *const buf, size_t count) {
  COUNT(read);
  ssize_t r = BYTEHOOK_CALL_PREV(automatic_proxy_read, type_read, fd, buf, count);
  BYTEHOOK_POP_STACK();
  return r;
}

// __read_chk
GLOBAL_VARIABLES(__read_chk);
typedef ssize_t (*type___read_chk)(int, void *const, size_t, size_t);
static ssize_t manual_proxy___read_chk(int fd, void *const buf, size_t count, size_t bos) {
  COUNT(__read_chk);
  return ((type___read_chk)orig___read_chk)(fd, buf, count, bos);
}
static ssize_t automatic_proxy___read_chk(int fd, void *const buf, size_t count, size_t bos) {
  COUNT(__read_chk);
  ssize_t r = BYTEHOOK_CALL_PREV(automatic_proxy___read_chk, type___read_chk, fd, buf, count, bos);
  BYTEHOOK_POP_STACK();
  return r;
}

// write
GLOBAL_VARIABLES(write);
typedef ssize_t (*type_write)(int, const void *const, size_t);
static ssize_t manual_proxy_write(int fd, const void *const buf, size_t count) {
  COUNT(write);
  return ((type_write)orig_write)(fd, buf, count);
}
static ssize_t automatic_proxy_write(int fd, const void *const buf, size_t count) {
  COUNT(write);
  ssize_t r = BYTEHOOK_CALL_PREV(automatic_proxy_write, type_write, fd, buf, count);
  BYTEHOOK_POP_STACK();
  return r;
}

// __write_chk
GLOBAL_VARIABLES(__write_chk);
typedef ssize_t (*type___write_chk)(int, void *const, size_t, size_t);
static ssize_t manual_proxy___write_chk(int fd, void *const buf, size_t count, size_t bos) {
  COUNT(__write_chk);
  return ((type___write_chk)orig___write_chk)(fd, buf, count, bos);
}
static ssize_t automatic_proxy___write_chk(int fd, void *const buf, size_t count, size_t bos) {
  COUNT(__write_chk);
  ssize_t r = BYTEHOOK_CALL_PREV(automatic_proxy___write_chk, type___write_chk, fd, buf, count, bos);
  BYTEHOOK_POP_STACK();
  return r;
}

// readv
GLOBAL_VARIABLES(readv);
typedef ssize_t (*type_readv)(int, const struct iovec *, int);
static ssize_t manual_proxy_readv(int fd, const struct iovec *iov, int count) {
  COUNT(readv);
  return ((type_readv)orig_readv)(fd, iov, count);
}
static ssize_t automatic_proxy_readv(int fd, const struct iovec *iov, int count) {
  COUNT(readv);
  ssize_t r = BYTEHOOK_CALL_PREV(automatic_proxy_readv, type_readv, fd, iov, count);
  BYTEHOOK_POP_STACK();
  return r;
}

// writev
GLOBAL_VARIABLES(writev);
typedef ssize_t (*type_writev)(int, const struct iovec *, int);
static ssize_t manual_proxy_writev(int fd, const struct iovec *iov, int count) {
  COUNT(writev);
  return ((type_writev)orig_writev)(fd, iov, count);
}
static ssize_t automatic_proxy_writev(int fd, const struct iovec *iov, int count) {
  COUNT(writev);
  ssize_t r = BYTEHOOK_CALL_PREV(automatic_proxy_writev, type_writev, fd, iov, count);
  BYTEHOOK_POP_STACK();
  return r;
}

#pragma clang diagnostic pop

int systest_hook(void) {
  LOG_ALWAYS_SHOW("systest hook start");

  HOOK_PARTIAL(pthread_create);
  HOOK_PARTIAL(pthread_exit);
#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
  HOOK_ALL(pthread_mutex_lock);
  HOOK_ALL(pthread_mutex_unlock);
#endif
  HOOK_ALL(pthread_rwlock_rdlock);
  HOOK_ALL(pthread_rwlock_timedrdlock);
  HOOK_ALL(pthread_rwlock_wrlock);
  HOOK_ALL(pthread_rwlock_timedwrlock);
  HOOK_ALL(pthread_rwlock_unlock);
#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
  HOOK_ALL(malloc);
  HOOK_ALL(calloc);
  HOOK_ALL(realloc);
  HOOK_ALL(memalign);
  HOOK_ALL(free);
#endif
  HOOK_ALL(mmap);
  HOOK_ALL(mmap64);
  HOOK_ALL(__mmap2);
  HOOK_ALL(mremap);
  HOOK_ALL(munmap);
  HOOK_ALL(open);
  HOOK_ALL(__open_real);
  HOOK_ALL(__open_2);
#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
  HOOK_ALL(close);
#endif
  HOOK_ALL(pipe);
  HOOK_ALL(pipe2);
  HOOK_ALL(dup);
  HOOK_ALL(dup2);
  HOOK_ALL(socket);
  HOOK_ALL(socketpair);
  HOOK_ALL(eventfd);
#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
  HOOK_ALL(read);
  HOOK_ALL(__read_chk);
  HOOK_ALL(write);
  HOOK_ALL(__write_chk);
  HOOK_ALL(readv);
  HOOK_ALL(writev);
#endif

  LOG_ALWAYS_SHOW("systest hook end");
  return 0;
}

int systest_unhook(void) {
  LOG_ALWAYS_SHOW("systest unhook start");

  UNHOOK(pthread_create);
  UNHOOK(pthread_exit);
#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
  UNHOOK(pthread_mutex_lock);
  UNHOOK(pthread_mutex_unlock);
#endif
  UNHOOK(pthread_rwlock_rdlock);
  UNHOOK(pthread_rwlock_timedrdlock);
  UNHOOK(pthread_rwlock_wrlock);
  UNHOOK(pthread_rwlock_timedwrlock);
  UNHOOK(pthread_rwlock_unlock);
#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
  UNHOOK(malloc);
  UNHOOK(calloc);
  UNHOOK(realloc);
  UNHOOK(memalign);
  UNHOOK(free);
#endif
  UNHOOK(mmap);
  UNHOOK(mmap64);
  UNHOOK(__mmap2);
  UNHOOK(mremap);
  UNHOOK(munmap);
  UNHOOK(open);
  UNHOOK(__open_real);
  UNHOOK(__open_2);
#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
  UNHOOK(close);
#endif
  UNHOOK(pipe);
  UNHOOK(pipe2);
  UNHOOK(dup);
  UNHOOK(dup2);
  UNHOOK(socket);
  UNHOOK(socketpair);
  UNHOOK(eventfd);
#ifdef DEPENDENCY_ON_LOCAL_LIBRARY
  UNHOOK(read);
  UNHOOK(__read_chk);
  UNHOOK(write);
  UNHOOK(__write_chk);
  UNHOOK(readv);
  UNHOOK(writev);
#endif

  LOG_ALWAYS_SHOW("systest unhook end");
  return 0;
}

#pragma clang optimize off

static void *systest_simulate_thd(void *arg) {
  (void)arg;
  return NULL;
}

static void systest_simulate(void) {
  // pthread_create, pthread_exit
  pthread_t thd;
  pthread_create(&thd, NULL, &systest_simulate_thd, NULL);
  pthread_join(thd, NULL);

  // pthread_mutex_lock, pthread_mutex_unlock
  struct timespec timeout;
  timeout.tv_sec = time(NULL) + 1;
  timeout.tv_nsec = 0;
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&mutex);
  pthread_mutex_unlock(&mutex);

  // pthread_rwlock_rdlock, pthread_rwlock_wrlock, pthread_rwlock_unlock
  // pthread_rwlock_timedrdlock, pthread_rwlock_timedwrlock
  static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
  pthread_rwlock_rdlock(&rwlock);
  pthread_rwlock_unlock(&rwlock);
  pthread_rwlock_wrlock(&rwlock);
  pthread_rwlock_unlock(&rwlock);
  timeout.tv_sec = time(NULL) + 1;
  if (0 == pthread_rwlock_timedrdlock(&rwlock, &timeout)) pthread_rwlock_unlock(&rwlock);
  timeout.tv_sec = time(NULL) + 1;
  if (0 == pthread_rwlock_timedwrlock(&rwlock, &timeout)) pthread_rwlock_unlock(&rwlock);

  // malloc, calloc, realloc, memalign, free ...
  void *p = malloc(16);
  p = realloc(p, 24);
  free(p);
  p = calloc(1, 16);
  free(p);
  p = memalign(16, 32);
  free(p);

  // mmap64, mmap, mremap, munmap
  p = mmap64(NULL, 512, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  p = mremap(p, 512, 1024, 0);
  munmap(p, 1024);

  // open, close
  int fd = open("/dev/null", O_RDWR);
  close(fd);

  // pipe, pipe2
  int fds[2];
  if (0 == pipe(fds)) {
    close(fds[0]);
    close(fds[1]);
  }
  if (0 == pipe2(fds, O_CLOEXEC)) {
    close(fds[0]);
    close(fds[1]);
  }

  // dup, dup2
  fd = open("/dev/null", O_RDWR);
  int fd2 = dup(fd);
  close(fd);
  close(fd2);

  // dup2
  fd = open("/dev/null", O_RDWR);
  fd2 = open("/dev/null", O_RDWR);
  dup2(fd, fd2);
  close(fd);
  close(fd2);

  // socket, socketpair
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  close(fd);
  if (0 == socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
    close(fds[0]);
    close(fds[1]);
  }

  // eventfd
  fd = eventfd(0, EFD_CLOEXEC);
  close(fd);

  // read, write
  pipe(fds);
  char a = 'a';
  write(fds[1], &a, sizeof(a));
  read(fds[0], &a, sizeof(a));
  close(fds[0]);
  close(fds[1]);

  // readv, writev
  pipe(fds);
  a = 'a';
  char b = 'b';
  struct iovec iov[2] = {
      {&a, sizeof(a)},
      {&b, sizeof(b)},
  };
  writev(fds[1], iov, 2);
  readv(fds[0], iov, 2);
  close(fds[0]);
  close(fds[1]);
}

#pragma clang optimize on

static void systest_dump(void) {
  LOG(DELIMITER_TITLE);
  SHOW(pthread_create);
  SHOW(pthread_exit);

  LOG(DELIMITER_SUB);
  SHOW(pthread_mutex_lock);
  SHOW(pthread_mutex_unlock);

  LOG(DELIMITER_SUB);
  SHOW(pthread_rwlock_rdlock);
  SHOW(pthread_rwlock_timedrdlock);
  SHOW(pthread_rwlock_wrlock);
  SHOW(pthread_rwlock_timedwrlock);
  SHOW(pthread_rwlock_unlock);

  LOG(DELIMITER_SUB);
  SHOW(malloc);
  SHOW(calloc);
  SHOW(realloc);
  SHOW(memalign);
  SHOW(free);

  LOG(DELIMITER_SUB);
  SHOW(mmap);
  SHOW(mmap64);
  SHOW(__mmap2);
  SHOW(mremap);
  SHOW(munmap);

  LOG(DELIMITER_SUB);
  SHOW(open);
  SHOW(__open_real);
  SHOW(__open_2);
  SHOW(close);
  SHOW(pipe);
  SHOW(pipe2);
  SHOW(dup);
  SHOW(dup2);
  SHOW(socket);
  SHOW(socketpair);
  SHOW(eventfd);

  LOG(DELIMITER_SUB);
  SHOW(read);
  SHOW(__read_chk);
  SHOW(write);
  SHOW(__write_chk);
  SHOW(readv);
  SHOW(writev);
}

int systest_run(void) {
  systest_simulate();
  systest_dump();
  return 0;
}
