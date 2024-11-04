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

#include "bh_hub.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "bh_log.h"
#include "bh_safe.h"
#include "bh_sig.h"
#include "bh_trampo.h"
#include "bh_util.h"
#include "bytehook.h"
#include "queue.h"

#define BH_HUB_TRAMPO_PAGE_NAME "bytehook-plt-trampolines"
#define BH_HUB_TRAMPO_DELAY_SEC 5
#define BH_HUB_STACK_NAME       "bytehook-stack"
#define BH_HUB_STACK_SIZE       4096  // 4K is enough
#define BH_HUB_STACK_FRAME_MAX  16
#define BH_HUB_THREAD_MAX       1024
#define BH_HUB_DELAY_SEC        10

// proxy for each hook-task in the same target-address
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
typedef struct bh_hub_proxy {
  void *func;
  bool enabled;
  SLIST_ENTRY(bh_hub_proxy, ) link;
} bh_hub_proxy_t;
#pragma clang diagnostic pop

// proxy list for each hub
typedef SLIST_HEAD(bh_hub_proxy_list, bh_hub_proxy, ) bh_hub_proxy_list_t;

// frame in the stack
typedef struct {
  bh_hub_proxy_list_t proxies;
  uintptr_t orig_addr;
  void *return_address;
} bh_hub_frame_t;

// stack for each thread
typedef struct {
  size_t frames_cnt;
  bh_hub_frame_t frames[BH_HUB_STACK_FRAME_MAX];
} bh_hub_stack_t;

// hub for each target-address
struct bh_hub {
  bh_hub_proxy_list_t proxies;
  pthread_mutex_t proxies_lock;
  uintptr_t orig_addr;
  uintptr_t trampo;
  time_t destroy_ts;
  LIST_ENTRY(bh_hub, ) link;
};

// hub list for delayed-destroy staging
typedef LIST_HEAD(bh_hub_list, bh_hub, ) bh_hub_list_t;

// global data for hub delayed-destroy staging
static bh_hub_list_t bh_hub_delayed_destroy;
static pthread_mutex_t bh_hub_delayed_destroy_lock;

// global data for trampo
static bh_trampo_mgr_t bh_hub_trampo_mgr;

// global data for stack
static pthread_key_t bh_hub_stack_tls_key;
static bh_hub_stack_t *bh_hub_stack_cache;
static uint8_t *bh_hub_stack_cache_used;
static pthread_key_t bh_hub_stack_reserved_tls_key;

// hub trampoline template
extern void *bh_hub_trampo_template_data __attribute__((visibility("hidden")));
__attribute__((naked)) static void bh_hub_trampo_template(void) {
#if defined(__arm__)
  __asm__(
      // Save parameter registers, LR
      "push  { r0 - r3, lr }     \n"

      // Call bh_hub_push_stack()
      "ldr   r0, hub_ptr         \n"
      "mov   r1, lr              \n"
      "ldr   ip, push_stack      \n"
      "blx   ip                  \n"

      // Save the hook function's address to IP register
      "mov   ip, r0              \n"

      // Restore parameter registers, LR
      "pop   { r0 - r3, lr }     \n"

      // Call hook function
      "bx    ip                  \n"

      "bh_hub_trampo_template_data:"
      ".global bh_hub_trampo_template_data;"
      "push_stack:"
      ".word 0;"
      "hub_ptr:"
      ".word 0;");
#elif defined(__aarch64__)
  __asm__(
      // Save parameter registers, XR(X8), LR
      "stp   x0, x1, [sp, #-0xd0]!    \n"
      "stp   x2, x3, [sp, #0x10]      \n"
      "stp   x4, x5, [sp, #0x20]      \n"
      "stp   x6, x7, [sp, #0x30]      \n"
      "stp   x8, lr, [sp, #0x40]      \n"
      "stp   q0, q1, [sp, #0x50]      \n"
      "stp   q2, q3, [sp, #0x70]      \n"
      "stp   q4, q5, [sp, #0x90]      \n"
      "stp   q6, q7, [sp, #0xb0]      \n"

      // Call bh_hub_push_stack()
      "ldr   x0, hub_ptr              \n"
      "mov   x1, lr                   \n"
      "ldr   x16, push_stack          \n"
      "blr   x16                      \n"

      // Save the hook function's address to IP register
      "mov   x16, x0                  \n"

      // Restore parameter registers, XR(X8), LR
      "ldp   q6, q7, [sp, #0xb0]      \n"
      "ldp   q4, q5, [sp, #0x90]      \n"
      "ldp   q2, q3, [sp, #0x70]      \n"
      "ldp   q0, q1, [sp, #0x50]      \n"
      "ldp   x8, lr, [sp, #0x40]      \n"
      "ldp   x6, x7, [sp, #0x30]      \n"
      "ldp   x4, x5, [sp, #0x20]      \n"
      "ldp   x2, x3, [sp, #0x10]      \n"
      "ldp   x0, x1, [sp], #0xd0      \n"

      // Call hook function
      "br    x16                      \n"

      "bh_hub_trampo_template_data:"
      ".global bh_hub_trampo_template_data;"
      "push_stack:"
      ".quad 0;"
      "hub_ptr:"
      ".quad 0;");
#elif defined(__i386__)
  __asm__(
      "pushl  %ebp             \n"
      "movl   %esp, %ebp       \n"

      // the second param for bh_hub_push_stack(): return address
      "pushl  4(%ebp)          \n"

      // the first param for bh_hub_push_stack(): hub_ptr
      "call   pic_trampo       \n"
      "pic_trampo:             \n"
      "popl   %ecx             \n"
      "addl   $(hub_ptr - pic_trampo), %ecx\n"
      "movl   (%ecx), %eax     \n"
      "pushl  %eax             \n"

      // Call bh_hub_push_stack()
      "addl   $(push_stack - hub_ptr), %ecx\n"
      "movl   (%ecx), %eax     \n"
      "call   *%eax            \n"

      "movl   %ebp, %esp       \n"
      "popl   %ebp             \n"

      // Call hook function
      "jmp    *%eax\n"

      "bh_hub_trampo_template_data:"
      ".global bh_hub_trampo_template_data;"
      "push_stack:"
      ".word 0; .word 0;"
      "hub_ptr:"
      ".word 0; .word 0;");
#elif defined(__x86_64__)
  __asm__(
      "pushq   %rbp                      \n"
      "movq    %rsp, %rbp                \n"

      // Save caller-saved registers
      "subq    $192,  %rsp               \n"
      "movupd  %xmm0, 176(%rsp)          \n"
      "movupd  %xmm1, 160(%rsp)          \n"
      "movupd  %xmm2, 144(%rsp)          \n"
      "movupd  %xmm3, 128(%rsp)          \n"
      "movupd  %xmm4, 112(%rsp)          \n"
      "movupd  %xmm5,  96(%rsp)          \n"
      "movupd  %xmm6,  80(%rsp)          \n"
      "movupd  %xmm7,  64(%rsp)          \n"
      "movq    %rax,   56(%rsp)          \n"
      "movq    %rdi,   48(%rsp)          \n"
      "movq    %rsi,   40(%rsp)          \n"
      "movq    %rdx,   32(%rsp)          \n"
      "movq    %rcx,   24(%rsp)          \n"
      "movq    %r8,    16(%rsp)          \n"
      "movq    %r9,     8(%rsp)          \n"
      "movq    %r10,     (%rsp)          \n"

      // Call bh_hub_push_stack()
      "movq    hub_ptr(%rip), %rdi       \n"
      "movq    8(%rbp), %rsi             \n"
      "call    *push_stack(%rip)         \n"

      // Save the hook function's address to IP register
      "movq    %rax, %r11                \n"

      // Restore caller-saved registers
      "movupd  176(%rsp), %xmm0          \n"
      "movupd  160(%rsp), %xmm1          \n"
      "movupd  144(%rsp), %xmm2          \n"
      "movupd  128(%rsp), %xmm3          \n"
      "movupd  112(%rsp), %xmm4          \n"
      "movupd   96(%rsp), %xmm5          \n"
      "movupd   80(%rsp), %xmm6          \n"
      "movupd   64(%rsp), %xmm7          \n"
      "movq     56(%rsp), %rax           \n"
      "movq     48(%rsp), %rdi           \n"
      "movq     40(%rsp), %rsi           \n"
      "movq     32(%rsp), %rdx           \n"
      "movq     24(%rsp), %rcx           \n"
      "movq     16(%rsp), %r8            \n"
      "movq      8(%rsp), %r9            \n"
      "movq       (%rsp), %r10           \n"
      "addq    $192,      %rsp           \n"

      "movq    %rbp, %rsp                \n"
      "popq    %rbp                      \n"

      // Call hook function
      "jmp     *%r11                     \n"

      "bh_hub_trampo_template_data:"
      ".global bh_hub_trampo_template_data;"
      "push_stack:"
      ".quad 0;"
      "hub_ptr:"
      ".quad 0;");
#endif
}

static void *bh_hub_trampo_template_start(void) {
#if defined(__arm__) && defined(__thumb__)
  return (void *)((uintptr_t)&bh_hub_trampo_template - 1);
#else
  return (void *)&bh_hub_trampo_template;
#endif
}

static bh_hub_stack_t *bh_hub_stack_create(void) {
  // get stack from global cache
  for (size_t i = 0; i < BH_HUB_THREAD_MAX; i++) {
    uint8_t *used = &(bh_hub_stack_cache_used[i]);
    if (0 == *used) {
      uint8_t expected = 0;
      if (__atomic_compare_exchange_n(used, &expected, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        bh_hub_stack_t *stack = &(bh_hub_stack_cache[i]);
        stack->frames_cnt = 0;
        BH_LOG_DEBUG("hub: get stack from global cache[%zu] %p", i, (void *)stack);
        return stack;  // OK
      }
    }
  }

  // create new stack by mmap
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  void *buf = bh_safe_mmap(NULL, BH_HUB_STACK_SIZE, prot, flags, -1, 0);
  if (MAP_FAILED == buf) return NULL;  // failed
  bh_safe_prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)buf, BH_HUB_STACK_SIZE,
                (unsigned long)BH_HUB_STACK_NAME);
  bh_hub_stack_t *stack = (bh_hub_stack_t *)buf;
  stack->frames_cnt = 0;
  return stack;  // OK
}

static void bh_hub_stack_destroy(void *buf) {
  if (NULL == buf) return;

  if ((uintptr_t)bh_hub_stack_cache <= (uintptr_t)buf &&
      (uintptr_t)buf < ((uintptr_t)bh_hub_stack_cache + BH_HUB_THREAD_MAX * sizeof(bh_hub_stack_t))) {
    // return stack to global cache
    size_t i = ((uintptr_t)buf - (uintptr_t)bh_hub_stack_cache) / sizeof(bh_hub_stack_t);
    uint8_t *used = &(bh_hub_stack_cache_used[i]);
    if (1 != *used) abort();
    __atomic_store_n(used, 0, __ATOMIC_RELEASE);
    BH_LOG_DEBUG("hub: return stack to global cache[%zu] %p", i, buf);
  } else {
    // munmap stack
    bh_safe_munmap(buf, BH_HUB_STACK_SIZE);
  }
  bh_safe_pthread_setspecific(bh_hub_stack_reserved_tls_key, (const void *)1);
}

int bh_hub_init(void) {
  LIST_INIT(&bh_hub_delayed_destroy);
  pthread_mutex_init(&bh_hub_delayed_destroy_lock, NULL);

  // init TLS key
  if (__predict_false(0 != pthread_key_create(&bh_hub_stack_tls_key, bh_hub_stack_destroy))) return -1;
  if (__predict_false(0 != pthread_key_create(&bh_hub_stack_reserved_tls_key, NULL))) return -1;

  // init hub's stack cache
  if (__predict_false(NULL == (bh_hub_stack_cache = malloc(BH_HUB_THREAD_MAX * sizeof(bh_hub_stack_t)))))
    return -1;
  if (__predict_false(NULL == (bh_hub_stack_cache_used = calloc(BH_HUB_THREAD_MAX, sizeof(uint8_t)))))
    return -1;

  // init hub's trampoline manager
  size_t code_size = (uintptr_t)(&bh_hub_trampo_template_data) - (uintptr_t)(bh_hub_trampo_template_start());
  size_t data_size = sizeof(void *) + sizeof(void *);
  bh_trampo_init_mgr(&bh_hub_trampo_mgr, BH_HUB_TRAMPO_PAGE_NAME, code_size + data_size,
                     BH_HUB_TRAMPO_DELAY_SEC);

  return 0;
}

static void *bh_hub_push_stack(bh_hub_t *self, void *return_address) {
  bh_hub_stack_t *reserved_stack =
      (bh_hub_stack_t *)bh_safe_pthread_getspecific(bh_hub_stack_reserved_tls_key);
  if (reserved_stack != NULL) goto end;
  bh_hub_stack_t *stack = (bh_hub_stack_t *)bh_safe_pthread_getspecific(bh_hub_stack_tls_key);

  // create stack, only once
  if (__predict_false(NULL == stack)) {
    if (__predict_false(NULL == (stack = bh_hub_stack_create()))) goto end;
    bh_safe_pthread_setspecific(bh_hub_stack_tls_key, (void *)stack);
  }

  // check whether a recursive call occurred
  bool recursive = false;
  for (size_t i = stack->frames_cnt; i > 0; i--) {
    bh_hub_frame_t *frame = &stack->frames[i - 1];
    if (frame->orig_addr == self->orig_addr) {
      // recursive call found
      recursive = true;
      break;
    }
  }

  // find and return the first enabled proxy's function in the proxy-list
  // (does not include the original function)
  if (!recursive) {
    bh_hub_proxy_t *proxy;
    SLIST_FOREACH(proxy, &self->proxies, link) {
      if (proxy->enabled) {
        // push a new frame for the current proxy
        if (stack->frames_cnt >= BH_HUB_STACK_FRAME_MAX) goto end;
        stack->frames_cnt++;
        BH_LOG_DEBUG("hub: frames_cnt++ = %zu", stack->frames_cnt);
        bh_hub_frame_t *frame = &stack->frames[stack->frames_cnt - 1];
        frame->proxies = self->proxies;
        frame->orig_addr = self->orig_addr;
        frame->return_address = return_address;

        // return the first enabled proxy's function
        BH_LOG_DEBUG("hub: push_stack() return first enabled proxy %p", proxy->func);
        return proxy->func;
      }
    }
  }

  // if not found enabled proxy in the proxy-list, or recursive call found,
  // just return the original-function
end:
  BH_LOG_DEBUG("hub: push_stack() return orig_addr %p", (void *)self->orig_addr);
  return (void *)self->orig_addr;
}

void bh_hub_pop_stack(void *return_address) {
  bh_hub_stack_t *stack = (bh_hub_stack_t *)bh_safe_pthread_getspecific(bh_hub_stack_tls_key);
  if (0 == stack->frames_cnt) return;
  bh_hub_frame_t *frame = &stack->frames[stack->frames_cnt - 1];

  // only the first proxy will actually execute pop-stack()
  if (frame->return_address == return_address) {
    stack->frames_cnt--;
    BH_LOG_DEBUG("hub: frames_cnt-- = %zu", stack->frames_cnt);
  }
}

bh_hub_t *bh_hub_create(uintptr_t *trampo) {
  size_t code_size = (uintptr_t)(&bh_hub_trampo_template_data) - (uintptr_t)(bh_hub_trampo_template_start());
  size_t data_size = sizeof(void *) + sizeof(void *);

  bh_hub_t *self = malloc(sizeof(bh_hub_t));
  if (NULL == self) return NULL;
  SLIST_INIT(&self->proxies);
  pthread_mutex_init(&self->proxies_lock, NULL);
  self->orig_addr = 0;

  // alloc memory for trampoline
  if (0 == (self->trampo = bh_trampo_alloc(&bh_hub_trampo_mgr))) {
    free(self);
    return NULL;
  }

  // fill in code
  BH_SIG_TRY(SIGSEGV, SIGBUS) {
    memcpy((void *)self->trampo, bh_hub_trampo_template_start(), code_size);
  }
  BH_SIG_CATCH() {
    bh_trampo_free(&bh_hub_trampo_mgr, self->trampo);
    free(self);
    BH_LOG_WARN("hub: fill in code crashed");
    return NULL;
  }
  BH_SIG_EXIT

  // fill in data
  void **data = (void **)(self->trampo + code_size);
  *data++ = (void *)bh_hub_push_stack;
  *data = (void *)self;

  // clear CPU cache
  bh_util_clear_cache(self->trampo, code_size + data_size);

#if defined(__arm__) && defined(__thumb__)
  *trampo = self->trampo + 1;
#else
  *trampo = self->trampo;
#endif

  BH_LOG_INFO("hub: create trampo at %" PRIxPTR ", size %zu + %zu = %zu", *trampo, code_size, data_size,
              code_size + data_size);
  return self;
}

static void bh_hub_destroy_inner(bh_hub_t *self) {
  pthread_mutex_destroy(&self->proxies_lock);

  if (0 != self->trampo) bh_trampo_free(&bh_hub_trampo_mgr, self->trampo);

  while (!SLIST_EMPTY(&self->proxies)) {
    bh_hub_proxy_t *proxy = SLIST_FIRST(&self->proxies);
    SLIST_REMOVE_HEAD(&self->proxies, link);
    free(proxy);
  }

  free(self);
}

void bh_hub_destroy(bh_hub_t *self, bool with_delay) {
  struct timeval now;
  gettimeofday(&now, NULL);

  if (!LIST_EMPTY(&bh_hub_delayed_destroy)) {
    pthread_mutex_lock(&bh_hub_delayed_destroy_lock);
    bh_hub_t *hub, *hub_tmp;
    LIST_FOREACH_SAFE(hub, &bh_hub_delayed_destroy, link, hub_tmp) {
      if (now.tv_sec - hub->destroy_ts > BH_HUB_DELAY_SEC) {
        LIST_REMOVE(hub, link);
        bh_hub_destroy_inner(hub);
      }
    }
    pthread_mutex_unlock(&bh_hub_delayed_destroy_lock);
  }

  if (with_delay) {
    self->destroy_ts = now.tv_sec;
    bh_trampo_free(&bh_hub_trampo_mgr, self->trampo);
    self->trampo = 0;

    pthread_mutex_lock(&bh_hub_delayed_destroy_lock);
    LIST_INSERT_HEAD(&bh_hub_delayed_destroy, self, link);
    pthread_mutex_unlock(&bh_hub_delayed_destroy_lock);
  } else {
    bh_hub_destroy_inner(self);
  }
}

uintptr_t bh_hub_get_orig_addr(bh_hub_t *self) {
  return self->orig_addr;
}

uintptr_t *bh_hub_get_orig_addr_addr(bh_hub_t *self) {
  return &self->orig_addr;
}

int bh_hub_add_proxy(bh_hub_t *self, uintptr_t proxy_func) {
  int r = BYTEHOOK_STATUS_CODE_OK;

  pthread_mutex_lock(&self->proxies_lock);

  // check repeated funcion
  bh_hub_proxy_t *proxy;
  SLIST_FOREACH(proxy, &self->proxies, link) {
    if (proxy->enabled && proxy->func == (void *)proxy_func) {
      r = BYTEHOOK_STATUS_CODE_DUP;
      goto end;
    }
  }

  // try to re-enable an exists item
  SLIST_FOREACH(proxy, &self->proxies, link) {
    if (proxy->func == (void *)proxy_func) {
      if (!proxy->enabled) __atomic_store_n((bool *)&proxy->enabled, true, __ATOMIC_SEQ_CST);

      BH_LOG_INFO("hub: add(re-enable) func %" PRIxPTR, proxy_func);
      goto end;
    }
  }

  // create new item
  if (NULL == (proxy = malloc(sizeof(bh_hub_proxy_t)))) {
    r = BYTEHOOK_STATUS_CODE_OOM;
    goto end;
  }
  proxy->func = (void *)proxy_func;
  proxy->enabled = true;

  // insert to the head of the proxy-list
  // equivalent to: SLIST_INSERT_HEAD(&self->proxies, proxy, link);
  // but: __ATOMIC_RELEASE ensures readers see only fully-constructed item
  SLIST_NEXT(proxy, link) = SLIST_FIRST(&self->proxies);
  __atomic_store_n((uintptr_t *)(&SLIST_FIRST(&self->proxies)), (uintptr_t)proxy, __ATOMIC_RELEASE);
  BH_LOG_INFO("hub: add(new) func %" PRIxPTR, proxy_func);

end:
  pthread_mutex_unlock(&self->proxies_lock);
  return r;
}

int bh_hub_del_proxy(bh_hub_t *self, uintptr_t proxy_func, bool *have_enabled_proxy) {
  *have_enabled_proxy = false;

  pthread_mutex_lock(&self->proxies_lock);

  bh_hub_proxy_t *proxy;
  bool deleted = false;
  SLIST_FOREACH(proxy, &self->proxies, link) {
    if (proxy->func == (void *)proxy_func) {
      if (proxy->enabled) __atomic_store_n((bool *)&proxy->enabled, false, __ATOMIC_SEQ_CST);

      deleted = true;
      BH_LOG_INFO("hub: del func %" PRIxPTR, proxy_func);
    }

    if (proxy->enabled && !*have_enabled_proxy) *have_enabled_proxy = true;

    if (deleted && *have_enabled_proxy) break;
  }

  pthread_mutex_unlock(&self->proxies_lock);

  return deleted ? 0 : -1;
}

void *bh_hub_get_prev_func(void *func) {
  bh_hub_stack_t *stack = (bh_hub_stack_t *)bh_safe_pthread_getspecific(bh_hub_stack_tls_key);
  if (0 == stack->frames_cnt) bh_safe_abort();  // called in a non-hook status?
  bh_hub_frame_t *frame = &stack->frames[stack->frames_cnt - 1];

  // find and return the next enabled hook-function in the hook-chain
  bool found = false;
  bh_hub_proxy_t *proxy;
  SLIST_FOREACH(proxy, &(frame->proxies), link) {
    if (!found) {
      if (proxy->func == func) found = true;
    } else {
      if (proxy->enabled) break;
    }
  }
  if (NULL != proxy) {
    BH_LOG_DEBUG("hub: get_prev_func() return next enabled proxy %p", proxy->func);
    return proxy->func;
  }

  BH_LOG_DEBUG("hub: get_prev_func() return orig_addr %p", (void *)frame->orig_addr);
  // did not find, return the original-function
  return (void *)frame->orig_addr;
}

void *bh_hub_get_return_address(void) {
  bh_hub_stack_t *stack = (bh_hub_stack_t *)bh_safe_pthread_getspecific(bh_hub_stack_tls_key);
  if (0 == stack->frames_cnt) bh_safe_abort();  // called in a non-hook status?
  bh_hub_frame_t *frame = &stack->frames[stack->frames_cnt - 1];

  return frame->return_address;
}
