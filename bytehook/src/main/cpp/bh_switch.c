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

#include "bh_switch.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bh_config.h"
#include "bh_elf_relocator.h"
#include "bh_hub.h"
#include "bh_linker.h"
#include "bh_log.h"
#include "bh_safe.h"
#include "bh_sig.h"
#include "bh_task.h"
#include "bh_util.h"
#include "bytehook.h"
#include "queue.h"

// switch
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
typedef struct bh_switch {
  ElfW(Sym) *sym;  // key
  uintptr_t orig_addr;
  bh_hub_t *hub;
  TAILQ_ENTRY(bh_switch, ) link;
} bh_switch_t;
#pragma clang diagnostic pop

// switch list
typedef TAILQ_HEAD(bh_switch_list, bh_switch, ) bh_switch_list_t;

// switch manager
struct bh_switch_manager {
  bh_switch_list_t switches;
  pthread_rwlock_t switches_lock;
};

static int bh_switch_create(bh_switch_t **self, ElfW(Sym) *sym, uintptr_t *hub_trampo) {
  *self = malloc(sizeof(bh_switch_t));
  if (NULL == *self) return BYTEHOOK_STATUS_CODE_OOM;

  (*self)->sym = sym;
  (*self)->orig_addr = 0;
  (*self)->hub = NULL;

  if (NULL != hub_trampo) {
    if (NULL == ((*self)->hub = bh_hub_create(hub_trampo))) {
      free(*self);
      return BYTEHOOK_STATUS_CODE_NEW_TRAMPO;
    }
  }

  return 0;
}

static void bh_switch_destroy(bh_switch_t *self, bool hub_with_delay) {
  if (NULL != self->hub) bh_hub_destroy(self->hub, hub_with_delay);
  free(self);
}

static bh_switch_t *bh_switch_manager_find(bh_switch_manager_t *mgr, ElfW(Sym) *sym) {
  bh_switch_t *self = NULL;
  TAILQ_FOREACH(self, &mgr->switches, link)
  if (self->sym == sym) break;

  return self;
}

bh_switch_manager_t *bh_switch_manager_create(void) {
  bh_switch_manager_t *mgr = malloc(sizeof(bh_switch_manager_t));
  if (NULL == mgr) return NULL;

  TAILQ_INIT(&mgr->switches);
  pthread_rwlock_init(&mgr->switches_lock, NULL);
  return mgr;
}

void bh_switch_manager_destroy(bh_switch_manager_t *mgr) {
  bh_switch_t *self;
  pthread_rwlock_wrlock(&mgr->switches_lock);
  TAILQ_FOREACH(self, &mgr->switches, link)
  bh_switch_destroy(self, false);
  pthread_rwlock_unlock(&mgr->switches_lock);

  pthread_rwlock_destroy(&mgr->switches_lock);

  free(mgr);
}

static int bh_switch_hook_unique(bh_elf_t *elf, bh_task_t *task, ElfW(Sym) *sym, bh_array_t *gots,
                                 bh_array_t *prots, uintptr_t new_addr, uintptr_t *orig_addr) {
  bh_switch_manager_t *mgr = (bh_switch_manager_t *)elf->switch_mgr;

  pthread_rwlock_rdlock(&mgr->switches_lock);
  bh_switch_t *self = bh_switch_manager_find(mgr, sym);
  pthread_rwlock_unlock(&mgr->switches_lock);
  if (NULL != self) return BYTEHOOK_STATUS_CODE_DUP;

  // alloc new switch
  int r;
  if (0 != (r = bh_switch_create(&self, sym, NULL))) return r;

  bh_switch_t *useless = NULL;
  pthread_rwlock_wrlock(&mgr->switches_lock);  // SYNC - start

  // insert new switch to switch-list

  if (NULL != bh_switch_manager_find(mgr, sym)) {
    useless = self;
    r = BYTEHOOK_STATUS_CODE_DUP;
    goto end;
  }
  TAILQ_INSERT_TAIL(&mgr->switches, self, link);

  // do reloc & return original-address
  if (0 != (r = bh_elf_relocator_reloc(elf, task, gots, prots, new_addr, &self->orig_addr))) {
    TAILQ_REMOVE(&mgr->switches, self, link);
    useless = self;
    goto end;
  }
  *orig_addr = self->orig_addr;

end:
  pthread_rwlock_unlock(&mgr->switches_lock);  // SYNC - end
  if (NULL != useless) bh_switch_destroy(useless, false);
  return r;
}

static int bh_switch_hook_shared(bh_elf_t *elf, bh_task_t *task, ElfW(Sym) *sym, bh_array_t *gots,
                                 bh_array_t *prots, uintptr_t new_addr, uintptr_t *orig_addr) {
  int r;
  bh_switch_manager_t *mgr = (bh_switch_manager_t *)elf->switch_mgr;

  pthread_rwlock_rdlock(&mgr->switches_lock);  // SYNC(read) - start
  bh_switch_t *self = bh_switch_manager_find(mgr, sym);
  if (NULL != self) {  // already exists
    // return original-address
    *orig_addr = self->orig_addr;
    bh_task_do_orig_func_callback(task, elf->pathname, (void *)self->orig_addr);

    // add an new proxy to hub
    r = bh_hub_add_proxy(self->hub, new_addr);
    pthread_rwlock_unlock(&mgr->switches_lock);  // SYNC(read) - end
    return r;
  }
  pthread_rwlock_unlock(&mgr->switches_lock);  // SYNC(read) - end

  // first hook for this "sym"

  // alloc new switch
  uintptr_t hub_trampo;
  if (0 != (r = bh_switch_create(&self, sym, &hub_trampo))) return r;

  bh_switch_t *useless = NULL;
  pthread_rwlock_wrlock(&mgr->switches_lock);  // SYNC - start

  // insert new switch to switch-list
  bh_switch_t *exists = bh_switch_manager_find(mgr, sym);
  if (NULL != exists) {  // already exists
    // return original-address
    *orig_addr = exists->orig_addr;
    bh_task_do_orig_func_callback(task, elf->pathname, (void *)exists->orig_addr);

    // add an new proxy to hub
    useless = self;
    r = bh_hub_add_proxy(exists->hub, new_addr);
  } else {
    TAILQ_INSERT_TAIL(&mgr->switches, self, link);

    // do reloc & return original-address
    if (0 != (r = bh_elf_relocator_reloc(elf, task, gots, prots, hub_trampo,
                                         bh_hub_get_orig_addr_addr(self->hub)))) {
      TAILQ_REMOVE(&mgr->switches, self, link);
      useless = self;
      goto end;
    }
    self->orig_addr = bh_hub_get_orig_addr(self->hub);
    *orig_addr = self->orig_addr;

    // add proxy to hub
    if (0 != (r = bh_hub_add_proxy(self->hub, new_addr))) {
      bh_elf_relocator_reloc(elf, NULL, gots, prots, self->orig_addr, NULL);
      TAILQ_REMOVE(&mgr->switches, self, link);
      useless = self;
      goto end;
    }
  }

end:
  pthread_rwlock_unlock(&mgr->switches_lock);  // SYNC - end
  if (NULL != useless) bh_switch_destroy(useless, false);

  return r;
}

int bh_switch_hook(bh_elf_t *elf, bh_task_t *task, ElfW(Sym) *sym, bh_array_t *gots, bh_array_t *prots,
                   uintptr_t new_addr, uintptr_t *orig_addr) {
  int r;
  if (BYTEHOOK_IS_MANUAL_MODE)
    r = bh_switch_hook_unique(elf, task, sym, gots, prots, new_addr, orig_addr);
  else
    r = bh_switch_hook_shared(elf, task, sym, gots, prots, new_addr, orig_addr);

  if (0 == r)
    BH_LOG_INFO("switch: hook in %s mode OK: sym %" PRIxPTR ", new_addr %" PRIxPTR ", orig_addr %" PRIxPTR,
                BYTEHOOK_IS_MANUAL_MODE ? "MANUAL" : "AUTOMATIC", (uintptr_t)sym, new_addr, *orig_addr);

  return r;
}

static int bh_switch_hook_unique_invisible(bh_elf_t *elf, bh_task_t *task, bh_array_t *gots,
                                           bh_array_t *prots, uintptr_t new_addr, uintptr_t *orig_addr) {
  bh_switch_manager_t *mgr = (bh_switch_manager_t *)elf->switch_mgr;

  pthread_rwlock_wrlock(&mgr->switches_lock);  // SYNC - start

  // do reloc & return original-address
  int r = bh_elf_relocator_reloc(elf, task, gots, prots, new_addr, orig_addr);

  pthread_rwlock_unlock(&mgr->switches_lock);  // SYNC - end

  return r;
}

int bh_switch_hook_invisible(bh_elf_t *elf, bh_task_t *task, ElfW(Sym) *sym, bh_array_t *gots,
                             bh_array_t *prots, uintptr_t new_addr, uintptr_t *orig_addr) {
  int r;
  if (BYTEHOOK_IS_MANUAL_MODE)
    r = bh_switch_hook_unique_invisible(elf, task, gots, prots, new_addr, orig_addr);
  else
    r = bh_switch_hook_shared(elf, task, sym, gots, prots, new_addr, orig_addr);

  if (0 == r)
    BH_LOG_INFO("switch: hook(invisible) in %s mode OK: sym %" PRIxPTR ", new_addr %" PRIxPTR
                ", orig_addr %" PRIxPTR,
                BYTEHOOK_IS_MANUAL_MODE ? "MANUAL" : "AUTOMATIC", (uintptr_t)sym, new_addr, *orig_addr);
  return r;
}

static int bh_switch_unhook_unique(bh_elf_t *elf, ElfW(Sym) *sym, bh_array_t *gots, bh_array_t *prots,
                                   uintptr_t *orig_addr) {
  int r;
  bh_switch_manager_t *mgr = (bh_switch_manager_t *)elf->switch_mgr;
  bh_switch_t *useless = NULL;

  pthread_rwlock_wrlock(&mgr->switches_lock);  // SYNC - start

  bh_switch_t *self = bh_switch_manager_find(mgr, sym);
  if (NULL == self) {
    r = BYTEHOOK_ERRNO_NOT_FOUND;
    goto end;
  }

  r = bh_elf_relocator_reloc(elf, NULL, gots, prots, self->orig_addr, NULL);
  *orig_addr = self->orig_addr;

  TAILQ_REMOVE(&mgr->switches, self, link);
  useless = self;

end:
  pthread_rwlock_unlock(&mgr->switches_lock);  // SYNC - end
  if (NULL != useless) bh_switch_destroy(useless, false);
  return r;
}

static int bh_switch_unhook_shared(bh_elf_t *elf, ElfW(Sym) *sym, bh_array_t *gots, bh_array_t *prots,
                                   uintptr_t new_addr, uintptr_t *orig_addr) {
  int r;
  bh_switch_manager_t *mgr = (bh_switch_manager_t *)elf->switch_mgr;
  bh_switch_t *useless = NULL;

  pthread_rwlock_wrlock(&mgr->switches_lock);  // SYNC - start

  bh_switch_t *self = bh_switch_manager_find(mgr, sym);
  if (NULL == self) {
    r = BYTEHOOK_ERRNO_NOT_FOUND;
    goto end;
  }
  *orig_addr = self->orig_addr;

  // delete proxy in hub
  bool have_enabled_proxy;
  if (0 != bh_hub_del_proxy(self->hub, new_addr, &have_enabled_proxy)) {
    r = BYTEHOOK_ERRNO_NOT_FOUND;
    goto end;
  }
  r = 0;

  // unhook inst, remove current switch from switch-list
  if (!have_enabled_proxy) {
    r = bh_elf_relocator_reloc(elf, NULL, gots, prots, self->orig_addr, NULL);
    TAILQ_REMOVE(&mgr->switches, self, link);
    useless = self;
  }

end:
  pthread_rwlock_unlock(&mgr->switches_lock);  // SYNC - end
  if (NULL != useless) bh_switch_destroy(useless, true);
  return r;
}

int bh_switch_unhook(bh_elf_t *elf, ElfW(Sym) *sym, bh_array_t *gots, bh_array_t *prots, uintptr_t new_addr) {
  int r;
  uintptr_t orig_addr;
  if (BYTEHOOK_IS_MANUAL_MODE) {
    r = bh_switch_unhook_unique(elf, sym, gots, prots, &orig_addr);
  } else {
    r = bh_switch_unhook_shared(elf, sym, gots, prots, new_addr, &orig_addr);
  }

  if (0 == r)
    BH_LOG_INFO("switch: unhook in %s mode OK: sym %" PRIxPTR ", new_addr %" PRIxPTR ", orig_addr %" PRIxPTR,
                BYTEHOOK_IS_MANUAL_MODE ? "MANUAL" : "AUTOMATIC", (uintptr_t)sym, new_addr, orig_addr);

  return r;
}
