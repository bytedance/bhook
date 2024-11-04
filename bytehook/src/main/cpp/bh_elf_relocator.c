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

// Created by Kelun Cai (caikelun@bytedance.com) on 2024-09-12.

#include "bh_elf_relocator.h"

#include <stdint.h>
#include <sys/mman.h>

#include "bh_array.h"
#include "bh_const.h"
#include "bh_elf.h"
#include "bh_log.h"
#include "bh_sig.h"
#include "bh_switch.h"
#include "bh_task.h"
#include "bh_util.h"
#include "bytehook.h"

#ifdef __LP64__
static int bh_elf_relocator_reloc_invisible(bh_elf_t *elf, const char *sym_name, uintptr_t new_func) {
  // get sym and gots
  bh_array_t gots = BH_ARRAY_INITIALIZER(&gots);
  bh_array_t prots = BH_ARRAY_INITIALIZER(&prots);
  ElfW(Sym) *sym = bh_elf_find_symbol_and_gots_by_symbol_name(elf, sym_name, NULL, &gots, &prots);
  if (NULL == sym || 0 == gots.count) {
    BH_LOG_INFO("reloc: CFI hook_single(%s, %s) NOSYM.", elf->pathname, sym_name);
    return 0;  // OK
  }

  // do reloc
  int r = bh_elf_relocator_reloc(elf, NULL, &gots, &prots, new_func, NULL);
  bh_array_free(&gots);
  bh_array_free(&prots);

  if (BYTEHOOK_STATUS_CODE_NOSYM == r) {
    BH_LOG_INFO("reloc: CFI hook_single(%s, %s) NOSYM.", elf->pathname, sym_name);
    return 0;  // OK
  } else if (0 == r) {
    BH_LOG_INFO("reloc: CFI hook_single(%s, %s) OK.", elf->pathname, sym_name);
    return 0;  // OK
  } else {
    BH_LOG_INFO("reloc: CFI hook_single(%s, %s) FAILED. errno: %d.", elf->pathname, sym_name, r);
    return -1;  // failed
  }
}

static void bh_elf_relocator_cfi_slowpath_proxy(uint64_t CallSiteTypeId, void *Ptr) {
  (void)CallSiteTypeId, (void)Ptr;
}

static void bh_elf_relocator_cfi_slowpath_diag_proxy(uint64_t CallSiteTypeId, void *Ptr, void *DiagData) {
  (void)CallSiteTypeId, (void)Ptr, (void)DiagData;
}

static bool bh_elf_relocator_hook_cfi(bh_elf_t *elf) {
  if (0 != bh_elf_relocator_reloc_invisible(elf, BH_CONST_SYM_CFI_SLOWPATH,
                                            (uintptr_t)bh_elf_relocator_cfi_slowpath_proxy))
    return false;
  if (0 != bh_elf_relocator_reloc_invisible(elf, BH_CONST_SYM_CFI_SLOWPATH_DIAG,
                                            (uintptr_t)bh_elf_relocator_cfi_slowpath_diag_proxy))
    return false;
  return true;
}

static bool bh_elf_relocator_check_hook_cfi(bh_elf_t *elf) {
  if (bh_util_get_api_level() >= __ANDROID_API_O__) {
    // hook __cfi_slowpath and __cfi_slowpath_diag (only once)
    if (!elf->cfi_hooked) {
      bh_elf_cfi_hook_lock(elf);
      if (!elf->cfi_hooked) {
        elf->cfi_hooked_ok = bh_elf_relocator_hook_cfi(elf);
        elf->cfi_hooked = true;
      }
      bh_elf_cfi_hook_unlock(elf);
    }

    if (!elf->cfi_hooked_ok) return false;
  }

  return true;
}
#else

static bool bh_elf_relocator_check_hook_cfi(bh_elf_t *elf) {
  (void)elf;
  return true;
}

#endif

void bh_elf_relocator_hook(bh_elf_t *elf, bh_task_t *task) {
  // check ELF
  if (bh_elf_get_error(elf)) {
    bh_task_do_hooked_callback(task, BYTEHOOK_STATUS_CODE_READ_ELF, elf->pathname, NULL);
    return;
  }

  // do CFI hook (only once foreach ELF caller)
  if (!bh_elf_relocator_check_hook_cfi(elf)) {
    bh_task_do_hooked_callback(task, BYTEHOOK_STATUS_CODE_CFI_HOOK_FAILED, elf->pathname, NULL);
    return;
  }

  // get sym and gots
  bh_array_t gots = BH_ARRAY_INITIALIZER(&gots);
  bh_array_t prots = BH_ARRAY_INITIALIZER(&prots);
  ElfW(Sym) *sym =
      bh_elf_find_symbol_and_gots_by_symbol_name(elf, task->sym_name, task->callee_addr, &gots, &prots);
  if (NULL == sym || 0 == gots.count) {
    bh_task_do_hooked_callback(task, BYTEHOOK_STATUS_CODE_NOSYM, elf->pathname, NULL);
    bh_array_free(&gots);
    bh_array_free(&prots);
    return;
  }

  // do hook
  uintptr_t orig_addr = 0;
  int r;
  if (task->is_invisible)
    r = bh_switch_hook_invisible(elf, task, sym, &gots, &prots, (uintptr_t)task->new_func, &orig_addr);
  else
    r = bh_switch_hook(elf, task, sym, &gots, &prots, (uintptr_t)task->new_func, &orig_addr);
  bh_task_do_hooked_callback(task, r, elf->pathname, (void *)orig_addr);
  bh_array_free(&gots);
  bh_array_free(&prots);
}

void bh_elf_relocator_unhook(bh_elf_t *elf, bh_task_t *task) {
  // check ELF
  if (bh_elf_get_error(elf)) {
    bh_task_do_hooked_callback(task, BYTEHOOK_STATUS_CODE_READ_ELF, elf->pathname, NULL);
    return;
  }

  // get sym and gots
  bh_array_t gots = BH_ARRAY_INITIALIZER(&gots);
  bh_array_t prots = BH_ARRAY_INITIALIZER(&prots);
  ElfW(Sym) *sym =
      bh_elf_find_symbol_and_gots_by_symbol_name(elf, task->sym_name, task->callee_addr, &gots, &prots);
  if (NULL == sym || 0 == gots.count) {
    bh_task_do_hooked_callback(task, BYTEHOOK_STATUS_CODE_NOSYM, elf->pathname, NULL);
    bh_array_free(&gots);
    bh_array_free(&prots);
    return;
  }

  // do hook
  int r = bh_switch_unhook(elf, sym, &gots, &prots, (uintptr_t)task->new_func);
  bh_task_do_hooked_callback(task, r, elf->pathname, NULL);
  bh_array_free(&gots);
  bh_array_free(&prots);
}

int bh_elf_relocator_reloc(bh_elf_t *elf, bh_task_t *task, bh_array_t *gots, bh_array_t *prots,
                           uintptr_t new_addr, uintptr_t *orig_addr) {
  // get original address
  uintptr_t real_orig_addr = 0;
  BH_SIG_TRY(SIGSEGV, SIGBUS) {
    real_orig_addr = (uintptr_t)(*((void **)gots->data[0]));
  }
  BH_SIG_CATCH() {
    return BYTEHOOK_STATUS_CODE_READ_ELF;
  }
  BH_SIG_EXIT

  if (NULL != orig_addr) *orig_addr = real_orig_addr;

  // do callback with BYTEHOOK_STATUS_CODE_ORIG_ADDR for manual-mode
  //
  // In manual mode, the caller needs to save the original function address
  // in the hooked callback, and then may call the original function through
  // this address in the proxy function. So we need to execute the hooked callback
  // first, and then execute the address replacement in the GOT, otherwise it
  // will cause a crash due to timing issues.
  bh_task_do_orig_func_callback(task, elf->pathname, (void *)real_orig_addr);

  for (size_t i = 0; i < gots->count; i++) {
    void *got = (void *)gots->data[i];
    int prot = (int)prots->data[i];

    // add write permission
    if (0 == (prot & PROT_WRITE)) {
      if (0 != bh_util_set_addr_protect(got, prot | PROT_WRITE)) return BYTEHOOK_STATUS_CODE_SET_PROT;
    }

    // replace the target function address by "new_func"
    BH_SIG_TRY(SIGSEGV, SIGBUS) {
      __atomic_store_n((uintptr_t *)got, (uintptr_t)new_addr, __ATOMIC_SEQ_CST);
    }
    BH_SIG_CATCH() {
      return BYTEHOOK_STATUS_CODE_SET_GOT;
    }
    BH_SIG_EXIT

    // delete write permission
    //    if (0 == (prot & PROT_WRITE)) bh_util_set_addr_protect(got, prot);
  }

  return BYTEHOOK_STATUS_CODE_OK;
}
