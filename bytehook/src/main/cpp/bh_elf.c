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

#include "bh_elf.h"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "bh_linker.h"
#include "bh_log.h"
#include "bh_sig.h"
#include "bh_sleb128.h"
#include "bh_switch.h"
#include "bh_util.h"

#define MAYBE_MAP_FLAG(x, from, to) (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)                                                        \
  (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
   MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

#define BH_ELF_IS_EXPORT_SYM(shndx) (SHN_UNDEF != (shndx))  // this is enough for .dynsym

#if defined(__arm__)
#define BH_ELF_R_JUMP_SLOT R_ARM_JUMP_SLOT  //.rel.plt
#define BH_ELF_R_GLOB_DAT  R_ARM_GLOB_DAT   //.rel.dyn
#define BH_ELF_R_ABS       R_ARM_ABS32      //.rel.dyn
#elif defined(__aarch64__)
#define BH_ELF_R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define BH_ELF_R_GLOB_DAT  R_AARCH64_GLOB_DAT
#define BH_ELF_R_ABS       R_AARCH64_ABS64
#elif defined(__i386__)
#define BH_ELF_R_JUMP_SLOT R_386_JMP_SLOT
#define BH_ELF_R_GLOB_DAT  R_386_GLOB_DAT
#define BH_ELF_R_ABS       R_386_32
#elif defined(__x86_64__)
#define BH_ELF_R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define BH_ELF_R_GLOB_DAT  R_X86_64_GLOB_DAT
#define BH_ELF_R_ABS       R_X86_64_64
#endif

#if defined(__LP64__)
#define BH_ELF_R_SYM(info)  ELF64_R_SYM(info)
#define BH_ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define BH_ELF_R_SYM(info)  ELF32_R_SYM(info)
#define BH_ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

#define RELOCATION_GROUPED_BY_INFO_FLAG         ((size_t)1)
#define RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG ((size_t)2)
#if defined(__LP64__)
#define RELOCATION_GROUPED_BY_ADDEND_FLAG ((size_t)4)
#endif
#define RELOCATION_GROUP_HAS_ADDEND_FLAG ((size_t)8)

static void bh_elf_iterate_aps2(bh_sleb128_decoder_t *decoder, bool (*callback)(Elf_Reloc *, void *),
                                void *arg) {
  size_t num_relocs;
  if (0 != bh_sleb128_decoder_next(decoder, &num_relocs)) return;

  Elf_Reloc reloc;
  if (0 != bh_sleb128_decoder_next(decoder, (size_t *)&reloc.r_offset)) return;

  for (size_t idx = 0; idx < num_relocs;) {
    size_t group_size;
    if (0 != bh_sleb128_decoder_next(decoder, &group_size)) return;
    size_t group_flags;
    if (0 != bh_sleb128_decoder_next(decoder, &group_flags)) return;
    size_t group_r_offset_delta = 0;

    if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
      if (0 != bh_sleb128_decoder_next(decoder, &group_r_offset_delta)) return;
    }
    if (group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) {
      if (0 != bh_sleb128_decoder_next(decoder, (size_t *)&reloc.r_info)) return;
    }

#if defined(__LP64__)
    const size_t group_flags_reloc =
        group_flags & (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG);
    if (group_flags_reloc == (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
      size_t val;
      if (0 != bh_sleb128_decoder_next(decoder, &val)) return;
      reloc.r_addend += val;
    } else {
      reloc.r_addend = 0;
    }
#else
    if (__predict_false(group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG)) return;
#endif

    for (size_t i = 0; i < group_size; i++) {
      if (group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
        reloc.r_offset += group_r_offset_delta;
      } else {
        size_t val;
        if (0 != bh_sleb128_decoder_next(decoder, &val)) return;
        reloc.r_offset += val;
      }
      if ((group_flags & RELOCATION_GROUPED_BY_INFO_FLAG) == 0) {
        if (0 != bh_sleb128_decoder_next(decoder, (size_t *)&reloc.r_info)) return;
      }
#if defined(__LP64__)
      if (group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG) {
        size_t val;
        if (0 != bh_sleb128_decoder_next(decoder, &val)) return;
        reloc.r_addend += val;
      }
#endif
      if (!callback(&reloc, arg)) return;
    }

    idx += group_size;
  }
}

static void bh_elf_parse_dynamic_unsafe(bh_elf_t *self, ElfW(Dyn) *dynamic) {
  // iterate the dynamic segment
  for (ElfW(Dyn) *entry = dynamic; entry && entry->d_tag != DT_NULL; entry++) {
    switch (entry->d_tag) {
        //.rel.plt / .rela.plt
      case DT_JMPREL:
        self->rel_plt = (const Elf_Reloc *)(self->load_bias + entry->d_un.d_ptr);
        break;
      case DT_PLTRELSZ:
        self->rel_plt_cnt = (size_t)entry->d_un.d_val / sizeof(Elf_Reloc);
        break;

        //.rel.dyn / .rela.dyn
      case DT_REL:
      case DT_RELA:
        self->rel_dyn = (const Elf_Reloc *)(self->load_bias + entry->d_un.d_ptr);
        break;
      case DT_RELSZ:
      case DT_RELASZ:
        self->rel_dyn_cnt = (size_t)entry->d_un.d_val / sizeof(Elf_Reloc);
        break;

        //.rel.dyn / .rela.dyn (APS2 format)
      case DT_ANDROID_REL:
      case DT_ANDROID_RELA:
        self->rel_dyn_aps2 = (uint8_t *)(self->load_bias + entry->d_un.d_ptr);
        break;
      case DT_ANDROID_RELSZ:
      case DT_ANDROID_RELASZ:
        self->rel_dyn_aps2_sz = (size_t)entry->d_un.d_val;
        break;

        //.dynsym
      case DT_SYMTAB:
        self->dynsym = (ElfW(Sym) *)(self->load_bias + entry->d_un.d_ptr);
        break;

        //.dynstr
      case DT_STRTAB:
        self->dynstr = (const char *)(self->load_bias + entry->d_un.d_ptr);
        break;

        //.hash
      case DT_HASH:
        self->sysv_hash.buckets_cnt = ((const uint32_t *)(self->load_bias + entry->d_un.d_ptr))[0];
        self->sysv_hash.chains_cnt = ((const uint32_t *)(self->load_bias + entry->d_un.d_ptr))[1];
        self->sysv_hash.buckets = &(((const uint32_t *)(self->load_bias + entry->d_un.d_ptr))[2]);
        self->sysv_hash.chains = &(self->sysv_hash.buckets[self->sysv_hash.buckets_cnt]);
        break;

        //.gnu.hash
      case DT_GNU_HASH:
        self->gnu_hash.buckets_cnt = ((const uint32_t *)(self->load_bias + entry->d_un.d_ptr))[0];
        self->gnu_hash.symoffset = ((const uint32_t *)(self->load_bias + entry->d_un.d_ptr))[1];
        self->gnu_hash.bloom_cnt = ((const uint32_t *)(self->load_bias + entry->d_un.d_ptr))[2];
        self->gnu_hash.bloom_shift = ((const uint32_t *)(self->load_bias + entry->d_un.d_ptr))[3];
        self->gnu_hash.bloom = (const ElfW(Addr) *)(self->load_bias + entry->d_un.d_ptr + 16);
        self->gnu_hash.buckets = (const uint32_t *)(&(self->gnu_hash.bloom[self->gnu_hash.bloom_cnt]));
        self->gnu_hash.chains = (const uint32_t *)(&(self->gnu_hash.buckets[self->gnu_hash.buckets_cnt]));
        break;

      default:
        break;
    }
  }

  // check and fix APS2
  if (NULL != self->rel_dyn_aps2) {
    char *rel = (char *)self->rel_dyn_aps2;
    if (self->rel_dyn_aps2_sz < 4 || rel[0] != 'A' || rel[1] != 'P' || rel[2] != 'S' || rel[3] != '2') {
      self->rel_dyn_aps2 = 0;
      self->rel_dyn_aps2_sz = 0;
    } else {
      self->rel_dyn_aps2 += 4;
      self->rel_dyn_aps2_sz -= 4;
    }
  }
}

static int bh_elf_parse_dynamic(bh_elf_t *self) {
  if (self->error) return -1;
  if (self->is_dyn_parsed) return 0;

  pthread_mutex_lock(&self->dyn_parse_lock);
  if (!self->is_dyn_parsed) {
    self->is_dyn_parsed = true;
    BH_SIG_TRY(SIGSEGV, SIGBUS) {
      ElfW(Dyn) *dynamic = NULL;
      for (size_t i = 0; i < self->dlpi_phnum; i++) {
        if (self->dlpi_phdr[i].p_type == PT_DYNAMIC) {
          dynamic = (ElfW(Dyn) *)(self->load_bias + self->dlpi_phdr[i].p_vaddr);
          break;
        }
      }
      if (NULL == dynamic)
        self->error = true;
      else
        bh_elf_parse_dynamic_unsafe(self, dynamic);
    }
    BH_SIG_CATCH()
    self->error = true;
    BH_SIG_EXIT
  }
  pthread_mutex_unlock(&self->dyn_parse_lock);

  return self->error ? -1 : 0;
}

bh_elf_t *bh_elf_create(struct dl_phdr_info *info) {
  if (0 == info->dlpi_phdr || NULL == info->dlpi_name || NULL == info->dlpi_phdr || 0 == info->dlpi_phnum)
    return NULL;

  bh_elf_t *self;
  if (NULL == (self = calloc(1, sizeof(bh_elf_t)))) return NULL;
  if (NULL == (self->pathname = strdup(info->dlpi_name))) {
    free(self);
    return NULL;
  }
  if (NULL == (self->switch_mgr = (void *)bh_switch_manager_create())) {
    free((void *)(uintptr_t)(self->pathname));
    free(self);
    return NULL;
  }
  self->ref_count = 0;
  pthread_mutex_init(&self->ref_mutex, NULL);
  pthread_cond_init(&self->ref_cond, NULL);
  self->exist = false;
  self->error = false;
#ifdef __LP64__
  self->cfi_hooked = false;
  self->cfi_hooked_ok = false;
  pthread_mutex_init(&self->cfi_hook_lock, NULL);
#endif
  self->load_bias = info->dlpi_addr;
  self->dlpi_phdr = info->dlpi_phdr;
  self->dlpi_phnum = info->dlpi_phnum;
  self->is_dyn_parsed = false;
  pthread_mutex_init(&self->dyn_parse_lock, NULL);

  return self;
}

void bh_elf_destroy(bh_elf_t **self) {
  if (NULL == self || NULL == *self) return;

  bh_switch_manager_destroy((void *)((*self)->switch_mgr));
  pthread_mutex_destroy(&(*self)->ref_mutex);
  pthread_cond_destroy(&(*self)->ref_cond);
  pthread_mutex_destroy(&(*self)->dyn_parse_lock);
#ifdef __LP64__
  pthread_mutex_destroy(&(*self)->cfi_hook_lock);
#endif
  if (NULL != (*self)->pathname) free((void *)(uintptr_t)(*self)->pathname);
  free(*self);
  *self = NULL;
}

void bh_elf_increment_ref_count(bh_elf_t *self) {
  int old_ref_count = __atomic_fetch_add(&self->ref_count, 1, __ATOMIC_SEQ_CST);
  //  BH_LOG_INFO("ELF: increment_ref_count to %d", old_ref_count + 1);

  if (__predict_false(INT_MAX == old_ref_count)) abort();
}

void bh_elf_decrement_ref_count(bh_elf_t *self) {
  int old_ref_count = __atomic_fetch_sub(&self->ref_count, 1, __ATOMIC_SEQ_CST);
  //  BH_LOG_INFO("ELF: decrement_ref_count to %d", old_ref_count - 1);

  if (__predict_false(0 == old_ref_count))
    abort();
  else if (1 == old_ref_count) {
    pthread_mutex_lock(&self->ref_mutex);
    if (__predict_false(__atomic_load_n(&self->waiter_count, __ATOMIC_RELAXED) > 0)) {
      pthread_cond_signal(&self->ref_cond);
      BH_LOG_INFO("ELF: decrement_ref_count send cond signal");
    }
    pthread_mutex_unlock(&self->ref_mutex);
  }
}

int bh_elf_get_ref_count(bh_elf_t *self) {
  return __atomic_load_n(&self->ref_count, __ATOMIC_ACQUIRE);
}

bool bh_elf_is_match(bh_elf_t *self, const char *name) {
  return bh_linker_elf_is_match(self->pathname, name);
}

bool bh_elf_get_error(bh_elf_t *self) {
  return self->error;
}

void bh_elf_set_error(bh_elf_t *self, bool error) {
  self->error = error;
}

#ifdef __LP64__
void bh_elf_cfi_hook_lock(bh_elf_t *self) {
  pthread_mutex_lock(&self->cfi_hook_lock);
}

void bh_elf_cfi_hook_unlock(bh_elf_t *self) {
  pthread_mutex_unlock(&self->cfi_hook_lock);
}
#endif

void bh_elf_set_exist(bh_elf_t *self) {
  self->exist = true;
}

void bh_elf_unset_exist(bh_elf_t *self) {
  self->exist = false;
}

bool bh_elf_is_exist(bh_elf_t *self) {
  return self->exist;
}

static int bh_elf_get_protect(bh_elf_t *self, void *addr) {
  for (size_t i = 0; i < self->dlpi_phnum; i++) {
    const ElfW(Phdr) *phdr = &(self->dlpi_phdr[i]);
    if (self->dlpi_phdr[i].p_type == PT_GNU_RELRO)
      if ((uintptr_t)addr >= (self->load_bias + phdr->p_vaddr) &&
          (uintptr_t)addr < (self->load_bias + phdr->p_vaddr + phdr->p_memsz))
        return PROT_READ;
  }

  for (size_t i = 0; i < self->dlpi_phnum; i++) {
    const ElfW(Phdr) *phdr = &(self->dlpi_phdr[i]);
    if (self->dlpi_phdr[i].p_type == PT_LOAD)
      if ((uintptr_t)addr >= (self->load_bias + phdr->p_vaddr) &&
          (uintptr_t)addr < (self->load_bias + phdr->p_vaddr + phdr->p_memsz))
        return PFLAGS_TO_PROT(phdr->p_flags);
  }

  return PROT_READ;
}

static uint32_t bh_elf_sysv_hash(const uint8_t *name) {
  uint32_t h = 0, g;

  while (*name) {
    h = (h << 4) + *name++;
    g = h & 0xf0000000;
    h ^= g;
    h ^= g >> 24;
  }
  return h;
}

static uint32_t bh_elf_gnu_hash(const uint8_t *name) {
  uint32_t h = 5381;

  while (*name) {
    h += (h << 5) + *name++;
  }
  return h;
}

static ElfW(Sym) *bh_elf_find_symbol_by_name_use_sysv_hash(bh_elf_t *self, const char *sym_name) {
  uint32_t hash = bh_elf_sysv_hash((const uint8_t *)sym_name);

  for (uint32_t i = self->sysv_hash.buckets[hash % self->sysv_hash.buckets_cnt]; 0 != i;
       i = self->sysv_hash.chains[i]) {
    ElfW(Sym) *sym = self->dynsym + i;
    unsigned char type = ELF_ST_TYPE(sym->st_info);
    if (STT_FUNC != type && STT_GNU_IFUNC != type && STT_NOTYPE != type)
      continue;  // find function only, allow no-type
    if (0 != strcmp(self->dynstr + sym->st_name, sym_name)) continue;
    return sym;
  }

  return NULL;
}

static ElfW(Sym) *bh_elf_find_symbol_by_name_use_gnu_hash(bh_elf_t *self, const char *sym_name) {
  uint32_t hash = bh_elf_gnu_hash((const uint8_t *)sym_name);

  static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
  size_t word = self->gnu_hash.bloom[(hash / elfclass_bits) % self->gnu_hash.bloom_cnt];
  size_t mask = 0 | (size_t)1 << (hash % elfclass_bits) |
                (size_t)1 << ((hash >> self->gnu_hash.bloom_shift) % elfclass_bits);

  // if at least one bit is not set, this symbol is surely missing
  if ((word & mask) != mask) return NULL;

  // ignore STN_UNDEF
  uint32_t i = self->gnu_hash.buckets[hash % self->gnu_hash.buckets_cnt];
  if (i < self->gnu_hash.symoffset) return NULL;

  // loop through the chain
  while (1) {
    ElfW(Sym) *sym = self->dynsym + i;
    unsigned char type = ELF_ST_TYPE(sym->st_info);
    uint32_t sym_hash = self->gnu_hash.chains[i - self->gnu_hash.symoffset];

    if ((hash | (uint32_t)1) == (sym_hash | (uint32_t)1) &&
        (STT_FUNC == type || STT_GNU_IFUNC == type ||
         STT_NOTYPE == type) &&  // find function only, allow no-type
        0 == strcmp(self->dynstr + sym->st_name, sym_name)) {
      return sym;
    }

    // chain ends with an element with the lowest bit set to 1
    if (sym_hash & (uint32_t)1) break;

    i++;
  }

  return NULL;
}

static int bh_elf_check_reloc(bh_elf_t *self, const Elf_Reloc *rel, const char *sym_name, void *callee_addr,
                              bh_array_t *gots, bh_array_t *prots, ElfW(Sym) **sym, bool plt_jump) {
  const uint32_t r_type = BH_ELF_R_TYPE(rel->r_info);
  const uint32_t r_sym = BH_ELF_R_SYM(rel->r_info);
  void *got_addr = (void *)(self->load_bias + rel->r_offset);

  if (plt_jump) {
    if (BH_ELF_R_JUMP_SLOT != r_type) return 0;  // continue;
  } else {
    if (BH_ELF_R_GLOB_DAT != r_type && BH_ELF_R_ABS != r_type) return 0;  // continue;
  }

  if (NULL == *sym) {
    if (0 == strcmp(self->dynstr + self->dynsym[r_sym].st_name, sym_name)) {
      *sym = &self->dynsym[r_sym];
      if (NULL != callee_addr && *((void **)got_addr) != callee_addr) return -1;  // callee mismatch
      if (0 != bh_array_push(gots, (uintptr_t)got_addr)) return -1;               // oom
      if (0 != bh_array_push(prots, (uintptr_t)bh_elf_get_protect(self, got_addr))) return -1;  // oom
    }
  } else {
    if (&self->dynsym[r_sym] == *sym) {
      if (NULL != callee_addr && *((void **)got_addr) != callee_addr) return -1;  // callee mismatch
      if (0 != bh_array_push(gots, (uintptr_t)got_addr)) return -1;               // oom
      if (0 != bh_array_push(prots, (uintptr_t)bh_elf_get_protect(self, got_addr))) return -1;  // oom
    }
  }

  return 0;  // continue;
}

static bool bh_elf_find_got_by_sym_unsafe_aps2_cb(Elf_Reloc *rel, void *arg) {
  void **pkg = (void **)arg;
  bh_elf_t *self = (bh_elf_t *)*pkg++;
  char *sym_name = (char *)*pkg++;
  void *callee_addr = (void *)*pkg++;
  bh_array_t *gots = (bh_array_t *)*pkg++;
  bh_array_t *prots = (bh_array_t *)*pkg++;
  ElfW(Sym) **sym = (ElfW(Sym) **)*pkg;

  return 0 == bh_elf_check_reloc(self, rel, sym_name, callee_addr, gots, prots, sym, false);
}

static ElfW(Sym) *bh_elf_find_export_func_symbol_by_symbol_name_unsafe(bh_elf_t *self, const char *sym_name) {
  ElfW(Sym) *sym = NULL;

  // from GNU hash (.gnu.hash -> .dynsym -> .dynstr), O(x) + O(1) + O(1)
  if (self->gnu_hash.buckets_cnt > 0) {
    sym = bh_elf_find_symbol_by_name_use_gnu_hash(self, sym_name);
    if (NULL != sym && BH_ELF_IS_EXPORT_SYM(sym->st_shndx)) return sym;
  }

  // from SYSV hash (.hash -> .dynsym -> .dynstr), O(x) + O(1) + O(1)
  if (self->sysv_hash.buckets_cnt > 0) {
    sym = bh_elf_find_symbol_by_name_use_sysv_hash(self, sym_name);
    if (NULL != sym && BH_ELF_IS_EXPORT_SYM(sym->st_shndx)) return sym;
  }

  return NULL;
}

static void *bh_elf_find_export_func_addr_by_symbol_name_unsafe(bh_elf_t *self, const char *sym_name) {
  ElfW(Sym) *sym = bh_elf_find_export_func_symbol_by_symbol_name_unsafe(self, sym_name);
  if (NULL == sym) return NULL;

  return (void *)(self->load_bias + sym->st_value);
}

void *bh_elf_find_export_func_addr_by_symbol_name(bh_elf_t *self, const char *sym_name) {
  if (self->error) return NULL;
  if (0 != bh_elf_parse_dynamic(self)) return NULL;

  void *addr = NULL;

  BH_SIG_TRY(SIGSEGV, SIGBUS) {
    addr = bh_elf_find_export_func_addr_by_symbol_name_unsafe(self, sym_name);
  }
  BH_SIG_CATCH() {
    self->error = true;
    addr = NULL;
  }
  BH_SIG_EXIT

  return addr;
}

static ElfW(Sym) *bh_elf_find_symbol_and_gots_by_symbol_name_unsafe(bh_elf_t *self, const char *sym_name,
                                                                    void *callee_addr, bh_array_t *gots,
                                                                    bh_array_t *prots) {
  ElfW(Sym) *sym = NULL;

  // From: SYSV hash (.hash -> .dynsym -> .dynstr), O(x) + O(1) + O(1)
  // Notice: If ELF is linked as "-Wl,--hash-style=gnu", there will be no .hash section.
  //         The SYSV hash contains both imported and exported symbols.
  if (self->sysv_hash.buckets_cnt > 0) sym = bh_elf_find_symbol_by_name_use_sysv_hash(self, sym_name);

  // From: GNU hash (.gnu.hash -> .dynsym -> .dynstr), O(x) + O(1) + O(1)
  // Notice: If ELF is linked as "-Wl,--hash-style=sysv", there will be no .gnu.hash section.
  //         The GNU hash only contains exported symbols.
  if (NULL == sym && self->gnu_hash.buckets_cnt > 0)
    sym = bh_elf_find_symbol_by_name_use_gnu_hash(self, sym_name);

  // If we have already found "sym" at this moment, then we do not need to use "strcmp()" to
  // compare "sym_name" in the following linear search, and the following search will be faster.

  // linear Search sym and GOTS in .rel.plt
  for (size_t i = 0; i < self->rel_plt_cnt; i++)
    if (0 != bh_elf_check_reloc(self, &(self->rel_plt[i]), sym_name, callee_addr, gots, prots, &sym, true))
      return NULL;

  // linear Search sym and GOTS in .rel.dyn
  for (size_t i = 0; i < self->rel_dyn_cnt; i++)
    if (0 != bh_elf_check_reloc(self, &(self->rel_dyn[i]), sym_name, callee_addr, gots, prots, &sym, false))
      return NULL;

  // linear Search sym and GOTS in .rel.dyn (APS2 format)
  uintptr_t pkg[6] = {(uintptr_t)self, (uintptr_t)sym_name, (uintptr_t)callee_addr,
                      (uintptr_t)gots, (uintptr_t)prots,    (uintptr_t)&sym};
  if (NULL != self->rel_dyn_aps2) {
    bh_sleb128_decoder_t decoder;
    bh_sleb128_decoder_init(&decoder, self->rel_dyn_aps2, self->rel_dyn_aps2_sz);
    bh_elf_iterate_aps2(&decoder, bh_elf_find_got_by_sym_unsafe_aps2_cb, pkg);
  }

  return sym;
}

ElfW(Sym) *bh_elf_find_symbol_and_gots_by_symbol_name(bh_elf_t *self, const char *sym_name, void *callee_addr,
                                                      bh_array_t *gots, bh_array_t *prots) {
  if (self->error) return NULL;
  if (0 != bh_elf_parse_dynamic(self)) return NULL;

  ElfW(Sym) *sym = NULL;

  BH_SIG_TRY(SIGSEGV, SIGBUS) {
    sym = bh_elf_find_symbol_and_gots_by_symbol_name_unsafe(self, sym_name, callee_addr, gots, prots);
  }
  BH_SIG_CATCH() {
    self->error = true;
    sym = NULL;
  }
  BH_SIG_EXIT

  return sym;
}
