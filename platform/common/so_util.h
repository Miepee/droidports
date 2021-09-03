#ifndef __SO_UTIL_H__
#define __SO_UTIL_H__


#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include "elf.h"

#include <bits/wordsize.h>

#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ALIGN_MEM(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define ENSURE_SYMBOL(mod, symbol, ...) \
  { \
    if (symbol == NULL) { \
      const char *aliases[] = {__VA_ARGS__}; \
      for (int __i = 0; __i < ARRAY_SIZE(aliases); __i++) { \
        if (*(uintptr_t*)&symbol = (uintptr_t)so_symbol(mod, aliases[__i])) \
          break; \
      } \
      if (symbol == NULL) { \
        fatal_error("Symbol \"%s\" not found.\n", #symbol); \
        exit(-1); \
      } \
    } \
  }

// Typedef to general Elf types, depending on architecture
#if __WORDSIZE == 64
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Chdr Elf_Chdr;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Syminfo Elf_Syminfo;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Verdef Elf_Verdef;
typedef Elf64_Verdaux Elf_Verdaux;
typedef Elf64_Verneed Elf_Verneed;
typedef Elf64_Vernaux Elf_Vernaux;
typedef Elf64_auxv_t Elf_auxv_t;
typedef Elf64_Nhdr Elf_Nhdr;
typedef Elf64_Move Elf_Move;
//typedef Elf64_gptab Elf_gptabM;
//typedef Elf64_RegInfo Elf_RegInfo; doesnt exist?
typedef Elf64_Lib Elf_Lib;
typedef Elf64_Addr Elf_Addr;

#define ELF_ST_BIND(val) ELF64_ST_BIND(val)
#define ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#define ELF_ST_INFO(bind, type) ELF64_ST_INFO(bind, type)
#define ELF_ST_VISIBILITY(o) ELF64_ST_VISIBILITY(o) 
#define ELF_R_SYM(i) ELF64_R_SYM(i)
#define ELF_R_TYPE(i) ELF64_R_TYPE(i)
#define ELF_R_INFO(sym, type) ELF64_R_INFO(sym, type) 
#define ELF_M_SYM(info) ELF64_M_SYM(info) 
#define ELF_M_SIZE(info) ELF64_M_SIZE(info) 
#define ELF_M_INFO(sym, size) ELF64_M_INFO(sym, size) 

#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Chdr Elf_Chdr;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Syminfo Elf_Syminfo;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Rela Elf_Rela;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Verdef Elf_Verdef;
typedef Elf32_Verdaux Elf_Verdaux;
typedef Elf32_Verneed Elf_Verneed;
typedef Elf32_Vernaux Elf_Vernaux;
typedef Elf32_auxv_t Elf_auxv_t;
typedef Elf32_Nhdr Elf_Nhdr;
typedef Elf32_Move Elf_Move;
typedef Elf32_gptab Elf_gptabM;
typedef Elf32_RegInfo Elf_RegInfo;
typedef Elf32_Lib Elf_Lib;
typedef Elf32_Addr Elf_Addr;

#define ELF_ST_BIND(val) ELF32_ST_BIND(val)
#define ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#define ELF_ST_INFO(bind, type) ELF32_ST_INFO(bind, type)
#define ELF_ST_VISIBILITY(o) ELF32_ST_VISIBILITY(o) 
#define ELF_R_SYM(i) ELF32_R_SYM(i)
#define ELF_R_TYPE(i) ELF32_R_TYPE(i)
#define ELF_R_INFO(sym, type) ELF32_R_INFO(sym, type) 
#define ELF_M_SYM(info) ELF32_M_SYM(info) 
#define ELF_M_SIZE(info) ELF32_M_SIZE(info) 
#define ELF_M_INFO(sym, size) ELF32_M_INFO(sym, size)
#endif


ABI_ATTR typedef int (* init_array_t)();
typedef struct so_module {
  struct so_module *next;

  uintptr_t text_blockid, data_blockid;
  uintptr_t text_base, data_base;
  size_t text_size, data_size;

  Elf_Ehdr *ehdr;
  Elf_Phdr *phdr;
  Elf_Shdr *shdr;

  Elf_Dyn *dynamic;
  Elf_Sym *dynsym;
  Elf_Rel *reldyn;
  Elf_Rel *relplt;

  init_array_t *init_array;
  uint32_t *hash;

  int num_dynamic;
  int num_dynsym;
  int num_reldyn;
  int num_relplt;
  int num_init_array;

  char *soname;
  char *shstr;
  char *dynstr;
} so_module;

typedef struct {
  char *symbol;
  uintptr_t func;
} DynLibFunction;

typedef struct {
  char *symbol;
  uintptr_t hook;
  int opt;
} DynLibHooks;

void hook_address(uintptr_t addr, uintptr_t dst);
void hook_symbol(so_module *mod, const char *symbol, uintptr_t dst, int is_optional);
void hook_symbols(so_module *mod, DynLibHooks *hooks);

void so_flush_caches(so_module *mod);
int so_load(so_module *mod, const char *filename, uintptr_t load_addr, void *so_data, size_t sz);
int so_relocate(so_module *mod);
int so_resolve(so_module *mod);
void so_initialize(so_module *mod);
uintptr_t so_symbol(so_module *mod, const char *symbol);

//Platform Specific Implementations
int unrestricted_memcpy(void *dst, const void *src, size_t len);
uintptr_t block_alloc(int exec, uintptr_t base_addr, size_t sz);
void block_free(uintptr_t block, size_t sz);
void *block_get_base_address(uintptr_t block);
void so_flush_caches(so_module *mod);

// Defined on a per-port basis on their specific main.c files
extern DynLibFunction *so_static_patches[];    // Functions to be replaced in the binary
extern DynLibFunction *so_dynamic_libraries[]; // Functions to be resolved

#ifdef __cplusplus
};
#endif

#endif
