#ifndef __SDB_H__
#define __SDB_H__

#include <elf.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>

#define REGISTER_SIZE   10
#define COMMAND_SIZE    16
#define VALUE_SIZE      20
#define ADDRESS_SIZE    20
#define BYTE_SIZE       32
#define ASM_SIZE        64
#define CONTENT_SIZE    80
#define TOKEN_SIZE      1024
#define BUFFER_SIZE     4096

typedef struct {
    uint8_t   e_ident[16];    // Magic number and other information
    uint16_t  e_type;         // Object file type
    uint16_t  e_machine;      // Architecture
    uint32_t  e_version;      // Object file version
    uint64_t  e_entry;        // Entry point virtual address
    uint64_t  e_phoff;        // Program header table file offset
    uint64_t  e_shoff;        // Section header table file offset
    uint32_t  e_flags;        // Processor-specific flags
    uint16_t  e_ehsize;       // ELF header size in bytes
    uint16_t  e_phentsize;    // Program header table entry size
    uint16_t  e_phnum;        // Program header table entry count
    uint16_t  e_shentsize;    // Section header table entry size
    uint16_t  e_shnum;        // Section header table entry count
    uint16_t  e_shstrndx;     // Section header string table index
} Elf64Hdr;

typedef struct {
    pid_t           pid;
    Elf64_Ehdr      header;
    csh             handle;
    char            filename[PATH_MAX];
} sdb_t;

sdb_t*  sdb_create();
bool    sdb_load_status(sdb_t *sdb);
bool    sdb_running_status(sdb_t *sdb);

void    sdb_continue(sdb_t *sdb);
void    sdb_disasm(sdb_t *sdb, char *address);
void    sdb_dump(sdb_t *sdb, char *address);
void    sdb_help(void);
void    sdb_get(sdb_t *sdb, char *register_name);
void    sdb_getregs(sdb_t *sdb);
void    sdb_load(sdb_t *sdb, char *filename);
void    sdb_run(sdb_t *sdb);
void    sdb_vmmap(sdb_t *sdb);
void    sdb_set(sdb_t *sdb, char *register_name, unsigned long long value);
void    sdb_step(sdb_t *sdb);
void    sdb_start(sdb_t *sdb);

#endif
