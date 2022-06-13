#include "sdb.h"

char *help_msg[] = {
    "- break {instruction-address}: add a break point", 
    "- cont: continue execution", 
    "- delete {break-point-id}: remove a break point",
    "- disasm addr: disassemble instructions in a file or a memory region", 
    "- dump addr: dump memory content", 
    "- exit: terminate the debugger", 
    "- get reg: get a single value from a register", 
    "- getregs: show registers", 
    "- help: show this message", 
    "- list: list break points", 
    "- load {path/to/a/program}: load a program", 
    "- run: run the program", 
    "- vmmap: show memory layout", 
    "- set reg val: get a single value to a register", 
    "- si: step into instruction", 
    "- start: start the program and stop at the first instruction"
};

sdb_t* sdb_create(void) {
    sdb_t *sdb = (sdb_t*) malloc(sizeof(sdb_t));

    sdb->pid = -1; sdb->text_size = 0; sdb->text_address = 0;
    cs_open(CS_ARCH_X86, CS_MODE_64, &(sdb->handle));

    memset(sdb->filename, 0, sizeof(sdb->filename));
    memset(&sdb->breakpoints, 0, sizeof(bp_t));
    memset(&sdb->elf_header, 0, sizeof(Elf64Ehdr)); 
    memset(&sdb->section_header, 0, sizeof(Elf64Shdr));
    
    return sdb;
}

bool sdb_load_status(sdb_t *sdb) {
    return (strcmp(sdb->filename, "") != 0);
}

bool sdb_running_status(sdb_t *sdb) {
    return (sdb->pid != -1);
}

void sdb_breakpoints(sdb_t *sdb) {
    for (int i = 0; i < BREAK_SIZE; i++) {
        bp_t *bp = &(sdb->breakpoints[i]);

        if (!bp->used) break;

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

        if (regs.rip == bp->address) {
            ptrace(PTRACE_SINGLESTEP, sdb->pid, 0, 0);
            
            if (waitpid(sdb->pid, 0, 0) < 0) {
                perror("waitpid error"); exit(-1);
            }
        }

        unsigned long long word = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->address, 0);
        if ((word & 0xff) == 0xcc) continue;
        bp->origin = word;

        ptrace(PTRACE_POKETEXT, sdb->pid, bp->address, (bp->origin & 0xffffffffffffff00) | 0xcc);
    }
}

void sdb_break(sdb_t *sdb, char *address) {
    if (!strcmp(address, "")) {
        fprintf(stdout, "** no addr is given\n"); return;
    }

    unsigned long long number = strtoll(address, NULL, 0);

    if (number < sdb->text_address || number >= sdb->text_address + sdb->text_size) {
        fprintf(stdout, "** the address is out of the rage of the text segment\n"); return;
    }

    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    bp_t *bp;

    for (int i = 0; i < BREAK_SIZE; i++) {
        if (!sdb->breakpoints[i].used) {
            bp = &(sdb->breakpoints[i]); break;
        }
    }

    bp->used = true; bp->address = number; sdb_breakpoints(sdb);
}

void sdb_continue(sdb_t *sdb) {
    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "state must be RUNNING\n"); return;
    }
    
    int status; sdb_breakpoints(sdb); ptrace(PTRACE_CONT, sdb->pid, 0, 0);

    while (waitpid(sdb->pid, &status, 0) > 0) {
        if (!WIFSTOPPED(status)) continue;

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

        for (int i = 0; i < BREAK_SIZE; i++) {
            bp_t *bp = &(sdb->breakpoints[i]);

            if (!bp->used) break;

            if (bp->address == regs.rip - 1) {
                ptrace(PTRACE_POKETEXT, sdb->pid, bp->address, bp->origin);
                regs.rip--; ptrace(PTRACE_SETREGS, sdb->pid, 0, &regs);

                cs_insn *insn; size_t count;
                unsigned long long assembly = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->address, 0);

                if ((count = cs_disasm(sdb->handle, (uint8_t*) &assembly, 8, bp->address, 0, &insn)) > 0) {
                    char byte[BYTE_SIZE], bytes[BYTE_SIZE]; 
                    memset(byte, 0, sizeof(byte)); memset(bytes, 0, sizeof(bytes));

                    for (size_t j = 0; j < insn[0].size; j++) {
                        snprintf(byte, BYTE_SIZE, "%02x ", insn[0].bytes[j]);
                        strncat(bytes, byte, strlen(byte));
                    }

                    fprintf(stdout, "** breakpoint @\t\t%lx: %-15s\t\t\t%s\t%s\n", 
                        insn[0].address, bytes, insn[0].mnemonic, insn[0].op_str
                    );

                    cs_free(insn, count); return;
                }
            }
       }
    }

    if (WIFEXITED(status)) {
        fprintf(stdout, "** child process %d terminated normally (code %d)\n", sdb->pid, status); 
    } else {
        fprintf(stdout, "** child process %d terminated with error (code %d)\n", sdb->pid, status);
    }

    sdb->pid = -1;
}

void sdb_delete(sdb_t *sdb, char *index) {
    long int number = strtol(index, NULL, 10);

    if (!strcmp(index, "")) {
        fprintf(stdout, "** no addr is given\n"); return;
    }

    if (number < 0 || number >= BREAK_SIZE || !sdb->breakpoints[number].used) {
        fprintf(stdout, "** breakpoint %ld does not exist\n", number); return;
    }

    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    bp_t *bp = &(sdb->breakpoints[number]);
    unsigned long long word = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->address, 0);

    if ((word & 0xff) == 0xcc) {
        ptrace(PTRACE_POKETEXT, sdb->pid, bp->address, bp->origin);
    }

    for (int i = number; i < BREAK_SIZE; i++) {
        if (!sdb->breakpoints[i].used) break;
        sdb->breakpoints[i] = sdb->breakpoints[i + 1];
    }
}

void sdb_disasm(sdb_t *sdb, char *address) {
    if (!strcmp(address, "")) {
        fprintf(stdout, "** no addr is given\n"); return;
    }

    unsigned long long base = strtoll(address, NULL, 0);

    if (base < sdb->text_address || base >= sdb->text_address + sdb->text_size) {
        fprintf(stdout, "** the address is out of the range of the text segment\n"); return;
    }

    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    for (int i = 0; i < BREAK_SIZE; i++) {
        if (!sdb->breakpoints[i].used) break;
        bp_t *bp = &(sdb->breakpoints[i]);
        ptrace(PTRACE_POKETEXT, sdb->pid, bp->address, bp->origin);
    }

    unsigned long long ptr = base;
    char assembly[ASM_SIZE]; memset(assembly, 0, sizeof(assembly));

    for (; ptr < base + sizeof(assembly); ptr += 8) {
        errno = 0; long long word = ptrace(PTRACE_PEEKTEXT, sdb->pid, ptr, 0);
        if (errno != 0) break;
        memcpy(&assembly[ptr - base], &word, 8);
    }

    sdb_breakpoints(sdb); cs_insn *insn; size_t count;

    if ((count = cs_disasm(sdb->handle, (uint8_t*) assembly, ptr - base, base, 0, &insn)) > 0) {
        for (size_t i = 0; i < count && i < 10; i++) {
            char bytes[BYTE_SIZE]; memset(bytes, 0, sizeof(bytes));

            for (size_t j = 0; j < insn[i].size; j++) {
                char byte[BYTE_SIZE]; memset(byte, 0, sizeof(byte));
                snprintf(byte, BYTE_SIZE, "%02x ", insn[i].bytes[j]);
                strncat(bytes, byte, strlen(byte));
            }

            if (insn[i].address < sdb->text_address || insn[i].address >= sdb->text_address + sdb->text_size) {
                fprintf(stdout, "** the address is out of the range of the text segment\n"); break;
            }

            fprintf(stdout, "\t%lx: %-15s\t\t\t%s\t%s\n", 
                insn[i].address, bytes, insn[i].mnemonic, insn[i].op_str
            );
        }

        cs_free(insn, count);
    }
}

void sdb_dump(sdb_t *sdb, char *address) {
    if (!strcmp(address, "")) {
        fprintf(stdout, "** no addr is given\n"); return;
    }

    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    char content[CONTENT_SIZE]; memset(content, 0, sizeof(content));
    unsigned long long base = strtoll(address, NULL, 0), ptr = base;

    for (; ptr < base + sizeof(content); ptr += 8) {
        errno = 0; long long word = ptrace(PTRACE_PEEKTEXT, sdb->pid, ptr, 0);
        if (errno != 0) break;
        memcpy(&content[ptr - base], &word, 8);
    }

    for (int i = 0; i < 5; i++) {
        fprintf(stdout, "%10llx:", base + i * 16);

        for (int j = 0; j < 16; j++) {
            fprintf(stdout, " %02x", (unsigned char) content[i * 16 + j]);
        }

        fprintf(stdout, " |");

        for (int j = 0; j < 16; j++) {
            if (isprint(content[i * 16 + j])) {
                fprintf(stdout, "%c", content[i * 16 + j]);
            } else {
                fprintf(stdout, ".");
            }
        }

        fprintf(stdout, "|\n");
    }
}

void sdb_get(sdb_t *sdb, char *register_name) {
    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state mush be RUNNING\n"); return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

    if (!strcmp(register_name, "rax")) {
        fprintf(stdout, "rax = %lld (0x%llx)\n", regs.rax, regs.rax);
    } else if (!strcmp(register_name, "rbx")) {
        fprintf(stdout, "rbx = %lld (0x%llx)\n", regs.rbx, regs.rbx);
    } else if (!strcmp(register_name, "rcx")) {
        fprintf(stdout, "rcx = %lld (0x%llx)\n", regs.rcx, regs.rcx);
    } else if (!strcmp(register_name, "rdx")) {
        fprintf(stdout, "rdx = %lld (0x%llx)\n", regs.rdx, regs.rdx);
    } else if (!strcmp(register_name, "r8")) {
        fprintf(stdout, "r8 = %lld (0x%llx)\n", regs.r8, regs.r8);
    } else if (!strcmp(register_name, "r9")) {
        fprintf(stdout, "r9 = %lld (0x%llx)\n", regs.r9, regs.r9);
    } else if (!strcmp(register_name, "r10")) {
        fprintf(stdout, "r10 = %lld (0x%llx)\n", regs.r10, regs.r10);
    } else if (!strcmp(register_name, "r11")) {
        fprintf(stdout, "r11 = %lld (0x%llx)\n", regs.r11, regs.r11);
    } else if (!strcmp(register_name, "r12")) {
        fprintf(stdout, "r12 = %lld (0x%llx)\n", regs.r12, regs.r12);
    } else if (!strcmp(register_name, "r13")) {
        fprintf(stdout, "r13 = %lld (0x%llx)\n", regs.r13, regs.r13);
    } else if (!strcmp(register_name, "r14")) {
        fprintf(stdout, "r14 = %lld (0x%llx)\n", regs.r14, regs.r14);
    } else if (!strcmp(register_name, "r15")) {
        fprintf(stdout, "r15 = %lld (0x%llx)\n", regs.r15, regs.r15);
    } else if (!strcmp(register_name, "rdi")) {
        fprintf(stdout, "rdi = %lld (0x%llx)\n", regs.rdi, regs.rdi);
    } else if (!strcmp(register_name, "rsi")) {
        fprintf(stdout, "rsi = %lld (0x%llx)\n", regs.rsi, regs.rsi);
    } else if (!strcmp(register_name, "rbp")) {
        fprintf(stdout, "rbp = %lld (0x%llx)\n", regs.rbp, regs.rbp);
    } else if (!strcmp(register_name, "rsp")) {
        fprintf(stdout, "rsp = %lld (0x%llx)\n", regs.rsp, regs.rsp);
    } else if (!strcmp(register_name, "rip")) {
        fprintf(stdout, "rip = %lld (0x%llx)\n", regs.rip, regs.rip);
    } else if (!strcmp(register_name, "flags")) {
        fprintf(stdout, "flags = %lld (0x%llx)\n", regs.eflags, regs.eflags);
    }
}

void sdb_getregs(sdb_t *sdb) {
    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    struct user_regs_struct regs; 
    ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

    fprintf(stdout, "RAX %-18llx RBX %-18llx RCX %-18llx RDX %-18llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
    fprintf(stdout, "R8  %-18llx R9  %-18llx R10 %-18llx R11 %-18llx\n", regs.r8,  regs.r9,  regs.r10, regs.r11);
    fprintf(stdout, "R12 %-18llx R13 %-18llx R14 %-18llx R15 %-18llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
    fprintf(stdout, "RDI %-18llx RSI %-18llx RBP %-18llx RSP %-18llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
    fprintf(stdout, "RIP %-18llx FLAGS %016llx\n", regs.rip, regs.eflags);
}

void sdb_help(void) {
    for (int i = 0; i < 16; i++) {
        fprintf(stdout, "%s\n", help_msg[i]);
    }
}

void sdb_list(sdb_t *sdb) {
    for (int i = 0; i < BREAK_SIZE; i++) {
        if (!sdb->breakpoints[i].used) break;
        fprintf(stdout, "%3d: %6llx\n", i, sdb->breakpoints[i].address);
    }
}

void sdb_load(sdb_t *sdb, char *filename) {
    if (sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be NOT LOADED\n"); return;
    }

    FILE *fp = fopen(filename, "r");

    if (fp == NULL) {
        perror("fopen error"); exit(-1);
    }

    fread(&sdb->elf_header, 1, sizeof(sdb->elf_header), fp);
    fseek(fp, sdb->elf_header.e_shoff + sdb->elf_header.e_shstrndx * sizeof(sdb->section_header), SEEK_SET);
    fread(&sdb->section_header, 1, sizeof(sdb->section_header), fp);

    char section_name[sdb->section_header.sh_size]; 
    memset(section_name, 0, sizeof(section_name));

    fseek(fp, sdb->section_header.sh_offset, SEEK_SET);
    fread(section_name, 1, sdb->section_header.sh_size, fp);

    for (int i = 0; i < sdb->elf_header.e_shnum; i++) {
        fseek(fp, sdb->elf_header.e_shoff + i * sizeof(sdb->section_header), SEEK_SET);
        fread(&sdb->section_header, 1, sizeof(sdb->section_header), fp);

        if (!strcmp(section_name + sdb->section_header.sh_name, ".text")) {
            sdb->text_address = sdb->section_header.sh_addr;
            sdb->text_size = sdb->section_header.sh_size; break;
        }
    }

    snprintf(sdb->filename, PATH_MAX, "%s", filename);
    fprintf(stdout, "** program '%s' loaded. entry point 0x%lx\n", sdb->filename, sdb->elf_header.e_entry);
}

void sdb_run(sdb_t *sdb) {
    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be LOADED or RUNNING\n"); return;
    }

    int status;

    if (sdb_running_status(sdb)) {
        fprintf(stdout, "** program %s is already running\n", sdb->filename);
    } else {
        if ((sdb->pid = fork()) < 0) {
            perror("fork error"); exit(-1);
        } else if (sdb->pid == 0) {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
                perror("ptrace TRACEME error"); exit(-1);
            }

            execlp(sdb->filename, sdb->filename, NULL);
        } else {
            if (waitpid(sdb->pid, &status, 0) < 0) {
                perror("waitpid error"); exit(-1);
            }

            ptrace(PTRACE_SETOPTIONS, sdb->pid, 0, PTRACE_O_EXITKILL);
            fprintf(stdout, "** pid %d\n", sdb->pid);
        }  
    }

    sdb_breakpoints(sdb); ptrace(PTRACE_CONT, sdb->pid, 0, 0);

    while (waitpid(sdb->pid, &status, 0) > 0) {
        if (!WIFSTOPPED(status)) continue;

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

        for (int i = 0; i < BREAK_SIZE; i++) {
            bp_t *bp = &(sdb->breakpoints[i]);

            if (!bp->used) break;

            if (bp->address == regs.rip - 1) {
                ptrace(PTRACE_POKETEXT, sdb->pid, bp->address, bp->origin);
                regs.rip--; ptrace(PTRACE_SETREGS, sdb->pid, 0, &regs);

                cs_insn *insn; size_t count;
                unsigned long long assembly = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->address, 0);

                if ((count = cs_disasm(sdb->handle, (uint8_t*) &assembly, 8, bp->address, 0, &insn)) > 0) {
                    char byte[BYTE_SIZE], bytes[BYTE_SIZE]; 
                    memset(byte, 0, sizeof(byte)); memset(bytes, 0, sizeof(bytes));

                    for (size_t j = 0; j < insn[0].size; j++) {
                        snprintf(byte, BYTE_SIZE, "%02x ", insn[0].bytes[j]);
                        strncat(bytes, byte, strlen(byte));
                    }

                    fprintf(stdout, "** breakpoint @\t\t%lx: %-15s\t\t\t%s\t%s\n", 
                        insn[0].address, bytes, insn[0].mnemonic, insn[0].op_str
                    );

                    cs_free(insn, count); return;
                }
            }
       }
    }

    if (WIFEXITED(status)) {
        fprintf(stdout, "** child process %d terminated normally (code %d)\n", sdb->pid, status); 
    } else {
        fprintf(stdout, "** child process %d terminated with error (code %d)\n", sdb->pid, status);
    }

    sdb->pid = -1;  
}

void sdb_vmmap(sdb_t *sdb) {
    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    char pathname[PATH_MAX]; memset(pathname, 0, sizeof(pathname));
    snprintf(pathname, PATH_MAX, "/proc/%d/maps", sdb->pid);

    FILE *fp = fopen(pathname, "r");

    if (fp == NULL) {
        perror("fopen error"); exit(-1);
    }

    char *line = NULL; size_t len;

    char **tokens = (char**) malloc(TOKEN_SIZE * sizeof(char*));
    for (int i = 0; i < TOKEN_SIZE; i++) {
        tokens[i] = (char*) malloc(TOKEN_SIZE * sizeof(char));
    }

    while (getline(&line, &len, fp) != -1) {
        line[strlen(line) - 1] = 0;

        int count = 0; char *token = strtok(line, " ");

        while (token != NULL) {
            tokens[count++] = token; token = strtok(NULL, " ");
        }

        if (count == 6) {
            char *upper_address = strtok(tokens[0], "-"), *lower_address = strtok(NULL, "-");
            long int upper_num = strtol(upper_address, NULL, 16), lower_num = strtol(lower_address, NULL, 16);

            long int offset = strtol(tokens[2], NULL, 10); 
            char *perms = tokens[1], *pathname = tokens[5]; perms[strlen(perms) - 1] = 0;

            fprintf(stdout, "%016lx-%016lx %s %ld\t\t%s\n", upper_num, lower_num, perms, offset, pathname);
        }
    }
}

void sdb_set(sdb_t *sdb, char *register_name, unsigned long long value) {
    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

    if (!strcmp(register_name, "rax")) {
        regs.rax = value;
    } else if (!strcmp(register_name, "rbx")) {
        regs.rbx = value;
    } else if (!strcmp(register_name, "rcx")) {
        regs.rcx = value;
    } else if (!strcmp(register_name, "rdx")) {
        regs.rdx = value;
    } else if (!strcmp(register_name, "r8")) {
        regs.r8 = value;
    } else if (!strcmp(register_name, "r9")) {
        regs.r9 = value;
    } else if (!strcmp(register_name, "r10")) {
        regs.r10 = value;
    } else if (!strcmp(register_name, "r11")) {
        regs.r11 = value;
    } else if (!strcmp(register_name, "r12")) {
        regs.r12 = value;
    } else if (!strcmp(register_name, "r13")) {
        regs.r13 = value;
    } else if (!strcmp(register_name, "r14")) {
        regs.r14 = value;
    } else if (!strcmp(register_name, "r15")) {
        regs.r15 = value;
    } else if (!strcmp(register_name, "rdi")) {
        regs.rdi = value;
    } else if (!strcmp(register_name, "rsi")) {
        regs.rsi = value;
    } else if (!strcmp(register_name, "rbp")) {
        regs.rbp = value;
    } else if (!strcmp(register_name, "rsp")) {
        regs.rsp = value;
    } else if (!strcmp(register_name, "rip")) {
        regs.rip = value;
    } else if (!strcmp(register_name, "flags")) {
        regs.eflags = value;
    }

    ptrace(PTRACE_SETREGS, sdb->pid, 0, &regs);
}

void sdb_step(sdb_t *sdb) {
    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (!sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be RUNNING\n"); return;
    }

    if (ptrace(PTRACE_SINGLESTEP, sdb->pid, 0, 0) < 0) {
        perror("ptrace SINGLESTEP error"); exit(-1);
    }

    int status;

    if (waitpid(sdb->pid, &status, 0) < 0) {
        perror("waitpid error"); exit(-1);
    }
}

void sdb_start(sdb_t *sdb) {
    if (!sdb_load_status(sdb)) {
        fprintf(stdout, "** state must be LOADED\n"); return;
    }

    if (sdb_running_status(sdb)) {
        fprintf(stdout, "** state must be LOADED\n"); return;
    }

    int status;

    if ((sdb->pid = fork()) < 0) {
        perror("fork error"); exit(-1);
    } else if (sdb->pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            perror("ptrace TRACEME error"); exit(-1);
        }

        execlp(sdb->filename, sdb->filename, NULL);
    } else {
        if (waitpid(sdb->pid, &status, 0) < 0) {
            perror("waitpid error"); exit(-1);
        }

        ptrace(PTRACE_SETOPTIONS, sdb->pid, 0, PTRACE_O_EXITKILL);
        fprintf(stdout, "** pid %d\n", sdb->pid);
    }

    sdb_breakpoints(sdb);
}
