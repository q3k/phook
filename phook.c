// Copyright (c) 2016, Sergiusz Bazanski <sergiusz@bazanski.pl>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
// IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#include "phook.h"

// Allocation shellcode template
static const char *shellcode_template =
// xor rdi, rdi               - don't care about mmap base
    "\x48\x31\xff"
// mov rax, 9
    "\x48\xc7\xc0\x09\x00\x00\x00"
// mov rsi, 0xdeadbeefcafebabe - template for allocation size
    "\x48\xbe\xbe\xba\xfe\xca\xef\xbe\xad\xde"
// mov rdx, 7                 - PROT_EXEC | PROT_WRITE | PROT_EAD
    "\x48\xc7\xc2\x07\x00\x00\x00"
// mov r10, 0x22              - MAP_PRIVATE | MAP_ANONYMOUS
    "\x49\xc7\xc2\x22\x00\x00\x00"
// xor r8, r8                 - zero fd
    "\x4d\x31\xc0"
// xor r9, r9                 - zero fd offset
    "\x4d\x31\xc9"
// syscall
    "\x0f\x05"
// int 0x03
    "\xcd\x03"
;
static const uint32_t shellcode_address_offset = 12;
static const uint32_t shellcode_int_offset = 42;
static const uint32_t shellcode_size = 44;

static phook_error_t
shellcode_generate(uint8_t *out, uint32_t *size, uint64_t alloc_size)
{
    if (!size) {
        return NULL_POINTER;
    }

    if (!out) {
        *size = shellcode_size;
        return OK;
    }

    memcpy(out, shellcode_template, shellcode_size);
    uint64_t *address = (uint64_t *)(out + shellcode_address_offset);
    if (*address != 0xdeadbeefcafebabe) {
        return INTERNAL_ERROR;
    }
    *address = alloc_size;
    *size = shellcode_size;
    return OK;
}

static const char *process_proc = "/proc/";
static const char *process_exe = "/exe";

static phook_error_t
process_get_entrypoint(pid_t process, uint64_t *entrypoint)
{
    uint32_t malloc_size = strlen(process_proc) + strlen(process_exe) + 30;
    char *name = (char *)malloc(malloc_size);
    if (name == NULL) {
        return MALLOC_FAILED;
    }
    snprintf(name, malloc_size, "%s%d%s", process_proc, process, process_exe);

    int exe = open(name, O_RDONLY, 0);
    if (exe < 0) {
        free(name);
        return COULDNT_OPEN_PROC;
    }

    if (elf_version (EV_CURRENT) == EV_NONE) {
        free(name);
        close(exe);
        return LIBELF_ERROR;
    }
    Elf *e = elf_begin(exe, ELF_C_READ, NULL);
    Elf64_Ehdr *ehdr;
    if (e == NULL) {
        free(name);
        close(exe);
        return LIBELF_ERROR;
    }

    phook_error_t res = INTERNAL_ERROR;
    if (elf_kind(e) != ELF_K_ELF) {
        res = INVALID_ELF;
        goto fail;
    }
    if ((ehdr = elf64_getehdr(e)) == NULL) {
        res = INVALID_ELF;
        goto fail;
    }
    *entrypoint = ehdr->e_entry;

    return OK;

fail:
    elf_end(e);
    close(exe);
    free(name);
    return res;
}

phook_error_t
phook_fork_exec_trace(const char *command, char *const argv[], pid_t *out)
{
    if (!out) {
        return NULL_POINTER;
    }
    pid_t new = fork();
    if (new == -1) {
        return FORK_FAILED;
    }
    if (new == 0) {
        // Child
        execv(command, argv);
    } else {
        // Parent
        // Hack: sleep a second to make sure child has started executing
        sleep(1);
        if (ptrace(PTRACE_ATTACH, new, NULL, NULL) == -1) {
            kill(new, -15);
            return PTRACE_FAILED;
        }
        *out = new;
        return OK;
    }

    // We should never reach this
    return INTERNAL_ERROR;
}

phook_error_t
phook_process_allocate(pid_t process, uint64_t size, uint64_t *out)
{
    uint64_t entry;
    phook_error_t res = INTERNAL_ERROR;
    struct user_regs_struct regs, changed_regs, run_regs;
    uint32_t written, i;
    uint8_t *shellcode, *original;

    if (!out) {
        return NULL_POINTER;
    }
    if ((res = process_get_entrypoint(process, &entry)) != OK) {
        return res;
    }
    printf("process_allocate(): entrypoint is 0x%016lx\n", entry);

    if (ptrace(PTRACE_GETREGS, process, NULL, &regs) == -1) {
        return PTRACE_FAILED;
    }
    printf("process_allocate(): rip: 0x%016llx\n", regs.rip);

    uint32_t shellcode_size;
    if ((res = shellcode_generate(NULL, &shellcode_size, size)) != OK) {
        return res;
    }
    // Align to 8 bytes (word)
    if ((shellcode_size % 8) != 0)
        shellcode_size += 8 - (shellcode_size % 8);

    shellcode = (uint8_t *)malloc(shellcode_size);
    original = (uint8_t *)malloc(shellcode_size);
    if (shellcode == NULL || original == NULL) {
        return MALLOC_FAILED;
    }

    if ((res = shellcode_generate(shellcode, &written, size)) != OK) {
        goto fail;
    }

    // Copy original code
    for (i = 0; i < (shellcode_size/8); i++) {
        uint64_t *dest = (uint64_t *)(original + i * 8);
        void *src = (uint8_t *)entry + i * 8;
        if ((*dest = ptrace(PTRACE_PEEKDATA, process, src, NULL)) == -1) {
            res = PTRACE_FAILED;
            goto fail;
        }
    }

    // Write shellcode
    for (i = 0; i < (shellcode_size/8); i++) {
        uint64_t *src = (uint64_t *)(shellcode + i * 8);
        void *dest = (uint8_t *)entry + i * 8;
        if (ptrace(PTRACE_POKEDATA, process, dest, *src) == -1) {
            goto fail;
        }
    }

    memcpy(&changed_regs, &regs, sizeof(regs));
    changed_regs.rip = entry + 2;

    if (ptrace(PTRACE_SETREGS, process, NULL, &changed_regs) == -1) {
        res = PTRACE_FAILED;
        goto fail;
    }
    if (ptrace(PTRACE_CONT, process, NULL, NULL) == -1) {
        res = PTRACE_FAILED;
        goto fail;
    }

    while (1) {
        int status;
        waitpid(process, &status, 0);
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == 5) {
                if (ptrace(PTRACE_GETREGS, process, NULL, &run_regs) == -1) {
                    res = PTRACE_FAILED;
                    goto fail;
                }
                if (run_regs.rip == entry + shellcode_int_offset + 2) {
                    printf("process_allocate(): hit interrupt in target\n");
                    break;
                }
            } else {
                if (ptrace(PTRACE_CONT, process, NULL, WSTOPSIG(status)) == -1) {
                    res = PTRACE_FAILED;
                    goto fail;
                }
            }
        } else {
            if (ptrace(PTRACE_CONT, process, NULL, NULL) == -1) {
                res = PTRACE_FAILED;
                goto fail;
            }
        }
    }

    *out = run_regs.rax;

    // Write original
    for (i = 0; i < (shellcode_size/8); i++) {
        uint64_t *src = (uint64_t *)(original + i * 8);
        void *dest = (uint8_t *)entry + i * 8;
        if (ptrace(PTRACE_POKEDATA, process, dest, *src) == -1) {
            res = PTRACE_FAILED;
            goto fail;
        }
    }
    // Resume original
    if (ptrace(PTRACE_SETREGS, process, NULL, &regs) == -1) {
        res = PTRACE_FAILED;
        goto fail;
    }

    return OK;

fail:
    free(shellcode);
    free(original);
    return res;
}



// Temporary test stuff
#include <stdio.h>
#include <sys/mman.h>

char *const cargv[] = {
    "./victim",
    NULL
};
int main(int argc, char **argv)
{
    pid_t child;
    uint64_t buffer;
    printf("fork_exec_trace(): %s\n",
            phook_errstr(phook_fork_exec_trace(cargv[0], cargv, &child)));
    printf("process_allocate(): %s\n",
            phook_errstr(phook_process_allocate(child, 0x1000, &buffer)));
    printf("rwx buffer is 0x%016lx\n", buffer);

    ptrace(PTRACE_DETACH, child, NULL, NULL);
    int options;
    waitpid(child, &options, 0);

    return 0;
}
