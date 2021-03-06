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

#define _POSIX_SOURCE
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <libelf.h>
#include <capstone/capstone.h>

#include "phook.h"

const char *phook_errstr(phook_error_t err) {
    switch (err) {
        case OK:
            return "Success";
        case NULL_POINTER:
            return "Pointer in function call was NULL";
        case INTERNAL_ERROR:
            return "An internal programming error occured";
        case COULDNT_OPEN_PROC:
            return "Could not open process' /proc/PID/exe file";
        case LIBELF_ERROR:
            return "An unexpected libelf error occured";
        case INVALID_ELF:
            return "Process' binary is not an ELF64";
        case MALLOC_FAILED:
            return "A malloc() call failed";
        case FORK_FAILED:
            return "A fork() call failed";
        case PTRACE_FAILED:
            return "A ptrace() call failed";
        case CAPSTONE_ERROR:
            return "An unexpected capstone error occured";
        case COULDNT_SPLIT:
            return "Could not split instructions for hook";
        case COULDNT_ASSEMBLE:
            return "Could not assemble a trampoline";
        default:
            return "An unknown error occured";
    }
}


// mmap(2) allocation shellcode template
// Runs mmap(0, size, PROT_EXEC|PROT_WRITE|PROT_READ,
//           MAP_PRIVATE|MAP_ANONYMOUS, 0, 0)
struct {
    uint8_t code_0[12];
    uint64_t size;
    uint8_t code_1[22];
    uint8_t trap[2];
} __attribute__((packed)) mmap_shellcode = {
    .code_0 = { 0x48, 0x31, 0xff,                         // xor rdi, rdi
                0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00, // mov rax, 9
                0x48, 0xbe                                // mov rsi, $address
    },
    .size = 0xdeadbeefcafebabe,
    .code_1 = { 0x48, 0xc7, 0xc2, 0x07, 0x00, 0x00, 0x00, // mov rdx, 7
                0x49, 0xc7, 0xc2, 0x22, 0x00, 0x00, 0x00, // mov r10, 0x22
                0x4d, 0x31, 0xc0,                         // xor r8, r8
                0x4d, 0x31, 0xc9,                         // xor r9, r9
                0x0f, 0x05                                // syscall
    },
    .trap = { 0xcd, 0x03 }                                // int 0x03
};

static phook_error_t
mmap_generate(uint8_t *out, uint32_t *size, uint64_t alloc_size)
{
    if (!size) {
        return NULL_POINTER;
    }

    if (!out) {
        *size = sizeof(mmap_shellcode);
        return OK;
    }

    memcpy(out, &mmap_shellcode, sizeof(mmap_shellcode));

    uint64_t offset = (void *)&mmap_shellcode.size - (void *)&mmap_shellcode;
    uint64_t *address = (uint64_t *)(out + offset);
    if (*address != 0xdeadbeefcafebabe) {
        return INTERNAL_ERROR;
    }
    *address = alloc_size;
    *size = sizeof(mmap_shellcode);
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
    if ((res = mmap_generate(NULL, &shellcode_size, size)) != OK) {
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

    if ((res = mmap_generate(shellcode, &written, size)) != OK) {
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

    uint64_t offset = (void*)&mmap_shellcode.trap - (void*)&mmap_shellcode;
    //TODO(q3k): Clean this up, set up some timeouts and whatnot
    while (1) {
        int status;
        waitpid(process, &status, 0);
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == 5) {
                if (ptrace(PTRACE_GETREGS, process, NULL, &run_regs) == -1) {
                    res = PTRACE_FAILED;
                    goto fail;
                }
                if (run_regs.rip == entry + offset + 2) {
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

phook_error_t
phook_find_instruction_boundary(pid_t process, uint64_t start_address,
        uint64_t min_bytes, uint64_t *boundary)
{
    uint64_t maximum_words = 10; // Sanity limit
    uint64_t i;
    uint8_t instructions[maximum_words*8];
    uint64_t *words = (uint64_t *)instructions;
    csh capstone;
    cs_insn *insn;

    if (boundary == NULL) {
        return NULL_POINTER;
    }

    if (min_bytes > maximum_words * 8) {
        return COULDNT_SPLIT;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone) != CS_ERR_OK) {
        return CAPSTONE_ERROR;
    }

    size_t count;
    phook_error_t res;
    for (i = 0; i < maximum_words; i++) {
        uint64_t bytes_present = i * 8;
        void *src = (uint8_t *)start_address + bytes_present;
        if (process == 0) {
            words[i] = *((uint64_t *)src);
        } else {
            if ((words[i] = ptrace(PTRACE_PEEKDATA, process, src, NULL)) == -1)
            {
                return PTRACE_FAILED;
            }
        }

        if (i * 8 < min_bytes) {
            continue;
        }

        count = cs_disasm(capstone, instructions, bytes_present,
                start_address, 0, &insn);
        if (count <= 0) {
            return CAPSTONE_ERROR;
        }

        for (uint64_t j = 0; j < count; j++) {
            // How many bytes do the disassembled instructions take up
            uint64_t used_bytes = insn[j].address - start_address;
            if (used_bytes >= min_bytes) {
                *boundary = used_bytes;
                res = OK;
                goto cleanup;
            }
        }

        cs_free(insn, count);
        count = 0;
    }

cleanup:
    if (count) {
        cs_free(insn, count);
    }
    cs_close(&capstone);
    return res;
}

struct {
    uint8_t code_0[7];
    uint64_t address;
} __attribute__((packed)) detour_shellcode = {
    .code_0 = {
        0xff, 0x35, 0x01, 0x00, 0x00, 0x00, // push [rip+1]
        0xc3                                // ret
    },
    .address = 0xdeadbeefcafebabe
};

phook_error_t
phook_assemble_detour(uint64_t source, uint64_t target, uint8_t *out, uint64_t *len)
{
    // Unused for now. Can be used to detect and generate E9-base relative jumps
    (void) source;

    if (len == NULL) {
        return NULL_POINTER;
    }

    *len = sizeof(detour_shellcode);
    if (out == NULL) {
        return OK;
    }

    memcpy(out, &detour_shellcode, sizeof(detour_shellcode));
    uint64_t offset = (void *)&detour_shellcode.address - (void *)&detour_shellcode;
    uint64_t *address = (uint64_t *)(out + offset);

    if (*address != 0xdeadbeefcafebabe) {
        return INTERNAL_ERROR;
    }
    *address = target;

    return OK;
}

phook_error_t
phook_local_hook(void *source, void *target, void **return_trampoline)
{
    uint64_t detour_length, prologue_length;
    phook_error_t err;

    // First, let's check what the detour size is for source->target jump
    if ((err = phook_assemble_detour((uint64_t)source, (uint64_t)target, NULL,
                &detour_length)) != OK) {
        return err;
    }

    // Second, let's find the prologue size that we can safely override
    if ((err = phook_find_instruction_boundary(0, (uint64_t)source,
                    detour_length, &prologue_length)) != OK) {
        return err;
    }

    // Third, let's allocate size for the return trampoline. The trampoline
    // will be made of:
    //  - the source function prologue, prologue_length bytes
    //  - the trampoline+prologue_length -> source+prologue_length jump,
    //    detour_length bytes (hopefully)
    *return_trampoline = mmap(0, prologue_length+detour_length,
            PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, 0, 0);
    if (*return_trampoline == MAP_FAILED)
        return MALLOC_FAILED;
    
    // Fourth, let's copy the first part of the trampoline (see above)
    memcpy(*return_trampoline, source, prologue_length);

    // Fifth, let's assemble the return jump (see above)
    if ((err = phook_assemble_detour(
                    ((uint64_t)*return_trampoline)+prologue_length,
                    ((uint64_t)source)+prologue_length,
                    *return_trampoline+prologue_length, &detour_length)) != OK) {
        return err;
    }

    // Finally, we can hook the source function.
    if ((err = phook_assemble_detour(
                    (uint64_t)source, (uint64_t)target,
                    source, &detour_length)) != OK) {
        return err;
    }

    return OK;
}
