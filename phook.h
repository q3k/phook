#ifndef __PHOOK_H__
#define __PHOOK_H__

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

#ifndef __x86_64__
#error "ptracehook only support 64-bit Intel code!"
#endif // def __x86_64__

#include <sys/types.h>
#include <stdint.h>

// Error handling definitions
typedef enum {
    OK = 0,

    NULL_POINTER = -1,
    INTERNAL_ERROR = -2,
    COULDNT_OPEN_PROC = -3,
    LIBELF_ERROR = -4,
    INVALID_ELF = -5,
    MALLOC_FAILED = -6,
    FORK_FAILED = -7,
    PTRACE_FAILED = -8,
    CAPSTONE_ERROR = -9,
    COULDNT_SPLIT = -10,
    COULDNT_ASSEMBLE = -11
} phook_error_t;

/// Forward declarations of public functions

// Get error string for a phook error
// err: phook error
// return: consr char * to error string
const char *phook_errstr(phook_error_t err);

// Spawn a new process and ptrace it. This doesn't clean up or wait for the 
// process.
// command: process to start, like in execv(3)
// argv: argv for new process, like in execv(3)
// out: pointer to resulting pid_t
// return: error or OK
phook_error_t phook_fork_exec_trace(const char *command, char *const argv[],
        pid_t *out);

// Allocate some RWX memory in a currently ptraced process
// process: pid_t of process
// size: size of buffer to allocate
// out: pointer to address of resulting buffer in process' VMA
// return: error or OK
phook_error_t phook_process_allocate(pid_t process, uint64_t size,
        uint64_t *out);

// Find a instruction boundary after a certain treshold (useful for finding
// trampoline sites so that no instructions are split)
// process: pid_t of process or 0 for local
// start_address: start of disassembly
// min_bytes: how many bytes at minimum do we want the instructions to occupy
// boundary: pointer to the address of resulting instruction boundary
phook_error_t phook_find_instruction_boundary(pid_t process,
        uint64_t start_address, uint64_t min_bytes, uint64_t *boundary);

// Assemble a jump/detour
// source: where the jump will be from
// target: where the jump should redirect
// out: where to write the detour, or NULL to just get len
// len: pointer to output the resulting size of detour
phook_error_t phook_assemble_detour(uint64_t source, uint64_t target,
        uint8_t *out, uint64_t *len);

phook_error_t
phook_local_hook(void *source, void *target, void **return_trampoline);

#endif // __PHOOK_H__
