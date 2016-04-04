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

// Forward declarations of public functions
phook_error_t phook_fork_exec_trace(const char *command, char *const argv[], pid_t *out);
phook_error_t phook_process_allocate(pid_t process, uint64_t size, uint64_t *out);
const char *phook_errstr(phook_error_t err);

#endif // __PHOOK_H__
