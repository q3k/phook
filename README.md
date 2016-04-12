phook [fʊk]
===========

Definition
----------

_verb_: 1. To subvert and extend a closed-source Linux binary using the `ptrace(2)` sycall.

_noun_: 1. A library and toolchain used to phook.

Status
------

Work in progress, businness as usual. Present functions are working, others are being worked on by the author(s).

Simple usecases
===============

Detailed function signatures are in `phook.h`. Real documentation is coming once phook reaches alpha state. In the meantime, here's some things the author(s) have been using the library for:

Allocate an RWX buffer in a running process
-------------------------------------------

    uint64_t target_buffer;
    phook_process_allocate(pid, 0x1000, &target_buffer);

Load .so into dynamic running process
-------------------------------------

_In progres..._

Load .so into static running process
------------------------------------

_In progress..._


Hook local process function
---------------------------

Hook a function from a `LD_PRELOAD`ed library:


    // remap text section
    mprotect((void *)0x406000, 0xDBB000-0x406000, PROT_READ|PROT_WRITE|PROT_EXEC)
    
    typedef void (*hookedFunction_t)(uint64_t foo, uint64_t bar);
    hookedFunction_t binary_hookedFunction = (hookedFunction_t)0x99BCE0;
    hookedFunction_t original_hookedFunction;
    void our_hookedFunction(uint64_t foo, uint64_t bar) {
        // ...
        return (*original_hookedFunction)(action, player, bar);
    }
    
    // redirect binary_hookedFunction to our_hookedFunction
    hook_local_hook((void *)binary_hookedFunction, (void *)our_hookedFunction, (void **)&original_hookedFunction);
