# Flag Roulette
- how I solved GCC CTF 2024's `Flag Roulette`
- From leakless arbitrary write in libc into ROP after exit
    - seccomp filter ? no problem
    - full relro libc ? no problem
        - ~~this chall had partial relro libc but whatever~~

## Overview
- can allocate a chunk up to size `0x21000` and write one byte out of bound
- can do it multiple times, but need to free then allocate a chunk again between each overwrite
- seccomp filter (not fun otherwise)

## Setup
- unstrip libc with [pwnlib.libcdb.unstrip_libc](https://docs.pwntools.com/en/stable/libcdb.html#pwnlib.libcdb.unstrip_libc)
    - debug symbols make your life easier
    - update pwntools to version 4.12.0 if you don't have this wonderful utility
- [patchelf](https://github.com/NixOS/patchelf) with provided linker and unstripped libc
- dump the seccomp-filter with [seccomp-tools](https://github.com/david942j/seccomp-tools)
```bash
$ seccomp-tools dump ./flag_roulette
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
 0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
 0007: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0012
 0008: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0012
 0009: 0x15 0x02 0x00 0x00000009  if (A == mmap) goto 0012
 0010: 0x15 0x01 0x00 0x0000000b  if (A == munmap) goto 0012
 0011: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```
- patch `call seccomp_load` by `NOP` instructions inside `setup()`
    - prevents enabling the seccomp filter
    - for easier debugging 
    - avoid `SIGSEGV` turning into `SIGSYS`

## Leakless overwrite
- With a large enough allocation size, a chunk will be mmaped above libc at constant offset, allowing us to target any location in libc, leaklessly

## Mmap chunk size dynamic thresholding bypass
- Let's look at [__libc_free](https://elixir.bootlin.com/glibc/glibc-2.37/source/malloc/malloc.c#L3353)
```C
    if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* See if the dynamic brk/mmap threshold needs adjusting.
	 Dumped fake mmapped chunks do not affect the threshold.  */
      if (!mp_.no_dyn_threshold
          && chunksize_nomask (p) > mp_.mmap_threshold
          && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
    }
```
- Dynamic thresholding (threshold doubling at each `munmap_chunk`)
    - very early, chunks will start being allocated from the heap since we're limited to `0x21000` bytes
    - prevents us from getting unlimited one-byte overwrites in libc
    - we can disable it by overwriting `mp_.no_dyn_threshold`
- Now we have arbitrary write in libc !

## Libc base leak via FSOP
- We corrupt the `FILE* stdout` structure to make it leak memory
    - [_IO_IS_APPENDING](https://elixir.bootlin.com/glibc/glibc-2.37/source/libio/libio.h#L73) in `stdout->_flags`
    - `stdout->_IO_write_base` < `stdout->_IO_write_ptr`

- In this specific case:
    - overwrite second `stdout->_flags` by `0x18`
    - overwrite second byte of `stdout->_IO_write_base`
        - originally equal to `x8` where `x` is dependent on ASLR
        - we attempt to set it to `x7`
        - bruting `x` results in a usable leak with probability `1/16`

- Lots of good resources online on file structures and FSOP
    - e.g. this [writeup](https://ret2school.github.io/post/catastrophe/) by team ret2school
    - you can also just look into glibc's source code

## Code execution after `exit`
- A well-known strategy is to target an `__exit_funcs` function entry to get code execution with `$rdi` control in [__run_exit_handlers](https://elixir.bootlin.com/glibc/glibc-2.37/source/stdlib/exit.c#L36)
- it requires bypassing pointer mangling
    - TLDR: 
        - rotate left target pointer
        - overwrite `[$fs_base:0x30]` by `0` (8 bytes)
```asm
    0x7ffff7dff89e <__run_exit_handlers+158>:	ror    rax,0x11
    0x7ffff7dff8a2 <__run_exit_handlers+162>:	xor    rax,QWORD PTR fs:0x30
    [...]
    0x7ffff7dff8b9 <__run_exit_handlers+185>:	call   rax
```
- seccomp filtering prevents us to go for the straightforward `system('/bin/sh')`
- however there is still something we can do...

## From `__exit_funcs` to ROP
Now we finally get into the juicy stuff
### Stack pivoting with `setcontext`
```asm
    0x00007ffff7e02375 <setcontext+53>:	mov    rsp,QWORD PTR [rdx+0xa0]  ; -> pivoting the stack
    0x00007ffff7e0237c <+60>:	mov    rbx,QWORD PTR [rdx+0x80]
    0x00007ffff7e02383 <+67>:	mov    rbp,QWORD PTR [rdx+0x78]
    0x00007ffff7e02387 <+71>:	mov    r12,QWORD PTR [rdx+0x48]
    0x00007ffff7e0238b <+75>:	mov    r13,QWORD PTR [rdx+0x50]
    0x00007ffff7e0238f <+79>:	mov    r14,QWORD PTR [rdx+0x58]
    0x00007ffff7e02393 <+83>:	mov    r15,QWORD PTR [rdx+0x60]
    0x00007ffff7e02397 <+87>:	mov    rcx,QWORD PTR [rdx+0xa8]          ; -> return address
    0x00007ffff7e0239e <+94>:	push   rcx                              
    0x00007ffff7e0239f <+95>:	mov    rsi,QWORD PTR [rdx+0x70]
    0x00007ffff7e023a3 <+99>:	mov    rdi,QWORD PTR [rdx+0x68]
    0x00007ffff7e023a7 <+103>:	mov    rcx,QWORD PTR [rdx+0x98]
    0x00007ffff7e023ae <+110>:	mov    r8,QWORD PTR [rdx+0x28]
    0x00007ffff7e023b2 <+114>:	mov    r9,QWORD PTR [rdx+0x30]
    0x00007ffff7e023b6 <+118>:	mov    rdx,QWORD PTR [rdx+0x88]
    0x00007ffff7e023bd <+125>:	xor    eax,eax
    0x00007ffff7e023bf <+127>:	ret
```
- can pivot the stack if we control `$rdx` !
- well-known trick

### Gadget (new?) for `$rdx` control
- I found this interesting gadget after a lot of effort
```asm
    0x00007ffff7e36b72 <puts+114>:	mov    rdx,rbx ;
    0x00007ffff7e36b75 <+117>:	mov    rsi,rbp
    0x00007ffff7e36b78 <+120>:	call   QWORD PTR [r14+0x38]
```
- Why is this useful ?
    - both `$rbx` and `$r14` point to writable memory regions inside libc !!!
```asm
    0x7ffff7dff804 <__run_exit_handlers+4>:	mov    r14,rsi                ; __exit_funcs -> WRITABLE
    [...]
    0x7ffff7dff820 <__run_exit_handlers+32>:	lea    rbx,[rip+0x196ac1] ; __exit_funcs_lock -> WRITABLE
    [...]
    0x7ffff7dff8b9 <__run_exit_handlers+185>:	call   rax
```
- From there it is straight forward to setup an open, read, write ropchain that will get executed after `exit()`
    - leverage `__exit_funcs` to call `puts+114`
    - then `setcontext+53` to pivot to ropchain
    
### Notes
- [ropper](https://pypi.org/project/ropper/#description) will only give you `puts+121` 
    - aka `call qword ptr [rsi+0x38]`
    - always check vicinities of ropper gadgets when ~~stuck~~ bored
        - WITH duplicates : `--all`
- the technique demonstrated here should also work in some other libcs
    - I checked the gadgets existence in libc-2.35, with minimal offset adjustments


## FLAG
`GCC{Th0s3_p0in7S_R_w3lL_deS3rvEd_Gig4ch4d}`

