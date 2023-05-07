# **Heap-Hop**


## **TL;DR**
- Heap menu, you can create,display and create tracks but you cannot delete them
- I leveraged a heap buffer overflow into a free chunk for tcache poisoning to then overwrite a GOT entry


## **Checksec**
```
[*] '/home/skuuk/pwnme23/heap-hop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
- Partial Relro clearly hints at GOT overwrite
- No PIE so there's no need  to leak the address of the executable

## **What the bin doing ?**
```
[+] Welcome to hip-hop, you can create and listen to heap-hop music
Make your choice :
	- 1. Create a track.
	- 2. Read a track.
	- 3. Edit a track.
> 
```
### **What objects are created ?**
```C
struct track = {
    char[32] name,
    unsigned long size,
    char* content
}
```
### **Create**
I did not find any vulnerability here.
- We get to choose the size of the content which is stored in the `size` field and has to be smaller than `0x480` bytes.
- We get to choose the name of the track
- we get to choose the track content 
- at most `size` bytes are `read` from `stdin` into track->content`

### **Read**
We get to print `track->size` bytes from `track->content`

### **Edit**
We provide a new content and its size.
The track is updated accordingly...
*or is it ?*

Keeping only the interesting part from the decompilation :
```C
    printf("Enter the new tracklist content length\n> ");
    __isoc99_scanf(&DAT_00402086,&local_28);
    if (0x480 < local_28) {
                    /* WARNING: Subroutine does not return */
      _exit(1);
    }
    lVar1 = *(long *)(tracks + (ulong)local_2c * 8);
    pvVar2 = realloc(*(void **)(*(long *)(tracks + (ulong)local_2c * 8) + 0x28),local_28);
    *(void **)(lVar1 + 0x28) = pvVar2;
    printf("Enter the new tracklist content\n> ");
    read(0,*(void **)(*(long *)(tracks + (ulong)local_2c * 8) + 0x28),
         *(size_t *)(*(long *)(tracks + (ulong)local_2c * 8) + 0x20));
    puts("[+] track content edited.");
```
- The `track->content` is reallocated to the size that we provide
- The `track->size` field is not updated
- We copy `track->size` bytes into the content

Because, `track->size` is not updated, we can leak some of the heap contents using the read option, and we can write out of bounds too.

## **The exploit**

### **Goal**
```C
// turn
realloc(<ptr to 'cat flag'>);
// into
system(<ptr to 'cat flag'>);
```

### **Obstacles**
- Because of the realloc checks when calling edit, we cannot simply overwrite a content pointer with the address of the GOT entry of `realloc`
- We're dealing with GLIBC 2.35, which implies safe linking in singly linked free lists (tcache & fast bins)

### **Attack Plan**
- To leak the base of libc :
    - make a track `A` whose (content) `size` covers a track `B` 

        *(I'll refer to 2 tracks in this arragement  in this way)*
    - write OOB in `A`'s content to replace `B->content` with the address of a GOT entry
    - read `B`'s content to leak libc

- GOT overwrite ?
    - Because we cannot rely on `edit`, we will need to trick malloc into returning an arbitrary pointer
    - This can be achieved via tcache poisoning, where we overwrite a forward pointer from a tcache bin (freed chunks list)
    - Because of safe linking, forward pointers are obfuscated

- Bypassing safe linking
    - google was a valuable friend here and I learnt that pointers are obfuscated as follows :

        `fp = (actual fp) xor (heap base >> 12)`
    - with a heap leak, it is trivial to bypass such mitigation
    - just as for the libc leak, we can here read out of bound to leak the `content` pointer of `B` by reading `A` OOB

-  GOT overwrite !
    - Have a the content of a track `C` , its size covering that of a track `D`
    - Get  `D`'s `content` to be freed (make sure it cannot be coalesced, by allocating another track for example, and edit it a bigger size)
    - now a forward pointer from a tcache bin is present under `C`
    - overwrite this pointer with a 16 bytes aligned got entry (chunk must be 16 bytes aligned otherwise it will be skipped)
    so that `realloc` is present in the next 32 bytes
    - make tracks until the next suitable choice for a track is our fake chunk
    - make a new track, its username will overlap with the got. Craft the track name accordingly, so that the `realloc` got entry of malloc now points to `system`
    - edit a track whose content starts with `'cat flag.txt'`
    - enjoy your flag

That's the main idea, but the bulk of the exploit is setting up the heap layout properly by allocating and reallocating chunks so that the layout is as desired. 

Notably at some point I filled the tcache bin for a given size, chosen big enough (avoid fastbins) so that after subsequent allocations and reallocation, leftover content chunks on smaller reallocations would end up in unsorted bin, and be utilized (and split !) even if they don't exactly fit the allocation request. I am unsure if it was strictly necessary, but that's the only way I managed to have them utilized in subsequent allocations.

It's not super interesting so I won't discuss the details here, my heap management is most definitely suboptimal, but anyone interested can have a look at my exploit.

## **FLAG**
```
PWNME{d1d_y0u_kn0w_r341l0c_c4n_b3h4v3_l1k3_th4t_cd}
```
:P
