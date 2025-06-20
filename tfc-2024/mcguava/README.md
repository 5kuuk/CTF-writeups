# MCGUAVA

**TL;DR**: 
- Leakless double free exploitation on libc 2.39
- Presenting a novel alternative to House of Water:
    - large bin attack on `mp_.tcache_bins` (4 bits bruteforce) so that fake tcache entries for sizes greater than `0x410` are overlapped with a controlled heap chunk
    - leading to arbitrary allocations via partial overwrite

**20.06.2025 IMPORTANT NOTE**
- The technique I present here is extremely similar to the intended of the following challenge https://github.com/tj-oconnor/cyber-open-2022/blob/main/pwn/house/Solution.pdf, which is much older.
- The main difference is that the technique I present achieves the large bin attack targetting `mp_.tcache_bins` without a libc leak, whereas the above needs one


## Protections
We are provided with the executable and the Dockerfile on which it runs on remote
- the executable has all protections enabled, notably PIE and full RELRO
```
[*] '/home/skuuk/tfc/mcguava/guava'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
- the libc version inside the docker container is 2.39, which also has all protections enabled, notably full RELRO
```
[*] '/home/skuuk/tfc/mcguava/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Analysis
The executable presents us with an obscure menu:
```
...# ./guava
guava gius is not something you can just indulge in
guava gius guavocado is a lifestyle
guava is the single most important piece of guavocado
that you are supposed to buava and muava guava
muava mus or muava guava? simi gus

1. guava
2. gius
3. guavocado
*> 
```
Let's decompile the executable in binary ninja to get a better sense of what's going on

https://discord.com/channels/1376906927195422741/1376938565816291508
Firstly, the main function
```c
0000153b  int32_t main(int32_t argc, char** argv, char** envp)

00001550      void* fsbase
00001550      int64_t var_10 = *(fsbase + 0x28)
0000156f      setvbuf(fp: stdin, buf: nullptr, mode: 2, size: 0)
0000158d      setvbuf(fp: __bss_start, buf: nullptr, mode: 2, size: 0)
000015ab      setvbuf(fp: stderr, buf: nullptr, mode: 2, size: 0)
000015ab      
000015e0      for (int32_t i = 0; i s<= 0xff; i += 1)
000015cd          *((sx.q(i) << 3) + &guava_gius) = 0
000015cd      
000015e7      banner()
000015e7      
000015f1      while (true)
000015f1          menu()
0000160c          int32_t var_18
0000160c          __isoc99_scanf(format: &data_2136, &var_18)
00001611          int32_t rax_6 = var_18
00001611          
00001617          if (rax_6 == 3)
00001617              break
00001617          
00001621          if (rax_6 == 1)
0000162f              guava()
00001634              continue
00001621          else if (rax_6 == 2)
0000163b              gius()
00001640              continue
00001640          
00001656          puts(str: "invalid choice")
00001656      
00001647      exit(status: 0)
00001647      noreturn
```
Looking at `guava()` and `gius()`, we finally get a sense of what's going on:
```c
00001315  int64_t guava()

00001321      void* fsbase
00001321      int64_t rax = *(fsbase + 0x28)
00001321      
0000133b      if (cnt_guavas s> 0xff)
00001347          puts(str: "guava overload")
00001351          exit(status: 0)
00001351          noreturn
00001351      
00001365      printf(format: "how many guavas: ")
00001380      int32_t var_20
00001380      __isoc99_scanf(format: &data_2136, &var_20)
00001380      
0000138d      if (var_20 s> 0x6ff)
00001399          puts(str: "guava overload")
000013a3          exit(status: 0)
000013a3          noreturn
000013a3      
000013b0      int64_t rax_7 = malloc(bytes: sx.q(var_20))
000013c8      printf(format: "guavset: ")
000013e3      int32_t var_1c
000013e3      __isoc99_scanf(format: &data_2136, &var_1c)
000013e3      
000013fa      if (var_1c s< 0 || var_20 - 2 s<= var_1c)
00001406          puts(str: "guava overload")
00001410          exit(status: 0)
00001410          noreturn
00001410      
00001424      printf(format: "guavas: ")
0000144c      read(fd: 0, buf: sx.q(var_1c) + rax_7, nbytes: sx.q(var_20 - var_1c))
00001451      uint32_t cnt_guavas_1 = cnt_guavas
0000145a      cnt_guavas = cnt_guavas_1 + 1
00001475      *((sx.q(cnt_guavas_1) << 3) + &guava_gius) = rax_7
00001475      
00001487      if (rax == *(fsbase + 0x28))
0000148f          return rax - *(fsbase + 0x28)
0000148f      
00001489      __stack_chk_fail()
00001489      noreturn


00001490  int64_t gius()

0000149c      void* fsbase
0000149c      int64_t rax = *(fsbase + 0x28)
000014ba      printf(format: "guava no: ")
000014d5      int32_t vara_14
000014d5      __isoc99_scanf(format: &data_2136, &var_14)
000014d5      
000014e9      if (var_14 s< 0 || var_14 s> 0xff)
000014f5          puts(str: "guava overload")
000014ff          exit(status: 0)
000014ff          noreturn
000014ff      
0000151f      free(mem: *((sx.q(var_14) << 3) + &guava_gius))
0000151f      
00001532      if (rax == *(fsbase + 0x28))
0000153a          return rax - *(fsbase + 0x28)
0000153a      
00001534      __stack_chk_fail()
00001534      noreturn
```
- `guava()` allows us to `malloc()` an entry in the global struct `guava_guis` with a chosen size of at most `0x6ff`, then fill its content, starting at a chosen offset
- `guis()` allows us to call `free()` on `guava_guis` entries
    - these are not set to `NULL`, leading to a double free vulnerability

This chal is thus a leakless heap menu, with a double free vulnerability on libc 2.39 `:0`, in a similar fashion to `tamagoyaki` from potluck CTF, except we have to RCE this time, not just allocate an arbitrary chunk on the heap, and the executable uses `scanf` and `puts` (which adds possibilities for FSOP-based attacks)
- The similarity to `tamagoyaki` would hint at a [House of Water exploit](), however I had recently came up with of a novel leakless heap exploitation, and it was the perfect occasion to try it :D



## Exploit

### The technique
The first thing to understand is how `malloc()` [allocates from the tcache](https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L3316):
```c
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/// ...
static __always_inline void *
tcache_get_n (size_t tc_idx, tcache_entry **ep)
{
  tcache_entry *e;
  if (ep == &(tcache->entries[tc_idx]))
    e = *ep;
  else
    e = REVEAL_PTR (*ep);

  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");

  if (ep == &(tcache->entries[tc_idx]))
      *ep = REVEAL_PTR (e->next);
  else
    *ep = PROTECT_PTR (ep, REVEAL_PTR (e->next));

  --(tcache->counts[tc_idx]);
  e->key = 0;
  return (void *) e;
}

static __always_inline void *
tcache_get (size_t tc_idx)
{
  return tcache_get_n (tc_idx, & tcache->entries[tc_idx]);
}
// ...
void *
__libc_malloc (size_t bytes)
{
  // ...
  size_t tc_idx = csize2tidx (tbytes);
  // ...
  if (tc_idx < mp_.tcache_bins
      && tcache != NULL
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
  // ...
}

// ...
# define TCACHE_MAX_BINS		64
// ...
static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
#if USE_TCACHE
  ,
  .tcache_count = TCACHE_FILL_COUNT,
  .tcache_bins = TCACHE_MAX_BINS,
  .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
  .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};
```
- `mp_.tcache_bins`, which is set to `64` when `mp_` is initialized, but it is writable, can be set to a heap pointer (which will be bigger than `64`) via a [large bin attack](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/large_bin_attack.c)
- Note that if `mp_.tcache_bins` is corrupted this way, `malloc()` can access `tcache->counts` and `tcache->entries` out of bounds !
- This can be leveraged to return a fake tcache entry setup on a chunk that's below the `tcache_perthread_struct`, provided we can call `malloc()` with a large enough size, and that the corresponding count is non-zero. The count can be set by freeing a chunk that will set a legitimate entry, overlapping with the out of bound counts entry.

## Arbitrary chunk allocation (preparation)
- One can allocate a chunk, free it to unsorted bin, then allocate it again and use a partial overwrite to get a libc pointer to a desired location. For example, one can set a pointer to point above `_IO_2_1_stdout_`, with 4 bits bruteforce
    - Note that it is important for this brute to be consistent with the later 4 bits brute to `mp_`
- This can be done multiple times by splitting the unsorted bin chunk.
- In this case I did it twice so as to leak libc via `stdout` overwrite.

## Large bin attack
- Using the double free vulnerability and careful feng shui, one can overlap a large bin entry with an unsorted bin entry
- Then, set its `bk_nextsize` to an `main_arena` pointer (`bk` pointer of an unsorted bin entry), then leverage a partial `2` bytes overwrite (4bits bruteforce) to make it point to `&(mp_.tcache_bins)-0x20`
- Putting a smaller chunk that targets the same large bin as our previous large bin chunk will trigger the attack and set `mp_.tcache_bins`

## Arbitrary allocation
- Freeing chunks of the proper size (e.g `0x20` or `0x30`) to set the `tcache->counts` to be non-zero
- Allocate a chunk of proper size to (bigger than `0x410`), will return our pointer above `_IO_2_1_stdout_`

## Libc leak
- Use the first allocation to set the flags of `stdout` to `0xfbad1800`
- Use the second allocation to set the LSB of `stdout->_IO_write_base` to `0`, by leveraging the write at offset to leave above fields untouched
    - **This is the first and only time that "write at non-zero offset" is used, unlike House of Water, my technique does not rely on this to get an arbitrary allocation**
    - One can probably come up with other strategies after arbitrary allocation is possible
        - if the libc was not full relro, overwriting a got entry with a one gadget using a partial overwrite (probably a 12 bits brute) for example would make the exploit not rely on the "write at non-zero offset" at all

## Shell
- We can allocate `_IO_2_1_stdout_` again and use a FSOP technique to pop a shell
    - I used the chain introduced by kylebot in [angry-FSROP](https://github.com/Kyle-Kyle/angry-FSROP) to call `system("/bin/sh")`

## FLAG
```
root@skuuk-laptop:/home/skuuk/tfc/mcguava# python3 exploit.py HOST=challs.tfcctf.com PORT=30821
...
[+] Opening connection to challs.tfcctf.com on port 30821: Done
[CRITICAL] libc: 0x7f8a177c9000
/home/skuuk/tfc/mcguava/exploit.py:66: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendline(m,**kwargs)
[*] Switching to interactive mode
TFCCTF{gu4v4_ju1c3__1s_th3_4ll__m1ghty_b3v3rage!}
```

Thanks Mcsky23 for this cool challenge, allowing me to demonstrate this technique :D


