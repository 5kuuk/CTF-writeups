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

This map has a maximum capacity of `32` elements.
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
We choose an `atom` key, then all entries of `atoms` in the same bucket (i.e, whose key hashes to the same value) as it are copied into the `elems` list, which has only a capacity of 19 pairs !
We thus have an attack surface : if we get enough `atoms` keys to hash to the same value, then we can overflow `elems`, which is on the stack, and hijack control flow via ROP !
But hash collisions are notoriously hard to achieve on proper hash functions...
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
## The broken default hashing procedure of unordered map
You guessed it, and so did I during the ctf, **the unordered map's hashing has to be a terrible hashing function.**
A quick google search later, I stumbled onto an [article](https://codeforces.com/blog/entry/62393) on codeforces, which explains all that's needed to solve this challenge.
What I retained from it is the following :
- `hash(k) = f(k) mod p` where `f` is some hash function and `p` some prime
- by default, `f(k)=k`
