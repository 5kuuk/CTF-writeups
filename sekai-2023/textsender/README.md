# Textsender
![img](https://github.com/5kuuk/CTF-writeups/blob/main/sekai-2023/textsender/images/double_free_meme.jpg)
*Many thanks the whole SekaiCTF organizing team and especially Jonathan for designing this really cool challenge*

## tl;dr
I flagged this challenge with what I would describe as a [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.32/house_of_botcake.c) variant leveraging `realloc` in `getline` and an unintended double free,
instead of relying on the intended vulnerabilities to pull off a [House of Einherjar](https://github.com/shellphish/how2heap/blob/master/glibc_2.32/house_of_einherjar.c) :P

## Overview
### checksec
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
```
No PIE and only Partial RELRO. Thus, the way I intended to and then solved this challenge with is by overwriting
the got entry of free with the address of system and then calling free on a heap pointer to `"/bin/sh"`
to spawn a shell !

*But how did I get there ?*

### The heap menu
- options :
```
------- MENU -------
| 1. Set sender    |
| 2. Add message   |
| 3. Edit message  |
| 4. Print all     |
| 5. Send all      |
| 6. Exit          |
--------------------
> 
```
- message structure :
```C
typedef struct message {
  char* receiver;
  char* content;
} message;
```
- `sender`,`receiver` and `content` are provided through the `input` function which uses `scanf(%<x>s%*c,ptr)` calls, where `<x>` is the predetermined length of the input.
  As such, length cannot be controlled, and all whitespaces as well as terminating newlines are dropped. A null byte is also concatenated :
```c
void input(char *buffer,char *prompt,uint size)

{
  size_t tmp;
  char format [9];
  ushort prefix_length;
  
  format[0] = '%';
  sprintf(format + 1,"%d",(ulong)size);
  tmp = strlen(format);
  prefix_length = (ushort)tmp;
  format[(int)(uint)prefix_length] = 's';
  format[(int)(prefix_length + 1)] = '%';
  format[(int)(prefix_length + 2)] = '*';
  format[(int)(prefix_length + 3)] = 'c';
  format[(int)(prefix_length + 4)] = '\0';
  printf("%s",prompt);
  __isoc99_scanf(format,buffer);
  return;
}
```
- `sender` is filled with `"Sender: "` followed by user input
```c
void set_sender(void)

{
  sender = (undefined8 *)malloc(120);
  *sender = 0x203a7265646e6553; //"Sender: "
  input((char *)(sender + 1),"Sender\'s name: ",111);
  puts("[*] Added!");
  return;
}
```
- You have no control over allocation sizes for messages :
  + a `message` is `16` bytes
  + the `sender` and a message's `receiver` are `120` bytes each
  + a message's `content` is `504` bytes
```C
int add_message(message **messages,byte *nb_messages)

{
  int return_code;
  message *new_message;
  char *tmp;
  byte n;
  
  if (*nb_messages < 10) {
    new_message = (message *)malloc(0x10);
    tmp = (char *)malloc(120);
    new_message->receiver = tmp;
    tmp = (char *)malloc(504);
    new_message->content = tmp;
    input(new_message->receiver,"Receiver: ",120);
    input(new_message->content,"Message: ",504);
    n = *nb_messages;
    *nb_messages = n + 1;
    messages[n] = new_message;
    return_code = puts("[*] Added!");
  }
  else {
    puts("You reached maximum of message!");
    return_code = 0;
  }
  return return_code;
}
```
- When you want to edit a message, you have to provide again the receiver through a `getline` call,
   it is then compared to the receiver of each allocated `message` until the first corresponding one is found, and its `content` is edited with `input` again :
```C
void edit_message(message **messages,byte nb_messages)

{
  size_t buff_size;
  char *buff;
  __ssize_t receiver;
  long j;
  int i;
  char is_message_found;
  message *m;
  
  is_message_found = '\0';
  buff_size = 0;
  buff = (char *)0x0;
  printf("Name: ");
  receiver = getline(&buff,&buff_size,stdin);
  i = 0;
  while ((i < (int)(uint)nb_messages && (is_message_found == '\0'))) {
    m = messages[i];
    is_message_found = '\x01';
    j = 0;
    while ((j < receiver + -1 && (is_message_found != '\0'))) {
      if (buff[j] != m->receiver[j]) {
        is_message_found = '\0';
      }
      j = j + 1;
    }
    i = i + 1;
  }
  if (is_message_found == '\0') {
    puts("[-] Cannot find name!");
  }
  else {
    printf("Old message: %s\n",m->content);
    input(m->content,"New message: ",0x1f8);
    puts("[*] Changed!");
  }
  free(buff);
  return;
}
```
- you can print all receivers and contents of currently allocated messages :
```C
void print_message(message **messages,byte nb_messages)

{
  uint i;
  
  printf("Total: %hu draft.\n",(ulong)nb_messages);
  for (i = 0; (int)i < (int)(uint)nb_messages; i = i + 1) {
    printf("(Draft %d) %s: %s\n",(ulong)i,messages[(int)i]->receiver,messages[(int)i]->content);
  }
  return;
}
```
- If you want to free the `sender`, or a `message` you must free them all :
```c
void send_message(message *messages,byte *nb_messages)

{
  int is_free;
  uint i;
  message *m;
  
  printf("Total: %hu draft.\n",(ulong)*nb_messages);
  if (sender != (char *)0x0) {
    is_free = strncmp(sender,"Sender: ",8);
    if (is_free == 0) {
      free(sender);
      printf("[*] Sent sender\'s name!");
    }
  }
  for (i = 0; (int)i < (int)(uint)*nb_messages; i = i + 1) {
    m = (message *)(&messages->receiver)[(int)i];
    free(m->content);
    free(m->receiver);
    free(m);
    printf("[*] Sent draft %d!\n",(ulong)i);
  }
  *nb_messages = 0;
  return;
}
```

## Intended vulnerabilities
1) For `receiver` and `content`, the null byte is not accomodated for, leading to null byte overflow
2) You can use this receiver name comparison to probe and obtain a heap address
The intended way to solve this challenge is to use the latter to first leak a heap address
and then use the first for a House of Einherjar exploit.

However I did not figure out vulnerability `2` during the ctf, and without a heap leak I was unable to leverage vulnerability `1`
So I looked somewhere else...

## Unintended vulnerability
```C
if (sender != (char *)0x0) {
    is_free = strncmp(sender,"Sender: ",8);
    if (is_free == 0) {
      free(sender);
      printf("[*] Sent sender\'s name!");
    }
  }
```
You may initially believe that the above check is perfectly fine.
In fact, when sender is freed, it goes into a tcache bin (or fastbin if the tcache bin for size `128` is full), and thus the first 8 bytes, which previously held `"Sender :"`
now contain a (safely linked) null or heap pointer.
Furthermore, suppose such pointer is reused to hold a (same-sized) `receiver`, then, since scanf disregards whitespaces, you cannot input "Receiver :" and thus the free check still holds.

Regardless, this check is still bypassable, thanks to absolutely coincidental implementation details 😲


First, you should note that `getline` (which is called in `edit_message` to input the receiver's name) does not discard whitespaces, it just stops at (and stores) the terminating newline.
We can thus input `"Sender :"` with it.
Now we need to get into some neat implementation details of `getline`
I recommand that you have a look at [`_IO_getdelim`](https://elixir.bootlin.com/glibc/glibc-2.32/source/libio/iogetdelim.c#L40) (which is called internally by `getline`) 
for yourself but here are the key takeaways :
- if `*lineptr` (buffer) provided is `NULL` or `*size` is `0` (which here is our case here), `*lineptr` is allocated `120` bytes
- this buffer is continusouly reallocated to the double of its size until it can fit the whole user input.
- [`realloc`](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L3150)
will try to extend the current chunk to reallocate if the chunk below it happens to not be in use

`sender` also happens to be `120` bytes 😏 

Thus, it can be reused then extended by `getline`, and become larger (size > `0x408` not accounting for `chunk_size`) 
which will not fit in tcache and thus will be elligible for backwards consolidation when subsequently freed, if the above chunk is in unsorted bin.
Thus, neither the top chunk nor any chunk in free lists will be equal to the sender which we will free again, bypassing double free checks.
However unlike with [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.32/house_of_botcake.c),
since this chunk was in tcache range after being extended by realloc,
when it is double freed an attempt at backwards consolidation will be attempted again, and the `prev_size` vs actual `chunk_size` check will fail :(
No sweat, we can simply change this size accordingly since it is now contained into a valid chunk.

Now we have all the knowledge we need 😀

## Exploit
- allocate 8 messages
- allocate the sender
- send all


At this point, the tcache bin for size `512` will be full and thus the sender (in tcache bin for size `128`) will be sandwhiched between a `512` sized unsorted bin chunk
(which was used for the `504` bytes content of the 8th message) and the top chunk
- allocate `6 messages`, so that the only the `sender` is in tcache bin for size `128`
- do a 'fake' edit with a large (`> 0x408`) receiver name.


No message will actually be edited, but the `sender` chunk will be grabbed by `getline`, then it will be extended using the top chunk.
When it is then freed again in `edit_message` it will be large enough to be put consolidated back into the top chunk and the unsorted bin chunk above.
Our freed sender is now into the top chunk, at a known offset.
- empty free bins by allocating a new message
- do another large 'fake' edit to set the `sender` chunk size to `0x21` (`0x20` also works since it is in tcache range) and to set the first `8` bytes of `sender` to `"Sender :"`
- send all **<- DOUBLE FREE HAPPENS HERE**
- allocate 6 new messages
- create a new message `M`

Since when the double-free happens the `sender` chunk has size `0x20`, it will be grabbed to store `receiver` and `content` pointers.
Remember that it is also inside the top chunk right now.
- do a large fake edit replace both `M->receiver` and `M->content` by GOT `entry` of `free` *(at known location since the executable is not PIE)*
- print all messages to leak the address of `free` in libc, and use it to compute the address of `system`
- edit `M` to overwrite the GOT entry of `free` by the address of `system` *(which is writable because of the Partial RELRO)*
- do a fake edit with receiver name `"/bin/sh"`. When it is subsequently freed, `system("/bin/sh")` is called instead of `free`

## Flag
```
SEKAI{y0U_Kn@W_h0W_tO_c@NduCt_H0uS3_@f_31Nh3rJ4r_43422bb9c023c5a8c37388316956e7c4}
```
~~*famous last words* 😛~~
