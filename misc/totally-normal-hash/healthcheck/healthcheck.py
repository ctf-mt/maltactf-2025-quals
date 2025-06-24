#!/usr/bin/env python3

from pwn import *

p = remote("0.0.0.0", 1337)
print(open("/home/user/win.txt", "rb").read().decode())
p.sendline(open("/home/user/win.txt", "rb").read().strip())
print(p.recvuntil(b'maltactf{'))
print(p.recvuntil(b'}'))
exit(0)
