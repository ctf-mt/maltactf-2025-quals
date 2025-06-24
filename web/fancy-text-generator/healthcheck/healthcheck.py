#!/usr/bin/env python3

# can't check full xss solve here, only confirms server health
# use solution/solve.py to test actual xss manually if needed

import requests
import hashlib
import base64

def check_hash(script: str):
    digest = hashlib.sha256(script.encode()).digest()
    hash_base64 = base64.b64encode(digest)
    return hash_base64 == b"1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ="

# check main functionality
r = requests.get("http://127.0.0.1:1337/?text=<h1>healthcheck</h1>")

if "<h1>healthcheck</h1>" not in r.text:
    print("backend is dead?")
    exit(1)

# check static file access and integrity
r = requests.get("http://127.0.0.1:1337/loader.js")

if r.status_code != 200:
    print("couldn't load loader.js")
    exit(1)

if not check_hash(r.text):
    print("csp hash is wrong")
    exit(1)

r = requests.get("http://127.0.0.1:1337/main.js")

if r.status_code != 200:
    print("couldn't load main.js")
    exit(1)

exit(0)
