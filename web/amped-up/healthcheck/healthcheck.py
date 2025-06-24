#!/usr/bin/env python3

import requests

r = requests.get("http://127.0.0.1:1337/")

print(r.text)
exit(0)