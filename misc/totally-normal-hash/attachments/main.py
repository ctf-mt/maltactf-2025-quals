#!/usr/local/bin/python
try:
    from cryptostuff import make_merkle_root, hash_user
    import tempfile
    import re
    import subprocess
    import json
    import os
    from os.path import abspath, dirname, join


    def b2l(b):
        return int.from_bytes(b, 'big')

    def verify(proof):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
            temp_file.write(json.dumps(proof).encode('utf-8'))
            temp_file_path = temp_file.name
        try:
            result = subprocess.run(['node', join(abspath(dirname(__file__)), 'verifier/root.js'), temp_file_path], capture_output=True, text=True)
            if result.returncode != 0:
                return None

            output = result.stdout.strip()
            if not output:
                return None
            res = None
            if re.match(r'root = \d+', output):
                output = output.split('=')[1].strip()
                res = int(output)
            return res
        except:
            return None
        finally:
            os.remove(temp_file_path)


    username = int(input("Enter username: "))
    password = int(input("Enter password: "))
    password1 = password % (2**256)
    password2 = (password >> 256) % (2**256)
    password3 = (password >> 512) % (2**256)
    people = [
        ('genni', 'hunter2', 0, 0, 0),
        ('warriorz', 'hunter2', 0, 0, 0),
        ('neopro', 'hunter2', 0, 0, 0),
    ]
    users = [hash_user(*[b2l(x.encode()) if type(x) == str else x for x in p]) for p in people]
    users = [hash_user(username, password1, password2, password3, 0)] + users
    root = make_merkle_root(users)

    username = int(input("Enter username: "))
    password = int(input("Enter password: "))
    password1 = password % (2**256)
    password2 = (password >> 256) % (2**256)
    password3 = (password >> 512) % (2**256)
    role = int(input("Enter role (0 for user, 1 for admin): "))
    proof = json.loads(input("Enter proof: "))
    proof["leaf"] = hash_user(username, password1, password2, password3, role)

    root_ = verify(proof)
    if root_ and root_ == root:
        print("Access granted!")
    else:
        print("Access denied!")
        exit(1)

    if role == 1:
        print("woaw cool person")
        print(open(join(abspath(dirname(__file__)), 'flag.txt')).read())
except Exception as e:
    print(f"An error occurred: {e}")
