pt = b"maltactf{i_really_hope_the_relocations_got_you_:P}"
k = [0x42, 0x37, 0x91, 0xA7, 0x59, 0xDA, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x69, 0x13, 0x37, 0xAC]

def rol(x, r):
    return ((x << r) | (x >> (8 - r))) & 255

def ror(x, r):
    return ((x >> r) | (x << (8 - r))) & 255

def bt(x, bit):
    return (x >> bit) & 1

def round_encrypt(b, k, round):
    tmp = [0]*16
    for i in range(16):
        x = b[i]
        next = b[(i + 1) % 16]
        keybyte = k[(i + round) % 16]
        x ^= rol(keybyte, i % 8)
        x = (x + (next ^ round)) % 256
        x = 0b11111111 ^ x
        x = ror(x, i*13 % 8)
        if (bt(next, 7)):
            x ^= 0xA5
        if (bt(next, 1)):
            x = (x + 0x3C) % 256
        if (bt(next, 2)):
            x = (x - 0x7a) % 256
        tmp[i] = x
    for i in range(16):
        b[i] = tmp[(5 * i - round) % 16]
    return b

def encrypt(b, k):
    for r in range(12):
        b = round_encrypt(b, k, r)
    return b

while len(pt) % 16:
    pt += b'\x00'
print(f'{pt = }')
cts = []
for i in range(0, len(pt), 16):
    blk = list(pt[i:i+16])
    ct = encrypt(blk, k)
    cts += ct
print(f'{cts = }')
