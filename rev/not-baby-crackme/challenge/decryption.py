cts = [57, 206, 105, 57, 166, 97, 124, 244, 11, 58, 33, 141, 89, 240, 21, 128, 102, 65, 150, 117, 251, 54, 103, 92, 167, 149, 50, 238, 188, 247, 191, 194, 149, 117, 96, 81, 183, 170, 165, 213, 130, 55, 235, 71, 125, 142, 96, 200, 158, 111, 160, 136, 132, 12, 63, 158, 124, 9, 23, 140, 95, 150, 14, 215]
k = [0x42, 0x37, 0x91, 0xA7, 0x59, 0xDA, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x69, 0x13, 0x37, 0xAC]

def rol(x, r):
    return ((x << r) | (x >> (8 - r))) & 255

def ror(x, r):
    return ((x >> r) | (x << (8 - r))) & 255

def bt(x, bit):
    return (x >> bit) & 1

def round_decrypt(b, k, round):
    tmp = b[::]
    b = [tmp[(i+round)*13 % 16] for i in range(16)]
    possibilities = []
    for next_guess in range(256):
        tmp = [''] * 16
        for i in range(15,-1,-1):
            x = b[i]
            next = tmp[i + 1] if i < 15 else next_guess
            keybyte = k[(i + round) % 16]
            if (bt(next, 2)):
                x = (x + 0x7a) % 256
            if (bt(next, 1)):
                x = (x - 0x3C) % 256
            if (bt(next, 7)):
                x ^= 0xA5
            x = ror(x, -i*13 % 8)
            x = 0b11111111 ^ x
            x = (x - (next ^ round)) % 256
            x ^= rol(keybyte, i % 8)
            tmp[i] = x
        if tmp[0] == next_guess:
            possibilities.append(tmp)
    return possibilities

def decrypt(b, k):
    ls = [b]
    for r in range(12-1, -1, -1):
        ls_new = []
        for bb in ls:
            ls_new += round_decrypt(bb, k, r)
        ls = ls_new
    return ls

pts = []
out_pt = b''
for i in range(0, len(cts), 16):
    blk = cts[i:i+16]
    pts = decrypt(blk, k)
    for pt in pts:
        pt = bytes(pt).replace(b'\x00', b'')
        if not all(33 <= x <= 127 for x in pt):
            continue
        out_pt += pt
        break

print(f'{out_pt = }')
