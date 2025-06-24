"""
Welcome to Warri Codes Assembly
-------------------------------
"""
from functools import reduce

tb = lambda x: x.to_bytes(4, "little")
compile = lambda x: reduce(lambda a, b: a + b, x)
add = lambda x, y: b'\x00' + tb(x) + tb(y)
sub = lambda x, y: b'\x01' + tb(x) + tb(y)
mul = lambda x, y: b'\x02' + tb(x) + tb(y)
div = lambda x, y: b'\x03' + tb(x) + tb(y)
mod = lambda x, y: b'\x04' + tb(x) + tb(y)
mov = lambda x, y: b'\x05' + tb(x) + tb(y)
moc = lambda x, y: b'\x06' + tb(x) + tb(y)
cmp = lambda x, y: b'\x07' + tb(x) + tb(y)
jeq = lambda x: b'\x08' + tb(x) + tb(0)
jl = lambda x: b'\x09' + tb(x) + tb(0)
jle = lambda x: b'\x0a' + tb(x) + tb(0)
jg = lambda x: b'\x0b' + tb(x) + tb(0)
jge = lambda x: b'\x0c' + tb(x) + tb(0)
stm = lambda x, y: b'\x0d' + tb(x) + tb(y)
ldm = lambda x, y: b'\x0e' + tb(x) + tb(y)
sys = lambda: b'\x0f' + tb(0) + tb(0)
call = lambda x: b'\x10' + tb(x) + tb(0)
ret = lambda: b'\x11' + tb(0) + tb(0)
aand = lambda x, y: b'\x12' + tb(x) + tb(y)
xxor = lambda x, y: b'\x13' + tb(x) + tb(y)
nnot = lambda x: b'\x14' + tb(x) + tb(0)
jmp = lambda x: b'\x15' + tb(x) + tb(0)
pprint = lambda x: b'\x16' + tb(x) + tb(0)
ror = lambda x, y: b'\x17' + tb(x) + tb(y)
rol = lambda x, y: b'\x18' + tb(x) + tb(y)
shr = lambda x, y: b'\x19' + tb(x) + tb(y)
shl = lambda x, y: b'\x1a' + tb(x) + tb(y)

PTR = 0

BT = compile([moc(2, 0), moc(3, 1), moc(4, 2),
              cmp(2, 1), jge(72 + PTR), div(0, 4), add(2, 3), jmp(27 + PTR),
              aand(0, 3), ret()
              ])
BT_ADDR = PTR
PTR += len(BT)
print(f'BT: {BT_ADDR}')

ENC = compile([moc(2, 12), moc(3, 48), stm(3, 2), moc(0, 0),
               moc(3, 49), stm(3, 0), call(234), moc(3, 49), ldm(0, 3), moc(4, 1), add(0, 4),
               moc(4, 48), ldm(3, 4), cmp(0, 3), jl(36 + PTR), ret()
               ])
ENC_ADDR = PTR
PTR += len(ENC)
print(f'ENC: {ENC_ADDR}')

ENC_BLK = compile([
    moc(1, 0),
    # A LOOP
    moc(3, 0), add(3, 1), ldm(4, 3), moc(2, 1), add(3, 2), moc(2, 16), mod(3, 2), ldm(5, 3), mov(3, 1), add(3, 0),
    moc(2, 16), mod(3, 2), add(3, 2), ldm(6, 3),

    mov(7, 1), moc(2, 8), mod(7, 2), mov(8, 6), rol(8, 7), xxor(4, 8),
    mov(7, 5), xxor(7, 0), add(4, 7), moc(2, 256), mod(4, 2),
    nnot(4),
    mov(7, 1), moc(2, 13), mul(7, 2), moc(2, 8), mod(7, 2), ror(4, 7),

    moc(7, 50), stm(7, 0), moc(7, 51), stm(7, 1), moc(7, 52), stm(7, 2), moc(7, 53), stm(7, 3), moc(7, 54), stm(7, 4),
    moc(7, 55), stm(7, 5), moc(7, 56), stm(7, 6),
    mov(0, 5), moc(1, 7), call(BT_ADDR), moc(1, 0), cmp(0, 1),
    moc(7, 50), ldm(0, 7), moc(7, 51), ldm(1, 7), moc(7, 52), ldm(2, 7), moc(7, 53), ldm(3, 7), moc(7, 54), ldm(4, 7),
    moc(7, 55), ldm(5, 7), moc(7, 56), ldm(6, 7),
    jeq(621 + PTR), moc(2, 0xa5), xxor(4, 2),

    moc(7, 50), stm(7, 0), moc(7, 51), stm(7, 1), moc(7, 52), stm(7, 2), moc(7, 53), stm(7, 3), moc(7, 54), stm(7, 4),
    moc(7, 55), stm(7, 5), moc(7, 56), stm(7, 6),
    mov(0, 5), moc(1, 1), call(BT_ADDR), moc(1, 0), cmp(0, 1),
    moc(7, 50), ldm(0, 7), moc(7, 51), ldm(1, 7), moc(7, 52), ldm(2, 7), moc(7, 53), ldm(3, 7), moc(7, 54), ldm(4, 7),
    moc(7, 55), ldm(5, 7), moc(7, 56), ldm(6, 7),
    jeq(963 + PTR), moc(2, 0x3c), add(4, 2), moc(2, 256), mod(4, 2),

    moc(7, 50), stm(7, 0), moc(7, 51), stm(7, 1), moc(7, 52), stm(7, 2), moc(7, 53), stm(7, 3), moc(7, 54), stm(7, 4),
    moc(7, 55), stm(7, 5), moc(7, 56), stm(7, 6),
    mov(0, 5), moc(1, 2), call(BT_ADDR), moc(1, 0), cmp(0, 1),
    moc(7, 50), ldm(0, 7), moc(7, 51), ldm(1, 7), moc(7, 52), ldm(2, 7), moc(7, 53), ldm(3, 7), moc(7, 54), ldm(4, 7),
    moc(7, 55), ldm(5, 7), moc(7, 56), ldm(6, 7),
    jeq(1305 + PTR), moc(2, 0x7a), sub(4, 2), moc(2, 255), aand(4, 2),

    moc(3, 32), add(3, 1), stm(3, 4),
    moc(2, 1), add(1, 2), moc(2, 16), cmp(1, 2), jl(9 + PTR),
    # A LOOP END. We know this works

    # B LOOP
    moc(1, 0),
    moc(3, 16), moc(2, 5), mul(2, 1), add(3, 2), sub(3, 0), moc(2, 16), mod(3, 2),
    moc(2, 32), add(3, 2), ldm(7, 3), stm(1, 7), moc(2, 1), add(1, 2), moc(2, 16), cmp(1, 2), jl(1386 + PTR),
    # B LOOP END

    ret()
])

ENC_BLK_ADDR = PTR
PTR += len(ENC_BLK)
print(f'ENC_BLK_ADDR: {ENC_BLK_ADDR}')
if b'A' in ENC_BLK:
    print(ENC_BLK.index(b'A'))

bcode = BT + ENC + ENC_BLK
print("{" + str(list(bcode))[1:-1] + "}")