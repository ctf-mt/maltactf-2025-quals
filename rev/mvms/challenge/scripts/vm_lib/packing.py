from typing import Literal


endianness: Literal['little', 'big'] = 'little'
p8 = lambda x: x.to_bytes(1, endianness)
p8s = lambda x: x.to_bytes(1, endianness, signed=True)
p16 = lambda x: x.to_bytes(2, endianness)
p32 = lambda x: x.to_bytes(4, endianness)
p64 = lambda x: x.to_bytes(8, endianness)
p128 = lambda x: x.to_bytes(16, endianness)
