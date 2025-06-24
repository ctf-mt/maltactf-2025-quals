# made by neobeo 
from numpy import load
from pwn import unbits
enc = load('enc.npy')

M = matrix([(-1)**x for x in d0] for d0,d1 in enc)
v = vector(128 - round(vector(d1).norm()**2) for d0,d1 in enc)
print(unbits([round(.5-RR(x)) for x in M.solve_right(v)]))
