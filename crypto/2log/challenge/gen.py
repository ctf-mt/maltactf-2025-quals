# gen.py
FLAG = b"maltactf{tw0-d10g5?_m0r3_l1kE_d0ubl3-l1nAlg!}"
k0, k1 = int.from_bytes(FLAG[:len(FLAG)//2], "big"), int.from_bytes(FLAG[len(FLAG)//2:], "big")

F = GF(2**255-19)
lam = 1337
GJ = matrix(F, [[lam,1],[0,lam]])
a,b,c,d = 2, 0, -64, 1
M = matrix(F, [[a,b],[c,d]])
G = M * GJ * M**-1 # ==> GJ == M**-1 * G * M
GK = pow(G, k1)
print(f'{G = }')
print(f'{GK = }')