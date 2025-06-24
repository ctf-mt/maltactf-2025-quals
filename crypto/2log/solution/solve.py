from sage.all import matrix, GF, RealField, log

h1 = 1825310437373651425737133387514704339138752170433274546111276309
h2 = 6525529513224929513242286153522039835677193513612437958976590021494532059727
h3 = 42423271339336624024407863370989392004524790041279794366407913985192411875865

# G = matrix(RR, [[1401, 2],[-2048, 1273]])
# print(G.eigenvalues()) # 1337, 1337.

RR = RealField(3000)
m = log(RR(1337), RR(2))
k0_est = int(RR(h1) / m)
print(f'{k0_est = }')

F = GF(2**255-19)
G = matrix(F, [[1401, 2],[-2048, 1273]])
GJ, M = G.jordan_form(transformation=True)
# note that M here does not help us in any way. We have to ownself derive a suitable M

# Let G = M * GJ * M**-1 for some M.
# Then GK = M * GJK * M**-1. ---> GJK = M**-1 * GK * M
# Let M = [a b, c d], GK = [w x, y z], we have
# Minv = 1/det * d -b -c a
# GJK = 1/det * [adw-aby+cdx-cbz,​bdw-b2y+ddx-dbz,-acw+a2y-c2x+acz,-bcw+aby-cdx+adz]
# to solve the dlog easily, we need either {adw-aby+cdx-cbz, -acw+a2y-c2x+acz} and ​bdw-b2y+ddx-dbz. We only know w,x
# this means we must find M such that: 
# -ab-cb == 0 OR a2+ac == 0
# -b2-db == 0
# one such way is to find an M such that b = 0. 

# since
# M * GJ = G * M, b == 0,
# 1337a == 1401a + 2c
# 1337c == -2048a + 1273c
# c + 1337d == 1273d
# ==> a = 2, c = -64, d = 1

a, b, c, d = 2, 0, -64, 1
M = matrix(F, [[2, 0],[-64, 1]])
assert G == M * GJ * M**-1

det = pow(a*d-b*c, -1, 2**255-19)
GJK_0_0 = F(det * (a*d*h2+c*d*h3))
GJK_0_1 = F(det * (d*d*h3))
k1 = GJK_0_1 * 1337 * pow(GJK_0_0, -1, 2**255-19)

int2bytes = lambda x:x.to_bytes((x.bit_length() + 7) // 8, "big")
flag = int2bytes(int(k0_est))[:-4] + int2bytes(int(k1))
print(flag)

# fun fact, the 2 lines below were used to derive h1
# # RR = RealField(3000)
# # h1 = int(log(RR(1337), RR(2)) * k0 - randint(-2**32, 2**32))