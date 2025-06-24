from Crypto.Util.number import *
N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
e = 65537

# factorise using sage or cado-nfs or alpertron or factordb, should take around a minute
p = 276784813000398431755706235529589161781
q = 302904819256337380397575865141537456903
assert N == p * q

# find all possible residues
arr = []
for r in [p,q]:
    F.<x> = GF(r)[]
    f = x^e + (256*x+46)^e - c
    arr.append(f.gcd(pow(x,r,f)-x).roots(multiplicities=False))

# print all possible flags
prefix = b'The flag is maltactf{'
for r1, r2 in cartesian_product(arr):
    s = crt([ZZ(r1),ZZ(r2)], [p,q])
    s -= bytes_to_long(prefix) << 256
    print(prefix + long_to_bytes(s % N))

# b'The flag is maltactf{Ferm4ts_littl3_polyn0mial_tr1ck}'