import random, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

from montgomery_isogenies.kummer_line import KummerLine, KummerPoint
from montgomery_isogenies.kummer_isogeny import KummerLineIsogeny
from montgomery_isogenies.isogenies_x_only import lift_image_to_curve

from theta_structures.couple_point import CouplePoint
from theta_isogenies.product_isogeny import EllipticProductIsogeny

from utilities.discrete_log import BiDLP, discrete_log_pari
from utilities.supersingular import torsion_basis, torsion_basis_with_pairing

proof.all(False)    

def eval_dimtwo_isog(Phi, q, P, Q, ord, RS=None):

    R1 = P
    R2 = Phi.domain()[1](0)
    phiP = Phi(CouplePoint(R1, R2))
    imP = phiP[0]

    R1 = Q
    R2 = Phi.domain()[1](0)
    phiQ = Phi(CouplePoint(R1, R2))
    imQ = phiQ[0]

    R1 = P-Q
    R2 = Phi.domain()[1](0)
    phiPQ = Phi(CouplePoint(R1, R2))
    imPQ = phiPQ[0]

    if (imP - imQ)[0] != imPQ[0]:
        imQ = -imQ

    if RS == None:
        R, S, WP = torsion_basis_with_pairing(Phi.domain()[1], ord)
    else:
        R, S = RS
        WP = R.weil_pairing(S, ord)

    R1 = Phi.domain()[0](0)
    R2 = R
    phiR = Phi(CouplePoint(R1, R2))
    imR = phiR[0]

    R1 = Phi.domain()[0](0)
    R2 = S
    phiS = Phi(CouplePoint(R1, R2))
    imS = phiS[0]

    R1 = Phi.domain()[0](0)
    R2 = R-S
    phiRS = Phi(CouplePoint(R1, R2))
    imRS = phiRS[0]

    if (imR - imS)[0] != imRS[0]:
        imS = -imS

    wp = WP^q
    x, y = BiDLP(imP, imR, imS, ord, ePQ=wp)
    w, z = BiDLP(imQ, imR, imS, ord, ePQ=wp)

    imP = x*R + y*S
    imQ = w*R + z*S

    imP *= q
    imQ *= q
    return imP, imQ

def point_to_xonly(P, Q):
    L = KummerLine(P.curve())
    PQ = P - Q
    xP = L(P[0])
    xQ = L(Q[0])
    xPQ = L(PQ[0])
    return L, xP, xQ, xPQ
        
def random_unit(modulus):
    while True:
        alpha = ZZ.random_element(modulus)
        if gcd(alpha, modulus) == 1:
            break
    return alpha

def aes_enc(X, Y, msg):
    X_bytes = X.to_bytes()
    Y_bytes = Y.to_bytes() 
    key = sha256(X_bytes + Y_bytes).digest()[:16]
    return AES.new(key, AES.MODE_ECB).encrypt(pad(msg, 16))

def random_matrix(modulus):
    while True:
        d1 = ZZ.random_element(modulus)
        d2 = ZZ.random_element(modulus)
        d3 = ZZ.random_element(modulus)
        d4 = ZZ.random_element(modulus)
        if gcd(d1*d4 - d2*d3, modulus) == 1:
            break
    return d1, d2, d3, d4

# a, b, c, f = 254, 324, 36, 547
a, b, c, f = 127, 162, 18, 9
A, B, C = 2**a, 3**b, 5**c
p = 4 * f * A * B * C - 1
x = C

FF.<xx> = GF(p)[]
F.<i> = GF(p^2, modulus=xx^2+1)
E0 = EllipticCurve(F, [1, 0])
E0.set_order((p+1)**2)
PA, QA = torsion_basis(E0, 4*A)
PB, QB = torsion_basis(E0, B)
X0, Y0 = torsion_basis(E0, C)

PQA = PA - QA
PQB = PB - QB
XY0 = X0 - Y0

_E0 = KummerLine(E0)
_PB = _E0(PB[0])
_QB = _E0(QB[0])
_PQB = _E0(PQB[0])
xPA = _E0(PA[0])
xQA = _E0(QA[0])
xPQA = _E0(PQA[0])
xX_0 = _E0(X0[0])
xY_0 = _E0(Y0[0])
xXY_0 = _E0(XY0[0])

#############################
### Cue Winter by Vivaldi ###
#############################

def keygenA():
    for _ in range(1000):
        q = random.randint(0, 2^(a-1)-1)
        if q % 2 == 1 and q % 3 != 0 and q % 5 != 0 and (A-q) % 3 != 0 and (A-q) % 5 != 0 :
            break
    else:
        raise ValueError("Could not find suitable q.")

    deg = q
    rhs = deg * (2**a - deg) * B

    upper_bound = ZZ((rhs.nbits() - p.nbits()) // 2 - 2)
    alpha = random_unit(A)
    beta =  random_unit(A)
    gamma = random_unit(B)
    delta = random_unit(C)

    P2, Q2, P3, Q3 = PA, QA, PB, QB

    # https://eprint.iacr.org/2022/234.pdf, FullRepresentInteger
    QF = gp.Qfb(1, 0, 1)
    for _ in range(10_000):
        zz = randint(0, ZZ(2**upper_bound))
        tt = randint(0, ZZ(2**upper_bound))
        sq = rhs - p * (zz**2 + tt**2)
        if sq <= 0:
            continue
        if not sq.is_prime() or sq % 4 != 1:
            continue
        try:
            xx, yy = QF.qfbsolve(sq)
            break
        except ValueError:
            continue
    else:
        raise ValueError("Could not find a suitable endomorphism.")
    i_end = lambda P: E0(-P[0], i*P[1])
    pi_end = lambda P: E0(P[0]**p, P[1]**p)
    θ = lambda P: xx*P + yy*i_end(P) + zz*pi_end(P) + tt*i_end(pi_end(P))
    
    P2_ = θ(P2)
    Q2_ = θ(Q2)
    P3_ = θ(P3)
    Q3_ = θ(Q3)

    try:
        R = Q3
        wp_ = P3_.weil_pairing(R, B)
        wp = Q3_.weil_pairing(R, B)
        discrete_log_pari(wp_, wp, B)
        K3_dual = θ(Q3)
    except TypeError:
        R = P3
        K3_dual = θ(P3)

    K3_dual = _E0(K3_dual[0])
    phi3 = KummerLineIsogeny(_E0, K3_dual, B)

    xP2_ = _E0(P2_[0])
    xQ2_ = _E0(Q2_[0])
    xPQ2_ = _E0((P2_ - Q2_)[0])

    ximP2_ = phi3(xP2_)
    ximQ2_ = phi3(xQ2_)
    ximPQ2_ = phi3(xPQ2_)

    P2_ = ximP2_.curve_point()
    Q2_ = ximQ2_.curve_point()

    if (P2_ - Q2_)[0] != ximPQ2_.x():
        Q2_ = -Q2_

    inverse = inverse_mod(B, 4*A)
    P2_ = inverse * P2_
    Q2_ = inverse * Q2_
    
    P, Q = CouplePoint(-deg * P2, P2_), CouplePoint(-deg * Q2, Q2_)
    kernel = (P, Q)
    Phi = EllipticProductIsogeny(kernel, a)

    P23x = PA + PB + X0
    Q23x = QA + QB + Y0

    imP23x, imQ23x = eval_dimtwo_isog(Phi, A-deg, P23x, Q23x, 4*A*B*x)

    X_A = inverse_mod(4*A*B, x) * (4*A*B * imP23x)
    Y_A = inverse_mod(4*A*B, x) * (4*A*B * imQ23x)

    P2_og = alpha * inverse_mod(B*x, 4*A) * (B*x * imP23x)
    Q2_og =  beta * inverse_mod(B*x, 4*A) * (B*x * imQ23x)

    P3_og = gamma * inverse_mod(4*A*x, B) * (4*A*x * imP23x)
    Q3_og = gamma * inverse_mod(4*A*x, B) * (4*A*x * imQ23x)

    _, xP2, xQ2, xPQ2 = point_to_xonly(P2_og, Q2_og)
    _, xP3, xQ3, xPQ3 = point_to_xonly(P3_og, Q3_og)

    return (deg, alpha, beta, delta), (xP2, xQ2, xPQ2, xP3, xQ3, xPQ3, delta * X_A, delta * Y_A)

def encrypt(pkA, m, r3=0):
    xP2, xQ2, xPQ2, xP3, xQ3, xPQ3, X_A, Y_A = pkA
    beta = r3 if r3 else 0
    d1, d2, d3, d4 = random_matrix(C) 
    omega = random_unit(A)
    omega_inv = inverse_mod(omega, A)

    _KB = _QB.ladder_3_pt(_PB, _PQB, beta)
    phiB = KummerLineIsogeny(_E0, _KB, B)

    EB = phiB.codomain()
    xP2_B = phiB(xPA)
    xQ2_B = phiB(xQA)
    X_B = phiB(xX_0).curve_point()
    Y_B = phiB(xY_0).curve_point()
    xXY_B = phiB(xXY_0)

    if (X_B - Y_B)[0] != xXY_B.x():
        Y_B = -Y_B

    X_B, Y_B = d1*X_B + d2*Y_B, d3*X_B + d4*Y_B
    
    P2_B, Q2_B = lift_image_to_curve(PA, QA, xP2_B, xQ2_B, 4 * A, B)
    P2_B =     omega * P2_B
    Q2_B = omega_inv * Q2_B

    EA = xP3.parent()
    xK = xQ3.ladder_3_pt(xP3, xPQ3, beta)
    phiB_ = KummerLineIsogeny(EA, xK, B)

    EAB = phiB_.codomain().curve()
    xP2_AB = phiB_(xP2)
    xQ2_AB = phiB_(xQ2)
    xPQ2_AB = phiB_(xPQ2)


    P2_AB = xP2_AB.curve_point()
    Q2_AB = xQ2_AB.curve_point()
    if (P2_AB - Q2_AB)[0] != xPQ2_AB.x():
        Q2_AB = -Q2_AB

    P2_AB *= omega
    Q2_AB *= omega_inv

    xX_AB = phiB_(EA(X_A[0]))
    xY_AB = phiB_(EA(Y_A[0]))
    xXY_AB = phiB_(EA((X_A - Y_A)[0]))

    X_AB = xX_AB.curve_point()
    Y_AB = xY_AB.curve_point()

    if (X_AB - Y_AB)[0] != xXY_AB.x():
        Y_AB = -Y_AB

    X_AB, Y_AB = d1*X_AB + d2*Y_AB, d3*X_AB + d4*Y_AB

    ct = aes_enc(X_AB[0], Y_AB[0], m)
    return EB.curve().ainvs(), P2_B, Q2_B, X_B, Y_B, EAB.ainvs(), P2_AB, Q2_AB, ct

#####################
### The Challenge ###
#####################

class User:
    def __init__(self, isAlice):
        if isAlice:
            self._priv, self.pub = keygenA()
            self.pub = list(self.pub)
        else:
            self._priv = random_unit(B)
            self.pub = []
        self.isAlice = isAlice

    def getKeys(self):
        if not self.isAlice:
            return {}
        out_pub = self.getPub()
        out_priv = {key:int(val) for key, val in zip(["q","a","b","d"], self._priv)}
        return {"pub":out_pub, "priv":out_priv}
    
    def getPub(self):
        out_pub = {key:f'{val}' for key, val in zip(["P2","Q2","PQ2","P3","Q3","PQ3","XA","YA"], self.pub)}
        out_pub["EA"] = f'{self.pub[0].parent().curve().ainvs()}'
        return out_pub
    
    def setPub(self, index, v0, v1, v2, v3):
        val = self.pub[index]
        point = (eval(f"{v0}*i+{v1}"), eval(f"{v2}*i+{v3}"))
        if type(val) == KummerPoint:
            parent = self.pub[0].parent()
            self.pub[index] = KummerPoint(parent, point)

    def encrypt_msg(self, User, m):
        if self.isAlice:
            return []
        vals = encrypt(User.pub, m, self._priv)
        self.pub = vals[:5] # update Bob.pub
        out_vals = {key:f'{val}' for key, val in zip(["EB","PB","QB","XB","YB","EAB","PAB","QAB"], vals[:-1])}
        out_vals["ct"] = vals[-1].hex()
        return out_vals

FLAG = b"maltactf{??????????????????????????????????????????????????????????????????????????????}"
messages = [
    b"Hi Alice! -Bob",
    b"Don't mind Charlie. He's a friend -Bob",
    b"If you want the flag, you can ask from Charlie! -Bob",
    b"I heard Marvel made me into a superhero. :O -Bob",
    b"https://eprint.iacr.org/2024/624.pdf -Bob"
]

print("[SERVER] Initialising...")
You = User(True)
Bob = User(False)
Charlie = User(True)
print("[SERVER] Ready.")
while True:
    print("--------\n1: Get Codes\n2: Set Codes\n3: Hear From Bob\n4. Get Charlie Codes\n--------")
    choice = int(input("> "))
    if choice == 1:
        print(json.dumps(You.getKeys()))
    elif choice == 2:
        index = int(input("Index > ")) % len(You.pub)
        v0 = int(input("v0 > "))
        v1 = int(input("v1 > "))
        v2 = int(input("v2 > "))
        v3 = int(input("v3 > "))
        You.setPub(index, v0, v1, v2, v3)
        print("Done!")
    elif choice == 3:
        print(json.dumps(Bob.encrypt_msg(You, random.choice(messages))))
    elif choice == 4:
        print(json.dumps(Charlie.getPub()))
    else:
        break

print("Bob: My final message,")
print(json.dumps(Bob.encrypt_msg(Charlie, FLAG)))