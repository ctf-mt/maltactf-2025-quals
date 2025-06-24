grid_rules = bytes.fromhex("0400928A026166024D190120040240BE002084002D2B0039420240BD01110B00127D001101009316024D600110020052030160D802D37B023D2F0240520253150023B300534301820B0140020211650131870022F401306C00E3BC00C2E30024740011C20273BE02020F0042190052CA02B2A90221AE01CB8801933900205002D39401129501D3B101217200318B00219F00380C02306B0052890231720240D800F35100D22F0110AE0071600031E601C29B01A3240211F3007326003C390211A20002D302038802B26402210E00E3BD00232100213E0021AF01721600C3B102936F01243602E2790260ED00510D0093E001606401301800B2D000219A00254702204F0035780030D602E2C301591A02390C00C29600D2480073CD02D2A202421000D3120083A60030CE0135CA0113B501210A0052E500400D01E3E000B34E0110140130850239500002A502316400393200D68E02311B0212D00121D90021F70021290193820001B7004D2900399500926F00A33501C32801A27A01D2130093E301108600521701219002291501025A02284D020F000212CB0263860128980201BB0131FF0072C602A2B001C35B0028B00042390123B002828A0010030013010252D10242F5003DCB0122240073140013B901D3530135D400601A00F30E01135101243F0110F20062BC022C5F0102F9016CCC02138302346C025298018A5801581D0011C702F28D01376E0050C10233CE027387014291015EE201253B0180ED0133FE00102D0111A10062D700923B0021EF01345102422A011122023B0000B3910021D50293E7013118024DBF0282EB014DC402427D01106D024302012BD402E2DC0120C10031060023D002B3AA01209A0124C50000D702420801253700A3440281090012E50123B200403800310800D3D6003DBF0111D202720401514401F3AE0221670150C302B21E00005D02323B0220BD02D28D0240BA0151C502730601310700623601120500D2A60111840151CF0253270120C002D21102491C0243C00011C802723600D37701453500D31B00D32E0039170012270241C902E2A500217000411A01D3A30242A90040B801203D0231110063370273E400D2DE00517702298702824200F37901B30D02925E01D39B027600000000000000000000000000")
grid_rules = grid_rules[:819]

from z3 import Or, And, Not, BitVec, Solver, Sum
import itertools
from functools import reduce

def z3_nummines(pos, cnt):
    L, U, R, D = pos-1, pos-N, pos+1, pos+N
    UL, UR, DL, DR = pos-1-N, pos-N+1, pos+N-1, pos+N+1
    conditions = []
    for combo in combi:
        if sum(combo) == cnt:
            v0, v1, v2, v3, v4, v5, v6, v7 = combo
            conds = [eval(i) for i in [f"(A[{UL}]=={v0})", f"(A[{L}]=={v1})", f"(A[{DL}]=={v2})", f"(A[{D}]=={v3})", f"(A[{DR}]=={v4})", f"(A[{R}]=={v5})", f"(A[{UR}]=={v6})", f"(A[{U}]=={v7})"]]
            res = reduce(And, conds)
            conditions.append(res)
    return reduce(Or, conditions)

def z3_connected(pos, nums):
    L, U, R, D = pos-1, pos-N, pos+1, pos+N
    UL, UR, DL, DR = pos-1-N, pos-N+1, pos+N-1, pos+N+1
    conditions = []
    for combo in combi:
        if sum(combo) not in nums:
            continue
        if sum(combo) == 8 or sum(combo) == 0:
            v0, v1, v2, v3, v4, v5, v6, v7 = combo
            conds = [eval(i) for i in [f"(A[{UL}]=={v0})", f"(A[{L}]=={v1})", f"(A[{DL}]=={v2})", f"(A[{D}]=={v3})", f"(A[{DR}]=={v4})", f"(A[{R}]=={v5})", f"(A[{UR}]=={v6})", f"(A[{U}]=={v7})"]]
            res = reduce(And, conds)
            conditions.append(res)
            continue
        _combo = list(combo[:])
        while _combo[0] == 0:
            _combo = [_combo[-1]] + _combo[:-1]
        while _combo[-1] == 1:
            _combo = [_combo[-1]] + _combo[:-1]
        if _combo.index(0) != sum(combo):
            continue
        v0, v1, v2, v3, v4, v5, v6, v7 = combo
        conds = [eval(i) for i in [f"(A[{UL}]=={v0})", f"(A[{L}]=={v1})", f"(A[{DL}]=={v2})", f"(A[{D}]=={v3})", f"(A[{DR}]=={v4})", f"(A[{R}]=={v5})", f"(A[{UR}]=={v6})", f"(A[{U}]=={v7})"]]
        res = reduce(And, conds)
        conditions.append(res)
    return reduce(Or, conditions)

def z3_disjoint(pos, nums):
    L, U, R, D = pos-1, pos-N, pos+1, pos+N
    UL, UR, DL, DR = pos-1-N, pos-N+1, pos+N-1, pos+N+1
    conditions = []
    for combo in combi:
        if sum(combo) not in nums:
            continue
        isdisjoint = True
        for i in range(8):
            if combo[i % 8] == 1 and (combo[(i+1) % 8] == 1 or combo[(i-1) % 8] == 1):
                isdisjoint = False
        if not isdisjoint:
            continue
        v0, v1, v2, v3, v4, v5, v6, v7 = combo
        conds = [eval(i) for i in [f"(A[{UL}]=={v0})", f"(A[{L}]=={v1})", f"(A[{DL}]=={v2})", f"(A[{D}]=={v3})", f"(A[{DR}]=={v4})", f"(A[{R}]=={v5})", f"(A[{UR}]=={v6})", f"(A[{U}]=={v7})"]]
        res = reduce(And, conds)
        conditions.append(res)
    return reduce(Or, conditions) if len(conditions) else eval(f"(A[{pos}]==2)") # auto false condition


combi = list(itertools.product([0, 1], repeat=8))
A = [BitVec(f"a{_}", 8) for _ in range(729)]
N = 27
S = Solver()
S.add(Sum(A) == 179) # 179
for i in range(N*N):
    S.add(Or(eval(f"A[{i}] == 0"), eval(f"A[{i}] == 1")))
for i in range(0, len(grid_rules), 3):
    a0, a1, cnt = False, False, 0
    pos = int.from_bytes(grid_rules[i:i+2], "little")
    ins = grid_rules[i+2]
    if ins >= 128:
        cnt += 8; ins -= 128
    if ins >= 64:
        cnt += 4; ins -= 64
    if ins >= 32: 
        cnt += 2; ins -= 32
    if ins >= 16: 
        cnt += 1; ins -= 16
    if ins >= 8: 
        a0 = True; ins -= 8
    if ins >= 4: 
        a1 = True; ins -= 4
    if ins >= 2: 
        cnt = -1
    nums = [cnt] if cnt != -1 else list(range(9))
    if len(nums) == 1:
        S.add(z3_nummines(pos, cnt))
    if a0 and a1:
        S.add(Or(z3_connected(pos, nums), z3_disjoint(pos, nums)))
    if not a0 and a1:
        S.add(z3_disjoint(pos, nums))
    if a0 and not a1:
        S.add(z3_connected(pos, nums))
    S.add(eval(f"A[{pos}] == 0"))
print("Checking")
print(S.check())
model = S.model()
out = ""
for i in range(N*N):
    out += str(model[A[i]])
print(out) # write to file, then run MS_Paint and open said file

# To Prove Uniqueness
S.add(Not(reduce(And, [eval(f"A[{i}] == {model[A[i]]}") for i in range(729)])))
print(S.check()) # unsat

"""
Fun Fact, This is what the MineSweeper Grid Looks Like! It's actually possible to solve by hand.
|X| --> Connected X mines
<X> --> Disjoint X mines
[ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ]
[ ? ][   ][ 1 ][ 0 ][   ][   ][ 2 ][   ][   ][ ? ][   ][?3?][   ][   ][|3|][   ][|3|][   ][   ][|3|][   ][   ][   ][<?>][   ][   ][ ? ]
[ ? ][ ? ][ 3 ][ 2 ][   ][ 2 ][   ][   ][ 2 ][   ][   ][   ][ ? ][   ][   ][   ][   ][   ][ ? ][   ][   ][   ][   ][   ][   ][<3>][ ? ]
[ ? ][   ][   ][   ][   ][   ][   ][   ][   ][   ][|2|][   ][   ][   ][   ][ 3 ][   ][   ][   ][|3|][   ][   ][   ][   ][   ][   ][ ? ]
[ ? ][   ][ 5 ][ ? ][ 4 ][   ][ 3 ][   ][ 1 ][   ][   ][   ][ 3 ][   ][   ][   ][   ][ 1 ][   ][   ][   ][   ][ 0 ][   ][?2?][   ][ ? ]
[ ? ][   ][   ][ 1 ][ 2 ][   ][   ][   ][   ][   ][ 2 ][   ][   ][   ][ ? ][ ? ][   ][   ][   ][<2>][   ][   ][   ][   ][|3|][   ][ ? ]
[ ? ][   ][   ][ 2 ][ 3 ][   ][   ][ 4 ][   ][   ][   ][   ][ 7 ][   ][ ? ][   ][ 4 ][ ? ][   ][   ][   ][?4?][   ][   ][   ][   ][ ? ]
[ ? ][ 2 ][   ][ 1 ][ 3 ][   ][   ][   ][ 0 ][   ][   ][   ][   ][   ][   ][   ][   ][   ][   ][ 2 ][   ][   ][   ][ 6 ][   ][?3?][ ? ]
[ ? ][ 2 ][   ][   ][   ][   ][ 5 ][   ][ ? ][   ][   ][<2>][ ? ][ 4 ][   ][   ][   ][   ][   ][   ][   ][ 5 ][   ][   ][   ][   ][ ? ]
[ ? ][   ][?3?][   ][ 2 ][   ][   ][   ][   ][   ][   ][ 1 ][ ? ][   ][   ][|?|][ 6 ][ 5 ][   ][ 3 ][   ][<2>][   ][   ][ 4 ][   ][ ? ]
[ ? ][   ][   ][   ][   ][   ][ 3 ][ ? ][   ][ 2 ][   ][ 2 ][ ? ][   ][   ][   ][   ][   ][   ][   ][   ][   ][   ][   ][   ][ 2 ][ ? ]
[ ? ][ 1 ][   ][   ][ 1 ][   ][ 1 ][   ][   ][   ][   ][   ][ ? ][ ? ][   ][   ][ ? ][   ][ 8 ][   ][   ][   ][ 1 ][   ][   ][   ][ ? ]
[ ? ][   ][   ][   ][   ][   ][   ][   ][   ][   ][ 1 ][   ][   ][<2>][   ][<3>][   ][   ][   ][   ][|5|][   ][   ][   ][   ][   ][ ? ]
[ ? ][ 1 ][   ][   ][   ][ 3 ][ 3 ][   ][ 5 ][   ][   ][   ][   ][   ][   ][   ][<2>][   ][   ][   ][   ][   ][   ][   ][<4>][   ][ ? ]
[ ? ][   ][   ][ 1 ][   ][   ][   ][   ][   ][   ][ 5 ][   ][|2|][ ? ][ ? ][   ][   ][   ][   ][<?>][   ][   ][   ][???][   ][   ][ ? ]
[ ? ][   ][   ][|?|][   ][<2>][ ? ][   ][   ][   ][   ][   ][   ][   ][   ][   ][   ][ 1 ][   ][   ][   ][ 2 ][   ][   ][   ][|?|][ ? ]
[ ? ][ 2 ][   ][   ][   ][ 2 ][   ][   ][ 2 ][ ? ][ 5 ][ 3 ][   ][ 1 ][   ][ 1 ][   ][   ][   ][|5|][   ][   ][   ][   ][   ][   ][ ? ]
[ ? ][   ][   ][<3>][   ][ 2 ][   ][   ][   ][   ][   ][   ][   ][   ][   ][   ][   ][ 2 ][   ][   ][   ][ 6 ][   ][<2>][ 1 ][   ][ ? ]
[ ? ][ 3 ][   ][   ][   ][?4?][   ][ ? ][   ][<3>][   ][   ][   ][   ][ 3 ][   ][   ][   ][   ][?6?][   ][   ][   ][   ][   ][   ][ ? ]
[ ? ][ 1 ][   ][ 4 ][   ][   ][   ][   ][   ][   ][   ][ 3 ][ ? ][   ][   ][   ][|4|][   ][   ][   ][   ][?4?][   ][?4?][   ][|3|][ ? ]
[ ? ][   ][   ][   ][   ][   ][|?|][   ][ 1 ][   ][   ][ 4 ][   ][   ][   ][   ][   ][   ][   ][ 4 ][   ][   ][   ][   ][   ][   ][ ? ]
[ ? ][   ][ 1 ][   ][ 2 ][   ][ 3 ][   ][   ][   ][   ][ 4 ][   ][ 8 ][   ][   ][ 2 ][   ][   ][   ][   ][   ][???][   ][   ][ ? ][ ? ]
[ ? ][   ][   ][   ][   ][   ][   ][   ][|2|][   ][   ][ ? ][   ][   ][   ][   ][   ][   ][ 2 ][   ][?4?][   ][   ][   ][   ][   ][ ? ]
[ ? ][   ][   ][   ][   ][ 4 ][   ][   ][   ][   ][|2|][   ][ 6 ][   ][?3?][   ][   ][   ][   ][   ][   ][   ][<3>][   ][|3|][   ][ ? ]
[ ? ][ 3 ][ 6 ][   ][   ][ 4 ][ 3 ][   ][|2|][   ][   ][   ][   ][   ][   ][   ][ 0 ][   ][   ][<?>][   ][   ][   ][   ][   ][   ][ ? ]
[ ? ][   ][ 3 ][   ][   ][   ][ 2 ][   ][   ][   ][   ][ 2 ][   ][ ? ][ ? ][   ][   ][   ][   ][   ][   ][   ][   ][   ][   ][?2?][ ? ]
[ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ][ ? ]
"""