# Same problem from GoogleCTF 2021 Quals; that one's written in go..
from random import randint
o1 = 233970423115425145550826547352470124412
o2 = 233970423115425145544350131142039591210
o3 = 233970423115425145545378039958152057148
print(factor(o1))
print(factor(o2))
print(factor(o3))
p = 233970423115425145524320034830162017933
E0 = EllipticCurve(GF(p), (-95051, 11279326))
E1 = EllipticCurve(GF(p), (-95051, 210))
E2 = EllipticCurve(GF(p), (-95051, 504))
E3 = EllipticCurve(GF(p), (-95051, 727))
assert(o1 == E1.order())
assert(o2 == E2.order())
assert(o3 == E3.order())
sec = randint(2, o1)
print(f'hidden secret: {sec}')

def alice(B):
    x,y = B
    b = int((y**2 - x**3 + 95051*x) % p)
    E = EllipticCurve(GF(p), (-95051, b))
    return sec * E(B)

facs1 = [11, 23, 31, 89, 4999, 28411, 45361]
facs2 = [61, 12157, 34693]
facs3 = [7, 37, 67, 607, 1979, 13327, 13799]

def derive_mods(facs, E):
    mods = []
    o = E.order()
    for f in facs:
        print(f)
        while True:
            B = E.random_point()
            B = B * (o // f)
            if B.order() == f:
                break
        res = alice((B[0], B[1]))
        for i in range(0, f):
            if res == B * i:
                mods.append(i)    
                break
    return mods

def confirm_mods(mods, facs, sec):
    for i in range(len(facs)):
        assert(sec % facs[i] == mods[i])
mods1 = derive_mods(facs1, E1)
mods2 = derive_mods(facs2, E2)
mods3 = derive_mods(facs3, E3)
res = crt(mods1 + mods2 + mods3, facs1 + facs2 + facs3)
print(f'derived secret: {res}')
         

