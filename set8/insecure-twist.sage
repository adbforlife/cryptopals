from random import randint, seed
from gmpy2 import powmod
from tqdm import tqdm
p = 233970423115425145524320034830162017933
E0 = EllipticCurve(GF(p), (-95051, 11279326))
G = E0(182, 85518893674295321206118380980485522083)
A = 534
B = 1
def ladder(u, k):
    def cswap(a,b,c):
        return (b,a) if c else (a,b)
    u2, w2 = (1, 0)
    u3, w3 = (u, 1)
    for i in range(p.nbits())[::-1]:
        b = 1 & (k >> i)
        u2, u3 = cswap(u2, u3, b)
        w2, w3 = cswap(w2, w3, b)
        u3, w3 = ((u2*u3 - w2*w3)**2, u*(u2*w3-w2*u3)**2)
        u3, w3 = (int(u3 % p), int(w3 % p))
        u2, w2 = ((u2**2 - w2**2)**2, 4*u2*w2 * (u2**2 + A*u2*w2 + w2**2))
        u2, w2 = (int(u2 % p), int(w2 % p))
        u2, u3 = cswap(u2, u3, b)
        w2, w3 = cswap(w2, w3, b)
    return int(u2 * int(powmod(w2,p-2,p)) % p)

o0 = E0.order()
assert(ladder(4, 1) == 4)
assert(ladder(4, o0) == 0)
# v^2 = u^3 + 534*u^2 + u
# u = x - 178
# v = y

twisto = p * 2 + 2 - o0
sec = randint(2, o0)
sec = 44577686865624338547564133897841076598
print(f"secret: {sec}")
facs = [11, 107, 197, 1621, 105143, 405373,
11 * 107, 11 * 197, 11 * 1621, 11 * 105143, 11 * 405373, 2323367]
'''
Derive tentative mods. Since we don't distinguish 2 mod 11 and 9 mod 11 for
example, this will take 2 mod 11 regardless
'''
'''
mods = []
for fac in facs:
    print(fac)
    while True:
        r = randint(2, p) 
        if not (r%p).is_square():
            test = ladder(r, twisto//fac)
            if ladder(test, fac) == 0 and test != 0:
                if len(factor(fac)) == 1:
                    break
                else:
                    a = factor(fac)[0][0]
                    b = factor(fac)[1][0]
                    if ladder(test, a) != 0 and ladder(test, b) != 0:
                        break
    # Alice unwillingly does this
    res = ladder(test, sec)
    for i in tqdm(range(0, fac+1)):
        if ladder(test, i) == res:
            mods.append(i)
            print(mods)
            break
'''
mods = [2, 33, 96, 205, 29726, 38095, 354, 101, 6279, 134869, 38095, 1062755]


'''
Derive 4 candidates for mod product of the small factors
'''
possibles = []
signs = [1]
for i in range(1, 6):
    maybe = crt([mods[0], mods[i]], [facs[0], facs[i]])
    if mods[5+i] == min(maybe, facs[0] * facs[i] - maybe):
        signs.append(1)
    else:
        signs.append(-1)
signs1 = signs + [1]
signs2 = signs + [-1]
signs3 = list(map(lambda x: -x, signs)) + [1]
signs4 = list(map(lambda x: -x, signs)) + [-1]
def signs2cand(ls):
    inds = [0,1,2,3,4,5,11]
    mods_real = [mods[i] for i in inds]
    facs_real = [facs[i] for i in inds]
    mods_real = [mods_real[i] if ls[i] > 0 else facs_real[i] - mods_real[i]
    for i in range(len(facs_real))]
    return crt(mods_real, facs_real)
cands = []
cands.append(signs2cand(signs1))
cands.append(signs2cand(signs2))
cands.append(signs2cand(signs3))
cands.append(signs2cand(signs4))
print(cands)
inds = [0,1,2,3,4,5,11]
fac = prod([facs[i] for i in inds])
assert(sec % fac in cands)

'''
Use kangaroo to get it done!
'''
# Solve G^x = y, x \in [a,b]
def kangaroo(G,Y,a,b):
    # width
    w = b - a
    # number of traps in kangaroo algo
    N = int(sqrt(w))
    # mean of S, range of our pseudo random function f
    m = N // 4
    # something random to make our f different every time
    r = randint(1,1000)
    # upper bound for range of f
    up = next_prime(2 * m)
    # pseudo random function with range roughly [1,upper]
    def f(Q):
        seed(Q[0]+r)
        resf = randint(1,up)
        return resf
   
    # use tame kangaroo to set trap for wild kangaroo
    YT = G * b
    d = b + f(YT)
    traps = []
    for i in tqdm(range(N-1)):
        YT = YT + G * f(YT)
        #assert(G * d == YT)
        d += f(YT)
        traps.append(d)
    trap = G * d

    # simulate wild kangaroo
    YW = Y
    dw = f(YW)
    for i in tqdm(range(8*N-1)):
        YW = YW + G * f(YW)
        if trap == YW:
            res = d - dw
            #assert(G * res == Y)
            return res
        elif dw > b - a + d:
            return None
        dw += f(YW)
    return None

assert(kangaroo(G, G * 300, 0, 10000) == 300)
testing = randint(2, 15217 * 15227)
known_mod = int(testing % 15217)
assert(kangaroo(G * 15217, G * testing + G * (-known_mod), 0, 20000) * 15217 +
    known_mod == testing)

def test_cand(cand):
    Y = G * sec
    Y2 = Y + G * (-cand)
    G2 = G * fac
    res = kangaroo(G2,Y2,0,twisto//fac)
    if res:
        return res * fac + cand
    else:
        return None
res = test_cand(cands[0])
if res:
    print(f"derived: {res}")


