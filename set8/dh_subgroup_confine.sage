import hashlib
from random import randint

p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
q = 236234353446506858198510045061214171961
j = 30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570

# Bob's sec key
b = randint(1, p) % q
B = pow(g,b,p)

def xor(m, k):
    if isinstance(m, str):
        m = m.encode('utf-8')
    if isinstance(k, str):
        k = k.encode('utf-8')
    assert(len(m) == len(k))
    return bytes([m[i]^^k[i] for i in range(len(m))])

def sha256(m): 
    h = hashlib.sha256()
    h.update(m)
    return h.digest()

def hmac_sha256(k,m):
    opad = bytes([0x5c for _ in range(32)])
    ipad = bytes([0x36 for _ in range(32)])
    if len(k) > 32:
        k = sha256(k)
    else:
        k += bytes([0 for _ in range(32 - len(k))])
    return sha256(xor(k, opad) + sha256(xor(k, ipad) + m))

m = b"crazy flamboyant for the rap enjoyment"
# What Bob does
def derive_hmac(A):
    k = pow(A,b,p)
    return hmac_sha256(str(k).encode(),m)

def crack_hmac(A,r,res):
    for i in range(0,r):
        if hmac_sha256(str(pow(A,i,p)).encode(),m) == res:
            return i
    assert(0)

factors = list(map(lambda x: x[0], list(factor(j))))[:-4]
assert(prod(factors) > q)
print(factors)
rems = []
for fac in factors:
    done = False
    while not done:
        a = randint(1,p)
        A = pow(a, (p-1)//fac, p)
        if A != 1:
            done = True
    res = derive_hmac(A)
    rem = crack_hmac(A, fac, res)
    assert(b % fac == rem)
    rems.append(rem)

print(rems)
guess = crt(rems, factors)
print(guess == b)



