import hashlib
from random import *
from gmpy2 import powmod

def sha256(m): 
    h = hashlib.sha256()
    h.update(m)
    return h.digest()

p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
q = 335062023296420808191071248367701059461
g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357
j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702

# Solve g^x = y (mod p), x \in [a,b]
def kangaroo(g,y,p,a,b):
    # width
    w = b - a
    # number of traps in kangaroo algo
    N = int(sqrt(w))
    # mean of S, range of our pseudo random function f
    m = N / 4
    # something random to make our f different every time
    r = randint(1,1000)
    # upper bound for range of f
    up = next_prime(2 * m)
    # pseudo random function with range roughly [1,upper]
    def f(x):
        seed(x)
        return randint(1,up)
   
    # use tame kangaroo to set trap for wild kangaroo
    x = int(powmod(g,b,p))
    d = b + f(x)
    traps = []
    for i in range(N-1):
        x = x * int(powmod(g,f(x),p)) % p
        assert(int(powmod(g,d,p)) == x)
        d += f(x)
        traps.append(d)
    trap = int(powmod(g,(d),p))

    # simulate wild kangaroo
    og_y = y
    dy = f(y)
    for i in range(8*N-1):
        y = y * int(powmod(g,f(y),p)) % p
        if trap == y:
            res = d - dy
            assert(int(powmod(g,res,p) == og_y))
            return res
        elif dy > b - a + d:
            return None
        dy += f(y)
    return None

y = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
x = 705485
assert(kangaroo(g,y,p,0,2^20) is not None)
'''
y = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733
x = kangaroo(g,y,p,0,2^40)
print(x,pow(g,x,p))
assert(x is not None)
'''

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

factors = list(map(lambda x: x[0], list(factor(j))))[:-1]
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
print(guess, prod(factors))

g2 = int(pow(g, prod(factors), p))
y2 = int(B * pow(g, -guess, p) % p)
print(y2)
x = kangaroo(g2,y2,p,0,2^41)
res = x * prod(factors) + guess
print(res == b)



