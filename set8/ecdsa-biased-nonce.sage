from Crypto.Util.number import *
from binascii import *
from hashlib import sha256
from random import randint, sample
from os import urandom

# secp256k1 (used by bitcoin)
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
E = EllipticCurve(GF(p), [a,b])
G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
assert(q == E.order())

def h(m):
    return bytes_to_long(sha256(m).digest())
def sign(m,d):
    k = (randint(2, q) >> 8) << 8
    r = int((k * G)[0])
    s = int((h(m) + d * r) * pow(k, -1, q))
    return (r,s)
def verify(m, sig, Q, G):
    r,s = sig
    u1 = int(h(m) * pow(s, -1, q) % q)
    u2 = int(r * pow(s, -1, q) % q)
    R = u1 * G + u2 * Q
    return r == R[0]
m = b'adbforlife'
d = 15251
Q = d * G
assert(verify(m, sign(m, d), Q, G))
    
d = randint(2, q)
print(f"sec: {d}")

# LLL time (not _always_ successful but good enough most of the time)
NUM = 50
M = Matrix(QQ, NUM + 2, NUM + 2)
for i in range(NUM):
    m = urandom(10)
    r,s = sign(m, d)
    # t =    r / ( s*2^l)
    # u = H(m) / (-s*2^l)
    # u + aq - dt ~ 0
    t = int(r * pow(s * 2**8, -1, q) % q)
    u = int(h(m) * pow(-s * 2**8, -1, q) % q)
    M[NUM,i] = t
    M[NUM+1,i] = u
    M[i,i] = q
M[NUM,NUM] = 1/256
M[NUM+1,NUM+1] = q/256
A = M.LLL()
for r in A.rows():
    if r[-1] == q/256:
        bad = False
        for i in range(1, NUM):
            if r[i] * r[0] < 0:
                bad = True
                break
        if not bad:
            print(f"derived: {abs(r[-2] * 256)}")
            break


