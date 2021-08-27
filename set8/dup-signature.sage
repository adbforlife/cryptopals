from Crypto.Util.number import *
from binascii import *
from hashlib import sha256
from random import randint, sample

# secp256k1 (used by bitcoin)
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
E = EllipticCurve(GF(p), [a,b])
G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
assert(n == E.order())

def h(m):
    return bytes_to_long(sha256(m).digest())


def sign(m, d):
    k = randint(2, n)
    r = int((k * G)[0])
    s = int((h(m) + d * r) * pow(k, -1, n) % n)
    return (r,s)

def verify(m, sig, Q, G):
    r,s = sig
    u1 = int(h(m) * pow(s, -1, n) % n)
    u2 = int(r * pow(s, -1, n) % n)
    R = u1 * G + u2 * Q
    return r == R[0]

m = b'adb'
d = 15213
Q = d * G
assert(verify(m, sign(m, d), Q, G))

# Fake public key
r,s = sign(m, d)
u1 = int(h(m) * pow(s, -1, n) % n)
u2 = int(r * pow(s, -1, n) % n)
R = u1 * G + u2 * Q
assert(R[0] == r)
d2 = 15251
t = int((u1 + u2 * d2) % n)
G2 = int(pow(t, -1, n)) * R
Q2 = d2 * G2
print(verify(m, (r,s), Q2, G2))


# Now, same for RSA (could be used to decrypt arbitrary to arbitrary message as
# well)
e = 65537
p = random_prime(2**512)
q = random_prime(2**512)
l = (p-1) * (q-1)
N = p * q
d = int(pow(e, -1, l))
m = h(b'adbforlife')
s = int(pow(m, d, N))
assert(int(pow(s, e, N)) == m)

curr = 2000
cands = []
for _ in range(1000):
    curr = next_prime(curr)
    cands.append(curr)

def solve():
        while True:
            ps = sample(set(cands), 45)
            p = 2 * prod(ps)
            if not is_prime(p+1):
                continue
            bad = False
            for prime in ps + [2]:
                if int(pow(s, p//prime, p)) == 1:
                    bad = True
                    break
                if int(pow(m, p//prime, p)) == 1:
                    bad = True
                    break
            if bad:
                continue
            else:
                for prime in ps:
                    cands.remove(prime)
                break
        while True:
            qs = sample(set(cands), 45)
            q = 2 * prod(qs)
            if not is_prime(q+1):
                continue
            bad = False
            for prime in qs + [2]:
                if int(pow(s, q//prime, q)) == 1:
                    bad = True
                    break
                if int(pow(m, q//prime, q)) == 1:
                    bad = True
                    break
            if bad:
                continue
            else:
                break

        p += 1
        q += 1
        assert(is_prime(p) and is_prime(q))
        print(f"p,q bitlen {p.nbits()},{q.nbits()}")
        N2 = p * q
        assert(N2 > N)
        ep = discrete_log(Zmod(p)(m), Zmod(p)(s))
        eq = discrete_log(Zmod(q)(m), Zmod(q)(s))
        assert(pow(s, ep, p) == m)
        assert(pow(s, eq, q) == m)
        e2 = crt([ep, eq], [p-1, q-1])
        return (e2, N2)

while True:
    try: 
        e2, N2 = solve()
        print(pow(s, e2, N2) == m)
        break
    except:
        pass
