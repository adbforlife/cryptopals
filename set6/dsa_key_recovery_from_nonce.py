from random import randint
from cryptools import *
from binascii import *

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

def dsa_sign(m,x):
    done = False
    while not done:
        k = randint(1, q-1)
        r = pow(g, k, p) % q
        if r != 0:
            done = True
    s = pow(k, -1, q) * (unbytify(sha1(m)) + x * r) % q
    return (r,s)

def dsa_sign_with_nonce(m,x,k):
    r = pow(g, k, p) % q
    s = pow(k, -1, q) * (unbytify(sha1(m)) + x * r) % q
    return (r,s)

def dsa_verify(m,r,s,y):
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    w = pow(s, -1, q)
    u1 = unbytify(sha1(m)) * w % q
    u2 = r * w % q
    v = (pow(g,u1,p) * pow(y,u2,p)) % p % q
    return v == r

priv = 15213
pub = pow(g, priv, p)
m = b'adbforlife'
r,s = dsa_sign(m, priv)
assert(dsa_verify(m, r, s, pub))

def get_priv_from_nonce(k,r,s,m): 
    return ((s * k - unbytify(sha1(m))) % q) * pow(r, -1, q) % q

m = b'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'
assert(sha1(m) == unhexlify(b'd2d0714f014a9784047eaeccf956520045c45265'))
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940
for guess in range(pow(2,16)+1):
    if pow(g, guess, p) % q == r:
        break
x = get_priv_from_nonce(guess,r,s,m)
assert((r,s) == dsa_sign_with_nonce(m,x,guess))
assert(sha1(hex(x)[2:].encode()) == unhexlify(b'0954edd5e0afe5542a4adf012611a91912a3ec16'))
print(f'private key is {x}')

