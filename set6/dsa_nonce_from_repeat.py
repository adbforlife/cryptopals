from random import randint
from cryptools import *
from binascii import *

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821



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


infos = open('44.txt', 'rb').read().rstrip().split(b'\n')
infos = [infos[i:i+4] for i in range(0,len(infos),4)]
def get_num(line):
    return eval(line.split(b': ')[1])
def get_msg(line):
    return line.replace(b'\n', b'').split(b': ')[1]
def get_hexnum(line):
    return int(line.split(b': ')[1], 16)
infos = [(get_msg(infos[i][0]), get_num(infos[i][2]), get_num(infos[i][1]), get_hexnum(infos[i][3])) for i in range(len(infos))]

for info in infos:
    assert(dsa_verify(info[0], info[1], info[2], y))

def is_correct_k(guess, r):
    return pow(g, guess, p) % q == r

for i in range(len(infos)):
    for j in range(i+1, len(infos)):
        info1 = infos[i]
        info2 = infos[j]
        m1 = info1[0]
        m2 = info2[0]
        h1 = unbytify(sha1(m1))
        assert(h1 == info1[3])
        h2 = unbytify(sha1(m2))
        assert(h2 == info2[3])
        r1 = info1[1]
        r2 = info2[1]
        s1 = info1[2]
        s2 = info2[2]
        try:
            guess = ((h1 - h2) % q) * pow((s1 - s2) % q, -1, q) % q
        except:
            continue
        if is_correct_k(guess, r1):
            x = get_priv_from_nonce(guess,r1,s1,m1)
            assert(sha1(hexlify(bytify(x))) == unhexlify(b'ca8f6f7c66fa362d40760d135b763eb8527d3d52'))
            print(f'private key is {x}, derived using messages {i} and {j}')

            



