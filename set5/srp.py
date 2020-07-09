import gmpy2
import random
import hashlib
from binascii import unhexlify
import os
from cryptools import *

n = '''ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff'''
n = n.encode()
n = b''.join(n.split(b'\n'))
n = unhexlify(n)
n = int.from_bytes(n, 'big')
assert(gmpy2.is_prime(n))
g = 2
k = 3
I = b'adbforlife2018@gmail.com'
p = b'bad_password'


def sha256(m):
    hash_obj = hashlib.sha256()
    hash_obj.update(m)
    return hash_obj.digest()

def hmac_sha256(k,m):
    opad = bytes([0x5c for _ in range(64)])
    ipad = bytes([0x36 for _ in range(64)])
    if len(k) > 64:
        k = sha256(k)
    else:
        k += bytes([0 for _ in range(64 - len(k))])
    return sha256(xor(k, opad) + sha256(xor(k, ipad) + m))

expected_h = b'5f95511c3c719d568e110af302bbddd4ae78f6cbe0f8c1a57778866c5e0db0eb'
assert(hmac_sha256(b'adb', b'gg') == unhexlify(expected_h))

salt = os.urandom(16)
xH = sha256(salt + p)
x = int.from_bytes(xH, 'big')
v = pow(g,x,n)

a = random.randint(1,n-1)
b = random.randint(1,n-1)
A = pow(g,a,n)
B = (k * v + pow(g,b,n)) % n

uH = sha256(A.to_bytes(192, 'big') + B.to_bytes(192, 'big'))
u = int.from_bytes(uH, 'big')

xc = int.from_bytes(sha256(salt + p), 'big')
sc = pow(B - k * pow(g,xc,n), a+u*x, n)
kc = sha256(sc.to_bytes(192, 'big'))

ss = pow(A * pow(v,u,n), b, n)
ks = sha256(ss.to_bytes(192, 'big'))

assert(hmac_sha256(kc, salt) == hmac_sha256(ks, salt))

