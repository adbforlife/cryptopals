from pwn import *
import random
from cryptools import *

n = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
g = 2
k = 3

I = b'adbforlife2018@gmail.com'
p = b'iloveyou'

PORT = 15213

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


###############
# Correct SRP #
###############

r = remote('localhost', PORT)

# send A for DH
r.sendline(I)
a = random.randint(1, n-1)
A = pow(g,a,n)
r.sendline(str(A).encode())

# receive salt and B
s = r.recvuntil(b'\n')
salt = s[:16]
B = int(s[16:])

# compute key
uH = sha256(A.to_bytes(192, 'big') + B.to_bytes(192, 'big'))
u = int.from_bytes(uH, 'big')
xH = sha256(salt + p)
x = int.from_bytes(xH, 'big')
s = pow(B, a + u * x, n)
k = sha256(s.to_bytes(192, 'big'))

# Get final ok
r.send(hmac_sha256(k, salt))
res = r.recvline()
print(res)

