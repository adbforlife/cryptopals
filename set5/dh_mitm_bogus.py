import gmpy2
import random
from binascii import unhexlify
from Crypto.Cipher import AES
import os
from cryptools import *

p = '''ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff'''
p = p.encode()
p = b''.join(p.split(b'\n'))
p = unhexlify(p)
p = int.from_bytes(p, 'big')
assert(gmpy2.is_prime(p))
g = 2

sa = 0
sb = 0
a = 0
b = 0

def establish_secrets():
    global a,b,sa,sb
    a = random.randint(1,p-1)
    b = random.randint(1,p-1)
    A = gmpy2.powmod(g,a,p)
    B = gmpy2.powmod(g,b,p)
    sa = int(gmpy2.powmod(B,a,p))
    sb = int(gmpy2.powmod(A,b,p))
    assert(sa == sb)

def establish_secrets_mitm():
    global a,b,sa,sb
    a = random.randint(1,p-1)
    b = random.randint(1,p-1)
    A = gmpy2.powmod(g,a,p)
    B = gmpy2.powmod(g,b,p)
    sa = int(gmpy2.powmod(p,a,p))
    sb = int(gmpy2.powmod(p,b,p))
    assert(sa == sb and sa == 0)

def send_to_bob(m):
    iv = os.urandom(16)
    cipher = AES.new(sha1(sa.to_bytes(192, 'big'))[:16], AES.MODE_CBC, iv=iv)
    c = cipher.encrypt(m)
    return c + iv

def dec_bob(c, iv):
    cipher = AES.new(sha1(sb.to_bytes(192, 'big'))[:16], AES.MODE_CBC, iv=iv)
    m = cipher.decrypt(c)
    return m

def send_to_alice(m):
    iv = os.urandom(16)
    cipher = AES.new(sha1(sb.to_bytes(192, 'big'))[:16], AES.MODE_CBC, iv=iv)
    c = cipher.encrypt(m)
    return c + iv

def dec_alice(c, iv):
    cipher = AES.new(sha1(sa.to_bytes(192, 'big'))[:16], AES.MODE_CBC, iv=iv)
    m = cipher.decrypt(c)
    return m

def send_to_bob_mitm(m):
    iv = os.urandom(16)
    cipher = AES.new(sha1(sa.to_bytes(192, 'big'))[:16], AES.MODE_CBC, iv=iv)
    c = cipher.encrypt(m)
    m_cipher = AES.new(sha1((0).to_bytes(192, 'big'))[:16], AES.MODE_CBC, iv=iv)
    print(f'Capturing {m_cipher.decrypt(c)}')
    return c + iv
    
def send_to_alice_mitm(m):
    iv = os.urandom(16)
    cipher = AES.new(sha1(sb.to_bytes(192, 'big'))[:16], AES.MODE_CBC, iv=iv)
    c = cipher.encrypt(m)
    m_cipher = AES.new(sha1((0).to_bytes(192, 'big'))[:16], AES.MODE_CBC, iv=iv)
    print(f'Capturing {m_cipher.decrypt(c)}')
    return c + iv

m = b'flag{frankiwiii}'

establish_secrets()
c = send_to_bob(m)
assert(dec_bob(c[:16], c[16:]) == m)
c = send_to_alice(m)
assert(dec_alice(c[:16], c[16:]) == m)

establish_secrets_mitm()
c = send_to_bob_mitm(m)
assert(dec_bob(c[:16], c[16:]) == m)
c = send_to_alice_mitm(m)
assert(dec_alice(c[:16], c[16:]) == m)


