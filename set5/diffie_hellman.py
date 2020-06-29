import random
from binascii import unhexlify
import gmpy2

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

a = random.randint(1,p-1)
b = random.randint(1,p-1)
A = gmpy2.powmod(g,a,p)
B = gmpy2.powmod(g,b,p)
s = gmpy2.powmod(A,b,p)
assert(s == gmpy2.powmod(B,a,p))

