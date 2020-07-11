import hashlib

def sha256(m):
    h = hashlib.sha256()
    h.update(m)
    return h.digest()

asn1_pad = b'30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20'
ap = asn1_pad.split(b' ')
ap = list(map(lambda x: bytes([int(x, 16)]), ap))
ap = b''.join(ap)

emLen = 256

def emsa_sha256_encode(m):
    h = sha256(m)
    t = ap + h
    tLen = len(t)
    if emLen < tLen + 11:
        assert(0)
    ps = b'\xff' * (emLen - tLen - 3)
    em = b'\x00\x01' + ps + b'\x00' + t
    return em

def emsa_sha256_decode_bad(em):
    h = sha256(m)

e = 3
from Crypto.Util.number import getPrime
done = False
while not done:
    try:
        p = getPrime(1024)
        q = getPrime(1024)
        n = p * q
        lam = (p-1) * (q - 1)
        d = pow(e, -1, lam)
        done = True
    except:
        pass


def sign(m):
    em = emsa_sha256_encode(m)
    sig = pow(int.from_bytes(em, 'big'), d, n)
    return sig.to_bytes(emLen, 'big')

def verify_bad(m, sig):
    em = pow(int.from_bytes(sig, 'big'), e, n)
    em = em.to_bytes(emLen, 'big')
    assert(em[:2] == b'\x00\x01')
    em = em[2:]
    while bytes([em[0]]) == b'\xff':
        em = em[1:]
    assert(em[0] == 0)
    em = em[1:]
    apLen = len(ap)
    assert(em[:apLen] == ap)
    em = em[apLen:apLen+32]
    return em == sha256(m)

m = b'hi mom'
sig = sign(m)
assert(verify_bad(m, sig))

def fake_sign(m):
    em = emsa_sha256_encode(m)
    new_em = em[:3]
    i = 2
    while bytes([em[i]]) == b'\xff':
        i += 1
    assert(em[i] == 0)
    i += 1
    new_em += b'\x00'
    new_em += em[i:]
    new_em += bytes(emLen - len(new_em))
    import gmpy2
    gmpy2.get_context().precision = 10000
    r = gmpy2.root(int.from_bytes(new_em, 'big'), 3)
    r = int(r)
    r += 1
    sig = r.to_bytes(emLen, 'big')
    return sig

sig = fake_sign(m)
assert(verify_bad(m, sig))


