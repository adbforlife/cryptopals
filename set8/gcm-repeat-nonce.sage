from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from binascii import *
import os
key = unhexlify(b'feffe9928665731c6d6a8f9467308308')
h = AES.new(key, AES.MODE_ECB).encrypt(bytes(16))

# Given message and header, produce a ciphertext and a tag
def encrypt(m, header, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(header)
    c, tag = cipher.encrypt_and_digest(m)
    return {'nonce': cipher.nonce, "header": header, "ciphertext": c, "tag": tag}

def derive_len(m, header):
    l1 = long_to_bytes(len(header) * 8).hex().rjust(16, '0')
    l2 = long_to_bytes(len(m) * 8).hex().rjust(16, '0')
    return unhexlify(l1 + l2)

# Given say header b0 and ciphertexts d0 and d1, 
# give b0*h^4 + d0*h^3 + d1*h^2 + len*h, where each
# coefficient is an elem in a quotient polynomial ring
def get_poly(m, header):
    l = derive_len(m, header)
    assert(len(l) == 16)
    m = hexlify(m).decode()
    m += '0' * ((32 - len(m)) % 32)
    header = hexlify(header).decode()
    header += '0' * ((32 - len(header)) % 32)
    m = unhexlify(header + m) + l
    # Coefficients of the final polynomail
    cs = []
    for i in range(0, len(m), 16):
        c = bytes2poly(m[i:i+16])
        cs.append(c)
    cs.append(0)
    return T(cs[::-1])
    
R.<x> = PolynomialRing(GF(2), 'x')
S.<y> = R.quotient(x^128 + x^7 + x^2 + x + 1)
T.<z> = S[]

def bytes2poly(m):
    assert(len(m) == 16)
    res = bin(bytes_to_long(m))[2:]
    res = [int(c) for c in res]
    res = [0] * (128 - len(res)) + res
    res = S(res)
    return res

def poly2bytes(f):
    b = ''.join(list(map(str, f.list())))
    return long_to_bytes(int(b, 2))

# Test 3 given by the original GCM document
m = unhexlify(b'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255')
head = unhexlify(b'')
iv = unhexlify(b'cafebabefacedbaddecaf888')
enc = encrypt(m, head, iv)
h = bytes2poly(h)
f = get_poly(enc["ciphertext"], head)
t = enc["tag"]
t = bytes2poly(t)
s = AES.new(key, AES.MODE_ECB).encrypt(enc["nonce"] + bytes([0,0,0,1]))
s = bytes2poly(s)
assert(t+s == f.subs(z=h))

# Test 4 given by the original GCM document
m = unhexlify(b'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
head = unhexlify(b'feedfacedeadbeeffeedfacedeadbeefabaddad2')
iv = unhexlify(b'cafebabefacedbaddecaf888')
enc = encrypt(m, head, iv)
f = get_poly(enc["ciphertext"], head)
t = enc["tag"]
t = bytes2poly(t)
s = AES.new(key, AES.MODE_ECB).encrypt(enc["nonce"] + bytes([0,0,0,1]))
s = bytes2poly(s)
assert(t+s == f.subs(z=h))

# Testing same iv vulnerability
m1 = b'first-messsage'
head1 = b''
m2 = b'the-second-one'
head2 = b''
enc1 = encrypt(m1, head1, iv)
enc2 = encrypt(m2, head2, iv)
t1 = bytes2poly(enc1["tag"])
t2 = bytes2poly(enc2["tag"])
poly1 = get_poly(enc1["ciphertext"], head1)
poly2 = get_poly(enc2["ciphertext"], head2)
poly = poly1 + poly2 + t1 + t2
c,b,a = poly.list()
# z^2 + 1/a * c is the square of z + h
assert(pow(1/a * c, 2**127) == h)
