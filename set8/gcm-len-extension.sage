from Crypto.Cipher import AES
from Crypto.Util.strxor import *
from Crypto.Util.number import *
from binascii import *
from os import urandom

key = b'\xbb\xa0\x97\x01_L\x1a}\x19\x9f\x8fsG\x03\xd1S'
nonce = b'\x17\xd0Bp\x13\xf8!\xf3\xeb\xd9\x9f\x19'

R.<x> = PolynomialRing(GF(2), 'x')
S.<y> = R.quotient(x^128 + x^7 + x^2 + x + 1)
T.<z> = S[]

def derive_len(m, header):
    l1 = long_to_bytes(len(header) * 8).rjust(8, b'\x00')
    l2 = long_to_bytes(len(m) * 8).rjust(8, b'\x00')
    return l1 + l2

# Given say header b0 and ciphertexts d0 and d1, 
# give b0*h^4 + d0*h^3 + d1*h^2 + len*h, where each
# coefficient is an elem in a quotient polynomial ring
def get_poly(m, header):
    l = derive_len(m, header)
    assert(len(l) == 16)
    m = m.ljust((len(m) + 15) // 16 * 16, b'\x00')
    header = header.ljust((len(header) + 15) // 16 * 16, b'\x00')
    m = header + m + l
    # Coefficients of the final polynomial
    cs = []
    for i in range(0, len(m), 16):
        c = bytes2poly(m[i:i+16])
        cs.append(c)
    cs.append(0)
    return T(cs[::-1])

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

def block_enc(k, m):
    assert(len(m) == 16)
    return AES.new(k, AES.MODE_ECB).encrypt(m)

def gcm_enc(k, m, header, nonce):
    s = block_enc(k, nonce + b'\x00\x00\x00\x01')
    h = block_enc(k, bytes(16))
    # Yes, imagine starting at 2 here sigh..
    c = AES.new(k, AES.MODE_CTR, nonce=nonce, initial_value=int(2)).encrypt(m)
    poly = get_poly(c, header)
    tag = strxor(poly2bytes(poly.subs(z=bytes2poly(h))), s)[:4]
    return c, tag

def gcm_enc_lib(k, m, header, nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=4)
    cipher.update(header)
    return cipher.encrypt_and_digest(m)

c1, tag1 = gcm_enc(key, b'message', b'header', nonce)
c2, tag2 = gcm_enc_lib(key, b'message', b'header', nonce)
assert((c1, tag1) == (c2, tag2))

def gcm_ver(k, c, tag, header, nonce):
    s = block_enc(k, nonce + b'\x00\x00\x00\x01')
    h = block_enc(k, bytes(16))
    poly = get_poly(c, header)
    t = strxor(poly2bytes(poly.subs(z=bytes2poly(h))), s)[:4]
    return t == tag

def gcm_ver_lib(k, c, tag, header, nonce):
    try:
        cipher = AES.new(k, AES.MODE_GCM, nonce=nonce, mac_len=4)
        cipher.update(header)
        cipher.decrypt_and_verify(c, tag)
        return True
    except:
        return False

assert(gcm_ver(key, c1, tag1, b'header', nonce))
assert(not gcm_ver(key, c1, tag1, b'headerr', nonce))
assert(not gcm_ver(key, c1, b'fake', b'header', nonce))
assert(gcm_ver_lib(key, c1, tag1, b'header', nonce))
assert(not gcm_ver_lib(key, c1, tag1, b'headerr', nonce))
assert(not gcm_ver_lib(key, c1, b'fake', b'header', nonce))

m = b'fakeflagfakeflag' * 2^17
m = m[:-1]
h = b'header' 
c, tag = gcm_enc_lib(key, m, h, nonce)
assert(gcm_ver_lib(key, c, tag, h, nonce))
print(f'true tag: {tag}')

def const2mat(cpoly):
    res = Matrix(GF(2), 128, 128)
    for i in range(128):
        ls = (cpoly * y^i).list()
        for j in range(128):
            res[j,i] = ls[j]
    return res

def getMs():
    res = Matrix(GF(2), 128, 128)
    for i in range(128):
        ls = (y^(2*i)).list()
        for j in range(128):
            res[j,i] = ls[j]
    return res

Ms = getMs()

def getT(n):
    T = Matrix(GF(2), (n-1) * 128, n * 128)
    for i in range(1,n+1):
        print(i)
        Msi = Ms^i
        for j in range(128):
            Ad = const2mat(y^j)
            Ad = Ad * Msi
            v = Ad[:n-1].list()
            for k in range((n-1)*128):
                T[k,(i-1) * 128 + j] = v[k]
    return T

def getAd(v):
    assert(len(v) == 128 * 17)
    res = Matrix(GF(2), 128, 128)
    for i in range(1, 18):
        sec = v[(i-1)*128 : i*128]
        res += const2mat(S(list(sec))) * Ms^i
    return res

def massage(blocks, v):
    assert(len(c) == 16 * 2^17 and len(v) == 128 * 17)
    def flipv(block, bs):
        assert(len(block) == 16)
        bs_int = int(''.join(list(map(str, bs))), 2)
        return long_to_bytes(bytes_to_long(block) ^^ bs_int).rjust(16, b'\x00')
    for i in range(1,18):
        ind = 2^i - 2
        blocks[ind] = flipv(blocks[ind], v[(i-1) * 128 : i * 128])
    
def get_tag(k, c, header, nonce):
    m = AES.new(k, AES.MODE_CTR, nonce=nonce, initial_value=int(2)).decrypt(c)
    res = gcm_enc_lib(k, m, header, nonce)
    assert(res[0] == c)
    return res[1]

print('Getting dependency matrix T and its kernel...')
TM = getT(17)
assert(TM.nrows() == 128 * 16 and TM.ncols() == 128 * 17)
NT = TM.right_kernel()
len1 = derive_len(m, h)
len2 = derive_len(m + b'\x00', h)
tvM = const2mat(bytes2poly(strxor(len1, len2)))
tv = vector(GF(2), tvM[:16].list())
og_v = TM.solve_right(tv)
print('Getting dependency matrix T and its kernel...done')

c = c + b'\x00'
og_blocks = [c[i:i+16] for i in range(0, len(c), 16)][::-1]

def tryRando():
    v = NT.random_element()
    v = og_v + v
    assert(len(v) == 128 * 17)
    #blocks = [c[i:i+16] for i in range(0, len(c), 16)][::-1]
    blocks = og_blocks.copy()
    massage(blocks, v)
    c2 = b''.join(blocks[::-1])
    assert(len(c2) == len(c))
    assert(get_tag(key, c2, h, nonce)[:2] == tag[:2])
    print(get_tag(key, c2, h, nonce))
    print(tag)
tryRando()
# Brute forcing is the same as previous chal..
