from Crypto.Hash import MD4
import os
from struct import pack, unpack

def md_pad(m):
    padlen = (56 - len(m) % 64) % 64
    if padlen == 0:
        padlen = 64
    assert(padlen >= 1)
    return m + b'\x80' + b'\x00' * (padlen - 1)

def md4(m, state=[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]):
    # Step 1. Pad
    oglen = len(m)
    def pad(m):
        padlen = (56 - len(m) % 64) % 64
        if padlen == 0:
            padlen = 64
        assert(padlen >= 1)
        return m + b'\x80' + b'\x00' * (padlen - 1)
    m = pad(m)

    # Step 2. Append length
    m += pack('<Q', oglen * 8)

    # Step 3. Init MD buffer
    A = state[0]
    B = state[1]
    C = state[2]
    D = state[3]

    # Step 4. Process
    mask = 0xffffffff
    x = [0 for _ in range(16)]
    def NOT(X):
        return mask ^ X
    def F(X,Y,Z):
        return (X & Y) | (NOT(X) & Z)
    def G(X,Y,Z):
        return (X & Y) | (X & Z) | (Y & Z)
    def H(X,Y,Z):
        return X ^ Y ^ Z
    def ROT_LEFT(X,n):
        return ((X << n) | ((X & mask) >> (32 - n))) & mask

    def op1(a,b,c,d,k,s):
        return ROT_LEFT((a + F(b,c,d) + x[k]),s) & mask
    def op2(a,b,c,d,k,s):
        return ROT_LEFT((a + G(b,c,d) + x[k] + 0x5a827999),s) & mask
    def op3(a,b,c,d,k,s):
        return ROT_LEFT((a + H(b,c,d) + x[k] + 0x6ed9eba1),s) & mask

    m = [unpack('<I', m[i:i+4])[0] for i in range(0,len(m),4)]
    n = len(m)
    assert(n % 16 == 0)
    for i in range(n//16):
        for j in range(16):
            x[j] = m[i*16+j]
        AA = A
        BB = B
        CC = C
        DD = D

        A = op1(A,B,C,D,0,3)
        D = op1(D,A,B,C,1,7)
        C = op1(C,D,A,B,2,11)
        B = op1(B,C,D,A,3,19)
        A = op1(A,B,C,D,4,3)
        D = op1(D,A,B,C,5,7)
        C = op1(C,D,A,B,6,11)
        B = op1(B,C,D,A,7,19)
        A = op1(A,B,C,D,8,3)
        D = op1(D,A,B,C,9,7)
        C = op1(C,D,A,B,10,11)
        B = op1(B,C,D,A,11,19)
        A = op1(A,B,C,D,12,3)
        D = op1(D,A,B,C,13,7)
        C = op1(C,D,A,B,14,11)
        B = op1(B,C,D,A,15,19)

        A = op2(A,B,C,D,0,3)
        D = op2(D,A,B,C,4,5)
        C = op2(C,D,A,B,8,9)
        B = op2(B,C,D,A,12,13)
        A = op2(A,B,C,D,1,3)
        D = op2(D,A,B,C,5,5)
        C = op2(C,D,A,B,9,9)
        B = op2(B,C,D,A,13,13)
        A = op2(A,B,C,D,2,3)
        D = op2(D,A,B,C,6,5)
        C = op2(C,D,A,B,10,9)
        B = op2(B,C,D,A,14,13)
        A = op2(A,B,C,D,3,3)
        D = op2(D,A,B,C,7,5)
        C = op2(C,D,A,B,11,9)
        B = op2(B,C,D,A,15,13)

        A = op3(A,B,C,D,0,3)
        D = op3(D,A,B,C,8,9)
        C = op3(C,D,A,B,4,11)
        B = op3(B,C,D,A,12,15)
        A = op3(A,B,C,D,2,3)
        D = op3(D,A,B,C,10,9)
        C = op3(C,D,A,B,6,11)
        B = op3(B,C,D,A,14,15)
        A = op3(A,B,C,D,1,3)
        D = op3(D,A,B,C,9,9)
        C = op3(C,D,A,B,5,11)
        B = op3(B,C,D,A,13,15)
        A = op3(A,B,C,D,3,3)
        D = op3(D,A,B,C,11,9)
        C = op3(C,D,A,B,7,11)
        B = op3(B,C,D,A,15,15)

        A = (A + AA) & mask
        B = (B + BB) & mask
        C = (C + CC) & mask
        D = (D + DD) & mask

    return pack('<I', A) + pack('<I', B) + pack('<I', C) + pack('<I', D)


def md4_no_pad(m, state=[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]):
    # Step 3. Init MD buffer
    A = state[0]
    B = state[1]
    C = state[2]
    D = state[3]

    # Step 4. Process
    mask = 0xffffffff
    x = [0 for _ in range(16)]
    def NOT(X):
        return mask ^ X
    def F(X,Y,Z):
        return (X & Y) | (NOT(X) & Z)
    def G(X,Y,Z):
        return (X & Y) | (X & Z) | (Y & Z)
    def H(X,Y,Z):
        return X ^ Y ^ Z
    def ROT_LEFT(X,n):
        return ((X << n) | ((X & mask) >> (32 - n))) & mask

    def op1(a,b,c,d,k,s):
        return ROT_LEFT((a + F(b,c,d) + x[k]),s) & mask
    def op2(a,b,c,d,k,s):
        return ROT_LEFT((a + G(b,c,d) + x[k] + 0x5a827999),s) & mask
    def op3(a,b,c,d,k,s):
        return ROT_LEFT((a + H(b,c,d) + x[k] + 0x6ed9eba1),s) & mask

    m = [unpack('<I', m[i:i+4])[0] for i in range(0,len(m),4)]
    n = len(m)
    assert(n % 16 == 0)
    for i in range(n//16):
        for j in range(16):
            x[j] = m[i*16+j]
        AA = A
        BB = B
        CC = C
        DD = D

        A = op1(A,B,C,D,0,3)
        D = op1(D,A,B,C,1,7)
        C = op1(C,D,A,B,2,11)
        B = op1(B,C,D,A,3,19)
        A = op1(A,B,C,D,4,3)
        D = op1(D,A,B,C,5,7)
        C = op1(C,D,A,B,6,11)
        B = op1(B,C,D,A,7,19)
        A = op1(A,B,C,D,8,3)
        D = op1(D,A,B,C,9,7)
        C = op1(C,D,A,B,10,11)
        B = op1(B,C,D,A,11,19)
        A = op1(A,B,C,D,12,3)
        D = op1(D,A,B,C,13,7)
        C = op1(C,D,A,B,14,11)
        B = op1(B,C,D,A,15,19)

        A = op2(A,B,C,D,0,3)
        D = op2(D,A,B,C,4,5)
        C = op2(C,D,A,B,8,9)
        B = op2(B,C,D,A,12,13)
        A = op2(A,B,C,D,1,3)
        D = op2(D,A,B,C,5,5)
        C = op2(C,D,A,B,9,9)
        B = op2(B,C,D,A,13,13)
        A = op2(A,B,C,D,2,3)
        D = op2(D,A,B,C,6,5)
        C = op2(C,D,A,B,10,9)
        B = op2(B,C,D,A,14,13)
        A = op2(A,B,C,D,3,3)
        D = op2(D,A,B,C,7,5)
        C = op2(C,D,A,B,11,9)
        B = op2(B,C,D,A,15,13)

        A = op3(A,B,C,D,0,3)
        D = op3(D,A,B,C,8,9)
        C = op3(C,D,A,B,4,11)
        B = op3(B,C,D,A,12,15)
        A = op3(A,B,C,D,2,3)
        D = op3(D,A,B,C,10,9)
        C = op3(C,D,A,B,6,11)
        B = op3(B,C,D,A,14,15)
        A = op3(A,B,C,D,1,3)
        D = op3(D,A,B,C,9,9)
        C = op3(C,D,A,B,5,11)
        B = op3(B,C,D,A,13,15)
        A = op3(A,B,C,D,3,3)
        D = op3(D,A,B,C,11,9)
        C = op3(C,D,A,B,7,11)
        B = op3(B,C,D,A,15,15)

        A = (A + AA) & mask
        B = (B + BB) & mask
        C = (C + CC) & mask
        D = (D + DD) & mask

    return pack('<I', A) + pack('<I', B) + pack('<I', C) + pack('<I', D)


def md4_mac_ref(k,m):
    h = MD4.new()
    h.update(k+m)
    return h.digest()


if __name__ == '__main__':
    prefix = b'this_is_a_test'
    forgery = b'forge'
    given = md4(prefix)
    expected = md4(md_pad(prefix) + pack('<Q', len(prefix) * 8) + forgery)
    guess = md4_no_pad(md_pad(forgery) + pack('<Q', len(forgery) * 8 + 512), list(unpack('<4I', given)))
    print(expected)
    print(guess)




