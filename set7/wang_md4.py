from Crypto.Hash import MD4
import os
from struct import pack, unpack

def md_pad(m):
    padlen = (56 - len(m) % 64) % 64
    if padlen == 0:
        padlen = 64
    assert(padlen >= 1)
    return m + b'\x80' + b'\x00' * (padlen - 1)

mask = 0xffffffff
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
def ROT_RIGHT(X,n):
    return (X >> n) | ((X << (32 - n)) & mask)

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
    x = [0 for _ in range(16)]
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
    x = [0 for _ in range(16)]
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

def md4_ops(m, state=[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]):
    assert(len(m) == 64)
    # Step 3. Init MD buffer
    A = state[0]
    B = state[1]
    C = state[2]
    D = state[3]

    # Step 4. Process
    x = [0 for _ in range(16)]
    def op1(a,b,c,d,k,s):
        return ROT_LEFT((a + F(b,c,d) + x[k]),s)
    def op2(a,b,c,d,k,s):
        return ROT_LEFT((a + G(b,c,d) + x[k] + 0x5a827999),s)
    def op3(a,b,c,d,k,s):
        return ROT_LEFT((a + H(b,c,d) + x[k] + 0x6ed9eba1),s)

    m = [unpack('<I', m[i:i+4])[0] for i in range(0,len(m),4)]
    n = len(m)
    assert(n == 16)
    x = m.copy()
    AA = A
    BB = B
    CC = C
    DD = D
    As = []
    Bs = []
    Cs = []
    Ds = []
    def store(A,B,C,D):
        As.append(A)
        Bs.append(B)
        Cs.append(C)
        Ds.append(D)

    store(A,B,C,D)
    A = op1(A,B,C,D,0,3)
    D = op1(D,A,B,C,1,7)
    C = op1(C,D,A,B,2,11)
    B = op1(B,C,D,A,3,19)
    store(A,B,C,D)
    A = op1(A,B,C,D,4,3)
    D = op1(D,A,B,C,5,7)
    C = op1(C,D,A,B,6,11)
    B = op1(B,C,D,A,7,19)
    store(A,B,C,D)
    A = op1(A,B,C,D,8,3)
    D = op1(D,A,B,C,9,7)
    C = op1(C,D,A,B,10,11)
    B = op1(B,C,D,A,11,19)
    store(A,B,C,D)
    A = op1(A,B,C,D,12,3)
    D = op1(D,A,B,C,13,7)
    C = op1(C,D,A,B,14,11)
    B = op1(B,C,D,A,15,19)
    store(A,B,C,D)

    A = op2(A,B,C,D,0,3)
    D = op2(D,A,B,C,4,5)
    C = op2(C,D,A,B,8,9)
    B = op2(B,C,D,A,12,13)
    store(A,B,C,D)
    A = op2(A,B,C,D,1,3)
    D = op2(D,A,B,C,5,5)
    C = op2(C,D,A,B,9,9)
    B = op2(B,C,D,A,13,13)
    store(A,B,C,D)
    A = op2(A,B,C,D,2,3)
    D = op2(D,A,B,C,6,5)
    C = op2(C,D,A,B,10,9)
    B = op2(B,C,D,A,14,13)
    store(A,B,C,D)
    A = op2(A,B,C,D,3,3)
    D = op2(D,A,B,C,7,5)
    C = op2(C,D,A,B,11,9)
    B = op2(B,C,D,A,15,13)
    store(A,B,C,D)

    A = op3(A,B,C,D,0,3)
    D = op3(D,A,B,C,8,9)
    C = op3(C,D,A,B,4,11)
    B = op3(B,C,D,A,12,15)
    store(A,B,C,D)
    A = op3(A,B,C,D,2,3)
    D = op3(D,A,B,C,10,9)
    C = op3(C,D,A,B,6,11)
    B = op3(B,C,D,A,14,15)
    store(A,B,C,D)
    A = op3(A,B,C,D,1,3)
    D = op3(D,A,B,C,9,9)
    C = op3(C,D,A,B,5,11)
    B = op3(B,C,D,A,13,15)
    store(A,B,C,D)
    A = op3(A,B,C,D,3,3)
    D = op3(D,A,B,C,11,9)
    C = op3(C,D,A,B,7,11)
    B = op3(B,C,D,A,15,15)
    store(A,B,C,D)

    A = (A + AA) & mask
    B = (B + BB) & mask
    C = (C + CC) & mask
    D = (D + DD) & mask
    assert(len(As) == 13)

    return (pack('<I', A) + pack('<I', B) + pack('<I', C) + pack('<I', D), As, Bs, Cs, Ds)

def massage(m):
    assert(len(m) == 64)
    _, As, Bs, Cs, Ds = md4_ops(m)
    ms = [unpack('<I', m[i:i+4])[0] for i in range(0,len(m),4)] 
    def fix1(v, b, desired):
        if desired:
            return v | (1 << (b - 1))
        else:
            return v ^ ((1 << (b - 1)) & v) 
    def fixls(v, ls):
        for b, d in ls:
            v = fix1(v, b, d)
        return v
    As[1] = fixls(As[1], [(7, Bs[0] & (1 << 6))])
    ms[0] = (ROT_RIGHT(As[1], 3) - F(Bs[0], Cs[0], Ds[0]) - As[0]) & mask
    Ds[1] = fixls(Ds[1], [(7, 0), (8, As[1] & (1 << 7)), (11, As[1] & (1 << 10))])
    ms[1] = (ROT_RIGHT(Ds[1], 7) - F(As[1], Bs[0], Cs[0]) - Ds[0]) & mask
    Cs[1] = fixls(Cs[1], [(7, 1), (8, 1), (11, 0), (26, Ds[1] & (1 << 25))])
    ms[2] = (ROT_RIGHT(Cs[1], 11) - F(Ds[1], As[1], Bs[0]) - Cs[0]) & mask
    Bs[1] = fixls(Bs[1], [(7, 1), (8, 0), (11, 0), (26, 0)])
    ms[3] = (ROT_RIGHT(Bs[1], 19) - F(Cs[1], Ds[1], As[1]) - Bs[0]) & mask

    As[2] = fixls(As[2], [(8, 1), (11, 1), (26, 0), (14, Bs[1] & (1 << 13))] +
        [(18, Bs[1] & (1 << 17)), (23, Bs[1] & (1 << 22))]
    )
    ms[4] = (ROT_RIGHT(As[2], 3) - F(Bs[1], Cs[1], Ds[1]) - As[1]) & mask
    Ds[2] = fixls(Ds[2], [(14, 0), (19, As[2] & (1 << 18)), (20, As[2] & (1 << 19)), (21, As[2] & (1 << 20)), (22, As[2] & (1 << 21)), (26, 1)] +
        [(18, 0), (23, 0)]
    )
    ms[5] = (ROT_RIGHT(Ds[2], 7) - F(As[2], Bs[1], Cs[1]) - Ds[1]) & mask
    Cs[2] = fixls(Cs[2], [(13, Ds[2] & (1 << 12)), (14, 0), (15, Ds[2] & (1 << 14)), (19, 0), (20, 0), (21, 1), (22, 0)] +
        [(18, 0), (23, 0)]
    )
    ms[6] = (ROT_RIGHT(Cs[2], 11) - F(Ds[2], As[2], Bs[1]) - Cs[1]) & mask
    Bs[2] = fixls(Bs[2], [(13, 1), (14, 1), (15, 0), (17, Cs[2] & (1 << 16)), (19, 0), (20, 0), (21, 0), (22, 0)] + 
        [(18, 0), (23, 0)]
    )
    ms[7] = (ROT_RIGHT(Bs[2], 19) - F(Cs[2], Ds[2], As[2]) - Bs[1]) & mask

    As[3] = fixls(As[3], [(13, 1), (14, 1), (15, 1), (17, 0), (19, 0), (20, 0), (21, 0), (21, 0), (23, Bs[2] & (1 << 22)), (22, 1), (26, Bs[2] & (1 << 25))])
    ms[8] = (ROT_RIGHT(As[3], 3) - F(Bs[2], Cs[2], Ds[2]) - As[2]) & mask
    Ds[3] = fixls(Ds[3], [(13, 1), (14, 1), (15, 1), (17, 0), (20, 0), (21, 1), (22, 1), (23, 0), (26, 1), (30, As[3] & (1 << 29))])
    ms[9] = (ROT_RIGHT(Ds[3], 7) - F(As[3], Bs[2], Cs[2]) - Ds[2]) & mask
    Cs[3] = fixls(Cs[3], [(17, 1), (20, 0), (21, 0), (22, 0), (23, 0), (26, 0), (30, 1), (32, Ds[3] & (1 << 31))])
    ms[10] = (ROT_RIGHT(Cs[3], 11) - F(Ds[3], As[3], Bs[2]) - Cs[2]) & mask
    Bs[3] = fixls(Bs[3], [(20, 0), (21, 1), (22, 1), (23, Cs[3] & (1 << 22)), (26, 1), (30, 0), (32, 0)])
    ms[11] = (ROT_RIGHT(Bs[3], 19) - F(Cs[3], Ds[3], As[3]) - Bs[2]) & mask

    As[4] = fixls(As[4], [(23, 0), (26, 0), (27, Bs[3] & (1 << 26)), (29, Bs[3] & (1 << 28)), (30, 1), (32, 0)])
    ms[12] = (ROT_RIGHT(As[4], 3) - F(Bs[3], Cs[3], Ds[3]) - As[3]) & mask
    Ds[4] = fixls(Ds[4], [(23, 0), (26, 0), (27, 1), (29, 1), (30, 0), (32, 1)])
    ms[13] = (ROT_RIGHT(Ds[4], 7) - F(As[4], Bs[3], Cs[3]) - Ds[3]) & mask
    Cs[4] = fixls(Cs[4], [(19, Ds[4] & (1 << 18)), (23, 1), (26, 1), (27, 0), (29, 0), (30, 0)])
    ms[14] = (ROT_RIGHT(Cs[4], 11) - F(Ds[4], As[4], Bs[3]) - Cs[3]) & mask
    Bs[4] = fixls(Bs[4], [(19, 0), (26, 1), (27, 1), (29, 1), (30, 0)])
    ms[15] = (ROT_RIGHT(Bs[4], 19) - F(Cs[4], Ds[4], As[4]) - Bs[3]) & mask

    As[5] = ROT_LEFT((As[4] + G(Bs[4],Cs[4],Ds[4]) + ms[0] + 0x5a827999), 3)
    if As[5] & (1 << 18) != Cs[4] & (1 << 18):
        if As[1] & (1 << 18):
            ms[0] = (ms[0] - (1 << 15)) & mask
        else:
            ms[0] = (ms[0] + (1 << 15)) & mask
        As[1] = As[1] ^ (1 << 18)
        ms[1] = (ROT_RIGHT(Ds[1], 7) - F(As[1], Bs[0], Cs[0]) - Ds[0]) & mask
        ms[2] = (ROT_RIGHT(Cs[1], 11) - F(Ds[1], As[1], Bs[0]) - Cs[0]) & mask
        ms[3] = (ROT_RIGHT(Bs[1], 19) - F(Cs[1], Ds[1], As[1]) - Bs[0]) & mask
        ms[4] = (ROT_RIGHT(As[2], 3) - F(Bs[1], Cs[1], Ds[1]) - As[1]) & mask
        As[5] = ROT_LEFT((As[4] + G(Bs[4],Cs[4],Ds[4]) + ms[0] + 0x5a827999), 3)
    if As[5] & (1 << 25) != 1 << 25:
        if As[1] & (1 << 25):
            ms[0] = (ms[0] - (1 << 22)) & mask
        else:
            ms[0] = (ms[0] + (1 << 22)) & mask
        As[1] = As[1] ^ (1 << 25)
        ms[1] = (ROT_RIGHT(Ds[1], 7) - F(As[1], Bs[0], Cs[0]) - Ds[0]) & mask
        ms[2] = (ROT_RIGHT(Cs[1], 11) - F(Ds[1], As[1], Bs[0]) - Cs[0]) & mask
        ms[3] = (ROT_RIGHT(Bs[1], 19) - F(Cs[1], Ds[1], As[1]) - Bs[0]) & mask
        ms[4] = (ROT_RIGHT(As[2], 3) - F(Bs[1], Cs[1], Ds[1]) - As[1]) & mask
        As[5] = ROT_LEFT((As[4] + G(Bs[4],Cs[4],Ds[4]) + ms[0] + 0x5a827999), 3)
    if As[5] & (1 << 26) != 0:
        if As[1] & (1 << 26):
            ms[0] = (ms[0] - (1 << 23)) & mask
        else:
            ms[0] = (ms[0] + (1 << 23)) & mask
        As[1] = As[1] ^ (1 << 26)
        ms[1] = (ROT_RIGHT(Ds[1], 7) - F(As[1], Bs[0], Cs[0]) - Ds[0]) & mask
        ms[2] = (ROT_RIGHT(Cs[1], 11) - F(Ds[1], As[1], Bs[0]) - Cs[0]) & mask
        ms[3] = (ROT_RIGHT(Bs[1], 19) - F(Cs[1], Ds[1], As[1]) - Bs[0]) & mask
        ms[4] = (ROT_RIGHT(As[2], 3) - F(Bs[1], Cs[1], Ds[1]) - As[1]) & mask
        As[5] = ROT_LEFT((As[4] + G(Bs[4],Cs[4],Ds[4]) + ms[0] + 0x5a827999), 3)
    if As[5] & (1 << 28) != 1 << 28:
        if As[1] & (1 << 28):
            ms[0] = (ms[0] - (1 << 25)) & mask
        else:
            ms[0] = (ms[0] + (1 << 25)) & mask
        As[1] = As[1] ^ (1 << 28)
        ms[1] = (ROT_RIGHT(Ds[1], 7) - F(As[1], Bs[0], Cs[0]) - Ds[0]) & mask
        ms[2] = (ROT_RIGHT(Cs[1], 11) - F(Ds[1], As[1], Bs[0]) - Cs[0]) & mask
        ms[3] = (ROT_RIGHT(Bs[1], 19) - F(Cs[1], Ds[1], As[1]) - Bs[0]) & mask
        ms[4] = (ROT_RIGHT(As[2], 3) - F(Bs[1], Cs[1], Ds[1]) - As[1]) & mask
        As[5] = ROT_LEFT((As[4] + G(Bs[4],Cs[4],Ds[4]) + ms[0] + 0x5a827999), 3)
    if As[5] & (1 << 31) != 1 << 31:
        if As[1] & (1 << 31):
            ms[0] = (ms[0] - (1 << 28)) & mask
        else:
            ms[0] = (ms[0] + (1 << 28)) & mask
        As[1] = As[1] ^ (1 << 31)
        ms[1] = (ROT_RIGHT(Ds[1], 7) - F(As[1], Bs[0], Cs[0]) - Ds[0]) & mask
        ms[2] = (ROT_RIGHT(Cs[1], 11) - F(Ds[1], As[1], Bs[0]) - Cs[0]) & mask
        ms[3] = (ROT_RIGHT(Bs[1], 19) - F(Cs[1], Ds[1], As[1]) - Bs[0]) & mask
        ms[4] = (ROT_RIGHT(As[2], 3) - F(Bs[1], Cs[1], Ds[1]) - As[1]) & mask
        As[5] = ROT_LEFT((As[4] + G(Bs[4],Cs[4],Ds[4]) + ms[0] + 0x5a827999), 3)

    _, As, Bs, Cs, Ds = md4_ops(b''.join(list(map(lambda x: pack('<I', x), ms))))
    if Ds[5] & (1 << 18) != As[5] & (1 << 18):
        if As[2] & (1 << 16):
            ms[4] = (ms[4] - (1 << 13)) & mask
        else:
            ms[4] = (ms[4] + (1 << 13)) & mask
        As[2] = As[2] ^ (1 << 16)
        ms[5] = (ROT_RIGHT(Ds[2], 7) - F(As[2], Bs[1], Cs[1]) - Ds[1]) & mask
        ms[6] = (ROT_RIGHT(Cs[2], 11) - F(Ds[2], As[2], Bs[1]) - Cs[1]) & mask
        ms[7] = (ROT_RIGHT(Bs[2], 19) - F(Cs[2], Ds[2], As[2]) - Bs[1]) & mask
        ms[8] = (ROT_RIGHT(As[3], 3) - F(Bs[2], Cs[2], Ds[2]) - As[2]) & mask
        Ds[5] = ROT_LEFT((Ds[4] + G(As[5],Bs[4],Cs[4]) + ms[4] + 0x5a827999), 5)
    if Ds[5] & (1 << 25) != Bs[4] & (1 << 25):
        if As[2] & (1 << 23):
            ms[4] = (ms[4] - (1 << 20)) & mask
        else:
            ms[4] = (ms[4] + (1 << 20)) & mask
        As[2] = As[2] ^ (1 << 23)
        ms[5] = (ROT_RIGHT(Ds[2], 7) - F(As[2], Bs[1], Cs[1]) - Ds[1]) & mask
        ms[6] = (ROT_RIGHT(Cs[2], 11) - F(Ds[2], As[2], Bs[1]) - Cs[1]) & mask
        ms[7] = (ROT_RIGHT(Bs[2], 19) - F(Cs[2], Ds[2], As[2]) - Bs[1]) & mask
        ms[8] = (ROT_RIGHT(As[3], 3) - F(Bs[2], Cs[2], Ds[2]) - As[2]) & mask
        Ds[5] = ROT_LEFT((Ds[4] + G(As[5],Bs[4],Cs[4]) + ms[4] + 0x5a827999), 5)
    if Ds[5] & (1 << 26) != Bs[4] & (1 << 26):
        if As[2] & (1 << 24):
            ms[4] = (ms[4] - (1 << 21)) & mask
        else:
            ms[4] = (ms[4] + (1 << 21)) & mask
        As[2] = As[2] ^ (1 << 24)
        ms[5] = (ROT_RIGHT(Ds[2], 7) - F(As[2], Bs[1], Cs[1]) - Ds[1]) & mask
        ms[6] = (ROT_RIGHT(Cs[2], 11) - F(Ds[2], As[2], Bs[1]) - Cs[1]) & mask
        ms[7] = (ROT_RIGHT(Bs[2], 19) - F(Cs[2], Ds[2], As[2]) - Bs[1]) & mask
        ms[8] = (ROT_RIGHT(As[3], 3) - F(Bs[2], Cs[2], Ds[2]) - As[2]) & mask
        Ds[5] = ROT_LEFT((Ds[4] + G(As[5],Bs[4],Cs[4]) + ms[4] + 0x5a827999), 5)
    if Ds[5] & (1 << 28) != Bs[4] & (1 << 28):
        if As[2] & (1 << 26):
            ms[4] = (ms[4] - (1 << 23)) & mask
        else:
            ms[4] = (ms[4] + (1 << 23)) & mask
        As[2] = As[2] ^ (1 << 26)
        ms[5] = (ROT_RIGHT(Ds[2], 7) - F(As[2], Bs[1], Cs[1]) - Ds[1]) & mask
        ms[6] = (ROT_RIGHT(Cs[2], 11) - F(Ds[2], As[2], Bs[1]) - Cs[1]) & mask
        ms[7] = (ROT_RIGHT(Bs[2], 19) - F(Cs[2], Ds[2], As[2]) - Bs[1]) & mask
        ms[8] = (ROT_RIGHT(As[3], 3) - F(Bs[2], Cs[2], Ds[2]) - As[2]) & mask
        Ds[5] = ROT_LEFT((Ds[4] + G(As[5],Bs[4],Cs[4]) + ms[4] + 0x5a827999), 5)
    if Ds[5] & (1 << 31) != Bs[4] & (1 << 31):
        if As[2] & (1 << 29):
            ms[4] = (ms[4] - (1 << 26)) & mask
        else:
            ms[4] = (ms[4] + (1 << 26)) & mask
        As[2] = As[2] ^ (1 << 29)
        ms[5] = (ROT_RIGHT(Ds[2], 7) - F(As[2], Bs[1], Cs[1]) - Ds[1]) & mask
        ms[6] = (ROT_RIGHT(Cs[2], 11) - F(Ds[2], As[2], Bs[1]) - Cs[1]) & mask
        ms[7] = (ROT_RIGHT(Bs[2], 19) - F(Cs[2], Ds[2], As[2]) - Bs[1]) & mask
        ms[8] = (ROT_RIGHT(As[3], 3) - F(Bs[2], Cs[2], Ds[2]) - As[2]) & mask
        Ds[5] = ROT_LEFT((Ds[4] + G(As[5],Bs[4],Cs[4]) + ms[4] + 0x5a827999), 5)
    
    res = b''.join(list(map(lambda x: pack('<I', x), ms))) 
    assert(verify_conds(res, [1,21,3,4]))
    _, As, Bs, Cs, Ds = md4_ops(res)
    if Cs[5] & (1 << 26) != Ds[5] & (1 << 26):
        ms[5] = (ms[5] + (1 << 10)) & mask
        ms[8] = (ms[8] - (1 << 17)) & mask
        ms[9] = (ms[9] - (1 << 17)) & mask
        Cs[5] = ROT_LEFT((Cs[4] + G(Ds[5],As[5],Bs[4]) + ms[8] + 0x5a827999), 9)
        Ds[2] = ROT_LEFT((Ds[1] + F(As[2],Bs[1],Cs[1]) + ms[5]), 7)
    if Cs[5] & (1 << 29) != Ds[5] & (1 << 29):
        if As[3] & (1 << 23):
            ms[8] = (ms[8] - (1 << 20)) & mask
        else:
            ms[8] = (ms[8] + (1 << 20)) & mask
        As[3] = As[3] ^ (1 << 23)
        ms[9] = (ROT_RIGHT(Ds[3], 7) - F(As[3], Bs[2], Cs[2]) - Ds[2]) & mask
        ms[10] = (ROT_RIGHT(Cs[3], 11) - F(Ds[3], As[3], Bs[2]) - Cs[2]) & mask
        ms[11] = (ROT_RIGHT(Bs[3], 19) - F(Cs[3], Ds[3], As[3]) - Bs[2]) & mask
        ms[12] = (ROT_RIGHT(As[4], 3) - F(Bs[3], Cs[3], Ds[3]) - As[3]) & mask
        Cs[5] = ROT_LEFT((Cs[4] + G(Ds[5],As[5],Bs[4]) + ms[8] + 0x5a827999), 9)
    if Cs[5] & (1 << 31) != Ds[5] & (1 << 31):
        ms[5] = (ms[5] + (1 << 15)) & mask
        ms[8] = (ms[8] - (1 << 22)) & mask
        ms[9] = (ms[9] - (1 << 22)) & mask
        Cs[5] = ROT_LEFT((Cs[4] + G(Ds[5],As[5],Bs[4]) + ms[8] + 0x5a827999), 9)
        Ds[2] = ROT_LEFT((Ds[1] + F(As[2],Bs[1],Cs[1]) + ms[5]), 7)

    res = b''.join(list(map(lambda x: pack('<I', x), ms))) 
    assert(verify_conds(res, [1,22,3,4,5]))

    return res

def verify_conds(m, sets=[1,21,3,4,5]):
    assert(len(m) == 64)
    _, As, Bs, Cs, Ds = md4_ops(m)
    ms = [unpack('<I', m[i:i+4])[0] for i in range(0,len(m),4)] 
    if 1 in sets:
        if (
            As[1] & (1 << 6) != Bs[0] & (1 << 6) or
            Ds[1] & (1 << 6) != 0 or
            Ds[1] & (1 << 7) != As[1] & (1 << 7) or
            Ds[1] & (1 << 10) != As[1] & (1 << 10) or
            Cs[1] & (1 << 6) != 1 << 6 or
            Cs[1] & (1 << 7) != 1 << 7 or
            Cs[1] & (1 << 10) != 0 or
            Cs[1] & (1 << 25) != Ds[1] & (1 << 25) or
            Bs[1] & (1 << 6) != 1 << 6 or
            Bs[1] & (1 << 7) != 0 or
            Bs[1] & (1 << 10) != 0 or
            Bs[1] & (1 << 25) != 0
        ):
            print('fail 1')
            return False

    if 21 in sets:
        if (
            As[2] & (1 << 7) != 1 << 7 or
            As[2] & (1 << 10) != 1 << 10 or
            As[2] & (1 << 25) != 0 or
            As[2] & (1 << 13) != Bs[1] & (1 << 13) or
            Ds[2] & (1 << 13) != 0 or
            Ds[2] & (1 << 18) != As[2] & (1 << 18) or
            Ds[2] & (1 << 19) != As[2] & (1 << 19) or
            Ds[2] & (1 << 20) != As[2] & (1 << 20) or
            Ds[2] & (1 << 21) != As[2] & (1 << 21) or
            Ds[2] & (1 << 25) != 1 << 25 or
            Cs[2] & (1 << 12) != Ds[2] & (1 << 12) or
            Cs[2] & (1 << 13) != 0 or
            Cs[2] & (1 << 14) != Ds[2] & (1 << 14) or
            Cs[2] & (1 << 18) != 0 or
            Cs[2] & (1 << 19) != 0 or
            Cs[2] & (1 << 20) != 1 << 20 or
            Cs[2] & (1 << 21) != 0 or
            Bs[2] & (1 << 12) != 1 << 12 or
            Bs[2] & (1 << 13) != 1 << 13 or 
            Bs[2] & (1 << 14) != 0 or
            Bs[2] & (1 << 16) != Cs[2] & (1 << 16) or
            Bs[2] & (1 << 18) != 0 or
            Bs[2] & (1 << 19) != 0 or
            Bs[2] & (1 << 20) != 0 or
            Bs[2] & (1 << 21) != 0 or
            As[2] & (1 << 17) != Bs[1] & (1 << 17) or
            As[2] & (1 << 22) != Bs[1] & (1 << 22) or
            Ds[2] & (1 << 17) != 0 or
            Ds[2] & (1 << 22) != 0 or
            Cs[2] & (1 << 17) != 0 or
            Cs[2] & (1 << 22) != 0 or
            Bs[2] & (1 << 17) != 0 or
            Bs[2] & (1 << 22) != 0
        ):
            print('fail 21')
            return False
    
    if 22 in sets:
        if (
            As[2] & (1 << 7) != 1 << 7 or
            As[2] & (1 << 10) != 1 << 10 or
            As[2] & (1 << 25) != 0 or
            As[2] & (1 << 13) != Bs[1] & (1 << 13) or
            Ds[2] & (1 << 13) != 0 or
            Ds[2] & (1 << 18) != As[2] & (1 << 18) or
            Ds[2] & (1 << 19) != As[2] & (1 << 19) or
            Ds[2] & (1 << 20) != As[2] & (1 << 20) or
            Ds[2] & (1 << 21) != As[2] & (1 << 21) or
            Ds[2] & (1 << 25) != 1 << 25 or
            Cs[2] & (1 << 12) != Ds[2] & (1 << 12) or
            Cs[2] & (1 << 13) != 0 or
            Cs[2] & (1 << 14) != Ds[2] & (1 << 14) or
            Cs[2] & (1 << 18) != 0 or
            Cs[2] & (1 << 19) != 0 or
            Cs[2] & (1 << 20) != 1 << 20 or
            Cs[2] & (1 << 21) != 0 or
            Bs[2] & (1 << 12) != 1 << 12 or
            Bs[2] & (1 << 13) != 1 << 13 or 
            Bs[2] & (1 << 14) != 0 or
            Bs[2] & (1 << 16) != Cs[2] & (1 << 16) or
            Bs[2] & (1 << 18) != 0 or
            Bs[2] & (1 << 19) != 0 or
            Bs[2] & (1 << 20) != 0 or
            Bs[2] & (1 << 21) != 0
        ):
            print('fail 22')
            return False

    
    if 3 in sets:
        if (
            As[3] & (1 << 12) != 1 << 12 or
            As[3] & (1 << 13) != 1 << 13 or
            As[3] & (1 << 14) != 1 << 14 or
            As[3] & (1 << 16) != 0 or
            As[3] & (1 << 18) != 0 or
            As[3] & (1 << 19) != 0 or
            As[3] & (1 << 20) != 0 or
            As[3] & (1 << 22) != Bs[2] & (1 << 22) or
            As[3] & (1 << 21) != 1 << 21 or
            As[3] & (1 << 25) != Bs[2] & (1 << 25) or
            Ds[3] & (1 << 12) != 1 << 12 or
            Ds[3] & (1 << 13) != 1 << 13 or
            Ds[3] & (1 << 14) != 1 << 14 or
            Ds[3] & (1 << 16) != 0 or
            Ds[3] & (1 << 19) != 0 or
            Ds[3] & (1 << 20) != 1 << 20 or
            Ds[3] & (1 << 21) != 1 << 21 or
            Ds[3] & (1 << 22) != 0 or
            Ds[3] & (1 << 25) != 1 << 25 or
            Ds[3] & (1 << 29) != As[3] & (1 << 29) or
            Cs[3] & (1 << 16) != 1 << 16 or
            Cs[3] & (1 << 19) != 0 or
            Cs[3] & (1 << 20) != 0 or
            Cs[3] & (1 << 21) != 0 or
            Cs[3] & (1 << 22) != 0 or
            Cs[3] & (1 << 25) != 0 or
            Cs[3] & (1 << 29) != 1 << 29 or
            Cs[3] & (1 << 31) != Ds[3] & (1 << 31) or
            Bs[3] & (1 << 19) != 0 or
            Bs[3] & (1 << 20) != 1 << 20 or
            Bs[3] & (1 << 21) != 1 << 21 or
            Bs[3] & (1 << 22) != Cs[3] & (1 << 22) or
            Bs[3] & (1 << 25) != 1 << 25 or
            Bs[3] & (1 << 29) != 0 or
            Bs[3] & (1 << 31) != 0
        ):
            print('fail 3')
            return False
    
    if 4 in sets:
        if (
            As[4] & (1 << 22) != 0 or
            As[4] & (1 << 25) != 0 or
            As[4] & (1 << 26) != Bs[3] & (1 << 26) or
            As[4] & (1 << 28) != Bs[3] & (1 << 28) or
            As[4] & (1 << 29) != 1 << 29 or
            As[4] & (1 << 31) != 0 or
            Ds[4] & (1 << 22) != 0 or
            Ds[4] & (1 << 25) != 0 or
            Ds[4] & (1 << 26) != 1 << 26 or
            Ds[4] & (1 << 28) != 1 << 28 or
            Ds[4] & (1 << 29) != 0 or
            Ds[4] & (1 << 31) != 1 << 31 or
            Cs[4] & (1 << 18) != Ds[4] & (1 << 18) or
            Cs[4] & (1 << 22) != 1 << 22 or
            Cs[4] & (1 << 25) != 1 << 25 or
            Cs[4] & (1 << 26) != 0 or
            Cs[4] & (1 << 28) != 0 or
            Cs[4] & (1 << 29) != 0 or
            Bs[4] & (1 << 18) != 0 or
            Bs[4] & (1 << 25) != 1 << 25 or
            Bs[4] & (1 << 26) != 1 << 26 or
            Bs[4] & (1 << 28) != 1 << 28 or
            Bs[4] & (1 << 29) != 0
        ):
            print('fail 4')
            return False

    if 5 in sets:
        if (
            As[5] & (1 << 18) != Cs[4] & (1 << 18) or
            As[5] & (1 << 25) != 1 << 25 or
            As[5] & (1 << 26) != 0 or
            As[5] & (1 << 28) != 1 << 28 or
            As[5] & (1 << 31) != 1 << 31 or
            Ds[5] & (1 << 18) != As[5] & (1 << 18) or
            Ds[5] & (1 << 25) != Bs[4] & (1 << 25) or
            Ds[5] & (1 << 26) != Bs[4] & (1 << 26) or
            Ds[5] & (1 << 28) != Bs[4] & (1 << 28) or
            Ds[5] & (1 << 31) != Bs[4] & (1 << 31) or
            Cs[5] & (1 << 26) != Ds[5] & (1 << 26) or
            Cs[5] & (1 << 29) != Ds[5] & (1 << 29) or
            Cs[5] & (1 << 31) != Ds[5] & (1 << 31)
        ):
            print('fail 5')
            return False
    return True

def get_m2(m):
    assert(len(m) == 64)
    ms = [unpack('<I', m[i:i+4])[0] for i in range(0,len(m),4)] 
    ms[1] = (ms[1] + (1 << 31)) & mask
    ms[2] = (ms[2] + (1 << 31) - (1 << 28)) & mask
    ms[12] = (ms[12] - (1 << 16)) & mask
    return b''.join(list(map(lambda x: pack('<I', x), ms))) 



if __name__ == '__main__':
    assert(md4(b'adb') == MD4.new(b'adb').digest())
    m = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do '
    assert(md4_ops(m)[0] == md4_no_pad(m))
    i = 0
    t = 0
    while True:
        i += 1
        if (i % 10000 == 0):
            print(f"trials: {i}, successes: {t}")
        m = os.urandom(64)
        m1 = massage(m)
        m2 = get_m2(m1)
        if md4_no_pad(m1) == md4_no_pad(m2):
            t += 1
            assert(md4(m1) == md4(m2))

# 21 conditions: 487283 tries
# 20 conditions: 3696491 tries 
# 19 conditions: 244579 tries
# 18 conditions: 550473 tries
# 17 conditions: 561438 tries
# 16 conditions: 237726 tries
# 13 conditions: 5079 tries