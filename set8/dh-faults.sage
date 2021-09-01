from random import randint
# secp128r1
p = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC
b = 0xE87579C11079F43DD824993C2CEE5ED3
E = EllipticCurve(GF(p), [a,b])
G = E(0x161FF7528B899B2D0C28607CA52C5B86, 0xCF5AC8395BAFEB13C02DA292DDED7A83)
q = 0xFFFFFFFE0000000075A30D1B9038A115
assert(q == E.order())
f = 1009

def add(A, B):
    return A + B

def faultyadd(A, B):
    if int(A[0] * B[0]) % f == 0:
        raise Exception("baba")
    return A + B

def ladder(Q, k, add):
    R = Q
    i = 0
    for b in bin(k)[3:]:
        i += 1
        try:
            R = add(R, R)
        except:
            raise Exception(-1)
        try:
            if b == '1':
                R = add(R, Q)
        except:
            raise Exception(i)
    return R

assert(ladder(G, 15213, add) == G * 15213)
while True:
    d = randint(2, q)
    if d.bit_length() == 128:
        break

def oracle(Q):
    try:
        ladder(Q, d, faultyadd)
        return True
    except:
        return False

ladder(G, 15213, faultyadd)
kbs = [1] + [0] * 127
def geti(i):
    kbsi = kbs[:i] + [1] + [0] * (127 - i)
    k = int(''.join(list(map(str, kbsi))), 2)
    while True:
        Q = G * randint(2, q)
        try:
            ladder(Q, k, faultyadd)
        except Exception as e:
            step = int(str(e))
            if step == i:
                if oracle(Q):
                    return 0
                else:
                    return 1

print(bin(d))
for i in range(1, 128):
    for _ in range(5):
        res = geti(i)
        if res == 0:
            break
    kbs[i] = res
    print(i, res)
print(kbs)
