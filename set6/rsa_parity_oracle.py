from Crypto.Util.number import getPrime
from base64 import *
from cryptools import *
import sys

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 65537
lam = (p-1) * (q-1)
d = pow(e,-1,lam)

def is_pt_odd(c):
    return pow(c,d,n) % 2

m = b'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
m = b64decode(m)
m = unbytify(m)
assert(m < n)
c = pow(m,e,n)

num = 1
denom = 2
mult = 1
odds = []
for i in range(2100):
    num *= 2
    denom *= 2
    mult *= 2
    is_odd = is_pt_odd(c * pow(mult,e,n) % n)
    if is_odd:
        num += 1
    else:
        num -= 1
    guess = n * num // denom
    assert('\n' not in str(bytify(guess)))
    print(bytify(guess))

print(bytify(guess))
print(bytify(guess + 1))
print(bytify(guess - 1))
assert(abs(guess-m) <= 1)
