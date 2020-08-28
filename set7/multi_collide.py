from Crypto.Cipher import AES
from cryptools import *
from os import urandom
from itertools import product

BLOCK_SIZE = 4
START = b'ADBFORLIFE'[:BLOCK_SIZE]
START2 = b'FRANKIWI'[:BLOCK_SIZE]

def padm(m):
    return m + bytes((BLOCK_SIZE - len(m) % BLOCK_SIZE) % BLOCK_SIZE)

def combine(m, h):
    key = pad(h)
    cipher = AES.new(key, AES.MODE_CTR, nonce=bytes(8))
    return cipher.encrypt(m)

def md(m, h, c):
    assert(len(m) % BLOCK_SIZE == 0) 
    for i in range(0, len(m), BLOCK_SIZE):
        block = m[i:i+BLOCK_SIZE]
        h = c(block, h)
    return h

def hash1(m):
    return md(padm(m), START, combine)

def hash2(m):
    return md(padm(m), START2, combine)

def big_hash(m):
    return hash1(m) + hash2(m)

def get_collide(h):
    guesses = {}
    while True:
        guess = urandom(BLOCK_SIZE * BLOCK_SIZE)
        guess_h = md(guess, h, combine)
        if guess_h in guesses and guesses[guess_h] != guess:
            return (guess, guesses[guess_h])
        else:
            guesses[guess_h] = guess

def get_collides(n):
    curr = START
    res = []
    for i in range(n):
        x,y = get_collide(curr)
        res.append((x,y))
        curr = md(x, curr, combine)
        print(f'Done with iteration {i+1} out of {n}')
    return product(*res)

collides = get_collides(20)
guesses = {}
for a in collides:
    guess = b''.join(a)
    guess_h = hash2(guess)
    if guess_h in guesses and guesses[guess_h] != guess:
        print(f'Found collision after {len(guesses)} hashes')
        print(f'x = {guess}')
        print(f'y = {guesses[guess_h]}')
        print(f'hash(x) = {big_hash(guess)}')
        print(f'hash(y) = {big_hash(guesses[guess_h])}')
        exit(0)
    else:
        guesses[guess_h] = guess
print('Did not find collision')

