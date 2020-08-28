from Crypto.Cipher import AES
from cryptools import *
from os import urandom
from itertools import product

BLOCK_SIZE = 4
START = b'ADBFORLIFE'[:BLOCK_SIZE]

# Implement custom hash

def padm(m):
    ml = len(m) * 8
    m += b'\x80'
    m += bytes((56 - len(m)) % 64)
    m += ml.to_bytes(8, byteorder='big')
    return m

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

def my_hash(m):
    return md(padm(m), START, combine)

def get_my_hash_map(m):
    h_to_len = {}
    curr = START
    assert(len(m) % BLOCK_SIZE == 0)
    for i in range(0, len(m), BLOCK_SIZE):
        block = m[i:i+BLOCK_SIZE]
        curr = combine(block, curr)
        h_to_len[curr] = i//BLOCK_SIZE + 1
    assert(curr == md(m, START, combine))
    return h_to_len


# Breaking second preimage on long message

MSG = urandom(2**16 * BLOCK_SIZE)
DESIRED_H = my_hash(MSG)

# Collision between one-block m and 2^(k-1) + 1 block m', with start state h.
def get_collide(h, k):
    guesses = {}
    dummy_blocks = urandom(2**(k-1) * BLOCK_SIZE)
    new_h = md(dummy_blocks, h, combine)
    for _ in range(2**16):
        guess = urandom(BLOCK_SIZE)
        guess_h = md(guess, h, combine)
        guesses[guess_h] = guess
    while True:
        guess = urandom(BLOCK_SIZE)
        guess_h = md(guess, new_h, combine)
        if guess_h in guesses:
            assert(md(guesses[guess_h], h, combine) == md(dummy_blocks + guess, h, combine))
            return (guesses[guess_h], dummy_blocks + guess)

# Get expandable message in [k, k + 2^k - 1]
def get_collides(k):
    curr = START
    res = []
    for i in range(1, k+1):
        x,y = get_collide(curr, i)
        res.append((x,y))
        assert(md(x, curr, combine) == md(y, curr, combine))
        curr = md(x, curr, combine)
        print(f'Done with iteration {i} out of {k}')
    return [b''.join(a) for a in product(*res)]

len_to_m = {}
for m in get_collides(16):
    len_to_m[len(m)//BLOCK_SIZE] = m
print(f'We have {len(len_to_m)} different messages with same hash')

final_state = md(list(len_to_m.values())[0], START, combine)
assert(final_state == md(list(len_to_m.values())[1], START, combine))

hmap = get_my_hash_map(MSG)
print(f'We have {len(hmap)} different states for hash of MSG')

while True:
    guess = urandom(BLOCK_SIZE)
    guess_h = md(guess, final_state, combine)
    if guess_h in hmap:
        length = hmap[guess_h]
        assert(length >= 16 and length <= 16 + 2**16 - 1)
        prefix = len_to_m[length - 1]
        bridge = guess
        res = prefix + bridge + MSG[length*BLOCK_SIZE:]
        assert(len(res) == len(MSG))
        assert(my_hash(res) == my_hash(MSG))
        print(f'We found second image')
        print(f'MSG == SECOND_MSG = {MSG == SECOND_MSG}')
        print(f'hash(MSG) = {my_hash(MSG)}')
        print(f'hash(SECOND_MSG) = {my_hash(res)}')
        exit(0)





