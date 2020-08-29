from Crypto.Cipher import AES
from cryptools import *
from os import urandom
from itertools import product

# We essentially could not use BLOCK_SIZE = 4 here, since this attack only
# allows 2^(3/4 b) complexity. For 4-byte blocks, we need roughly 2^24 calls
# to hash. This is a little too much for my amusement locally (doable tho)
BLOCK_SIZE = 2
START = b'ADBFORLIFE'[:BLOCK_SIZE]

# Implement custom hash

def padm_with_len(m, l):
    ml = l * 8
    m += b'\x80'
    m += bytes((56 - len(m)) % 64)
    m += ml.to_bytes(8, byteorder='big')
    return m

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


# Let's get a commitment going

def cut_half(hashes):
    assert(len(hashes) % 2 == 0)
    res_h = []
    res_blocks = []
    tmp_hashes = []
    i = 0
    for i in range(0, len(hashes), 2):
        group = hashes[i:i+2]
        guesses = {}
        for _ in range(2**8):
            guess = urandom(BLOCK_SIZE)
            guess_h = md(guess, group[0], combine)
            guesses[guess_h] = guess
        while True:
            guess = urandom(BLOCK_SIZE)
            guess_h = md(guess, group[1], combine)
            if guess_h in guesses:
                res_h.append(guess_h)
                res_blocks.append(guesses[guess_h])
                res_blocks.append(guess)
                break
    assert(len(res_h) == len(hashes) // 2)
    assert(len(res_blocks) == len(hashes))
    return res_blocks, res_h

# Initialize 2^k hash states
def init(k):
    guesses = {}
    while len(guesses) < 2**k:
        guess = urandom(BLOCK_SIZE)
        guesses[guess] = md(guess, START, combine)
    items = list(guesses.items())
    blocks = list(map(lambda x: x[0], items))
    hashes = list(map(lambda x: x[1], items))
    return blocks, hashes

# Expand to 2**k items
def expand(items, k):
    return [items[i // (2**k // len(items))] for i in range(2**k)]

# Return 2**k hash states, 2**k same-length messages, and final hash
def get_collisions(k):
    init_hashes = init(k)[1]
    curr_hashes = init_hashes.copy()
    assert(len(curr_hashes) == 2**k)
    mid_blocks = []
    mid_hashes = []
    for i in range(k):
        blocks, hashes = cut_half(curr_hashes)
        print(f'Done with iteration {i+1} out of {k}')
        mid_blocks.append(blocks)
        mid_hashes.append(hashes)
        curr_hashes = hashes
    assert(len(curr_hashes) == 1)
    assert(len(mid_blocks) == k)
    assert(len(mid_hashes) == k)
    final_hash = curr_hashes[0]
    for i in range(len(mid_blocks)):
        mid_blocks[i] = expand(mid_blocks[i], k)
    final_messages = []
    for i in range(len(mid_blocks[0])):
        final_messages.append(b''.join(list(map(lambda x: x[i], mid_blocks))))
    assert(md(final_messages[3], init_hashes[3], combine) == final_hash)
    assert(md(final_messages[10], init_hashes[10], combine) == final_hash)
    return init_hashes, final_messages, final_hash

# Return 2**k hash states, 2**k same-length messages with pad, prefix length, and final hash
def get_commitment(k):
    init_hashes, final_messages, final_hash = get_collisions(k)
    message = final_messages[0]
    init_state = init_hashes[0]
    print(f'Junk message len is {len(message)}')
    new_m = padm_with_len(message, len(message) + 64) # Block size for SHA1
    res_hash = md(new_m, init_state, combine)
    return init_hashes, final_messages, 64, res_hash

init_hashes, final_messages, prefix_len, res_hash = get_commitment(4)
print(f'My commitment hash is {res_hash}')

MSG = b'ADBFORLIFE' * 6 + b'BB'
curr_state = md(MSG, START, combine)
hash_set = set(init_hashes)
while True:
    guess = urandom(BLOCK_SIZE)
    guess_h = md(guess, curr_state, combine)
    if guess_h in hash_set:
        break
idx = init_hashes.index(guess_h)
assert(idx >= 0)

forge = MSG + guess + final_messages[idx]
print(f'My forged message is {forge}')
assert(my_hash(forge) == res_hash)
print(f'The hash for that is {my_hash(forge)}')


    
