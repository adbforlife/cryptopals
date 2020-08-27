from cryptools import *
from zlib import compress
from Crypto.Cipher import AES
from os import urandom

key = urandom(16)

def format_req(m):
    formatted = (f'POST / HTTP/1.1\n'
    f'Host: hapless.com\n'
    f'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n'
    f'Content-Length: {len(m.decode())}\n\n'
    f'{m.decode()}')
    return formatted.encode()

def enc_stream(m):
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.encrypt(m)

def enc_block(m):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(m)

def oracle(m):
    return enc_stream(compress(format_req(m)))

def oracle2(m):
    return enc_block(pad(compress(format_req(m))))

res = b'sessionid='
def guess_char():
    min_len = 200
    min_ij = (0,0)
    for i in range(32, 128):
        for j in range(32, 128):
            guess = res + bytes([i,j])
            junk = oracle(guess)
            if len(junk) < min_len:
                min_len = len(junk)
                min_ij = (i,j)
    return min_ij[0]

for _ in range(44):
    c = guess_char()
    res += bytes([c])
    print(res, len(oracle(res)))


res = b'ADB;sessionid='
def guess_char2():
    min_len = 200
    min_ij = (0,0)
    for i in range(10, 128):
        for j in range(10, 128):
            guess = res + bytes([i,j])
            junk = oracle2(guess)
            if len(junk) < min_len:
                min_len = len(junk)
                min_ij = (i,j)
    return min_ij[0]

for _ in range(44):
    c = guess_char2()
    res += bytes([c])
    print(res, len(oracle2(res)))
