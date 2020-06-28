from urllib.request import urlopen
from urllib.parse import urlencode
from urllib.error import URLError, HTTPError
from contextlib import closing
from binascii import hexlify
from time import time
from numpy import argmax

def time_for_sig(sig):
    f = b'flag'
    dat = urlencode({'file': f, 'sig': hexlify(sig)}).encode()
    
    start = time()
    try:
        with closing(urlopen(f'http://localhost:{PORT}/login', dat)) as f:
            print(f.read())
    except HTTPError:
        pass
    end = time()
    return end - start

def get_next_byte(sig):
    assert(len(sig) < 20)
    ts = [0 for _ in range(256)]
    for i in range(256):
        guess = sig + bytes([i]) + bytes([0 for _ in range(19 - len(sig))])
        ts[i] = time_for_sig(guess)
    return argmax(ts)


PORT = 15213
sig = b''
for _ in range(20):
    b = get_next_byte(sig)
    sig += bytes([b])
    print(sig)




