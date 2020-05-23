import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from cryptotools import *

from base64 import b64decode

key = generate_key()

# Doing this by hand in an unsystematic way is worse than solving repeated key
# xors, which we use here.
if __name__ == '__main__':
	ms = []
	with open('set3/19.txt', 'r') as f:
		ms = list(map(lambda x: b64decode(x.rstrip()), f.readlines()))
	cs = list(map(lambda x: aes_ctr_encrypt(x, key), ms))
	min_len = min(list(map(lambda x: len(x), cs)))
	cs1 = list(map(lambda x: x[:min_len], cs))
	print(len(b''.join(cs1)))
	key = repeating_xor_guess_key(b''.join(cs1), len(cs1[0]))
	print(len(cs1[0]))
	print(len(key))
	print(repeating_xor(b''.join(cs1), key))
