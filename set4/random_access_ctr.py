import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from cryptotools import *
from base64 import b64decode

key = generate_key()

def edit(ciphertext, key, offset, newtext):
	m = aes_ctr_decrypt(ciphertext, key)
	m = m[:offset] + newtext
	return aes_ctr_encrypt(m, key)

if __name__ == '__main__':
	m = b''
	with open('set4/25.txt', 'r') as f:
		m = aes_ecb_decrypt(b64decode(f.read().rstrip()), b"YELLOW SUBMARINE")
	c = aes_ctr_encrypt(m, key)
	print(xor(edit(c, key, 0, bytes(len(c))), c))

	