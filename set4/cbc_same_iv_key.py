import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from cryptotools import *

key = generate_key()
iv = key

def enc_oracle(m):
	m = b''.join(m.split(b';'))
	m = b''.join(m.split(b'='))
	prefix = b'comment1=cooking%20MCs;userdata='
	suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
	plaintext = prefix + m + suffix
	return aes_cbc_encrypt(plaintext, key, iv)

def dec_oracle(c):
	admin_string =  b';admin=true;'
	m = aes_cbc_decrypt(c, key, iv)
	return m

if __name__ == '__main__':
	test_bytes = bytes(16)
	c = enc_oracle(test_bytes)
	c1 = c[:16]
	c2 = bytes(16)
	m = dec_oracle(c1 + c2 + c1)
	print(xor(m[:16], m[32:48]) == key)
