import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from cryptotools import *

key = generate_key()

def enc_oracle(m):
	m = b''.join(m.split(b';'))
	m = b''.join(m.split(b'='))
	prefix = b'comment1=cooking%20MCs;userdata='
	suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
	plaintext = prefix + m + suffix
	return aes_ctr_encrypt(plaintext, key)

def dec_oracle(c):
	admin_string =  b';admin=true;'
	m = aes_ctr_decrypt(c, key)
	return m.find(admin_string) >= 0

if __name__ == '__main__':
	test_string = b'AadminAtrue'
	c = list(enc_oracle(test_string))
	c[32] = c[32] ^ ord('A') ^ ord(';')
	c[38] = c[38] ^ ord('A') ^ ord('=')
	c = bytes(c)
	print(dec_oracle(c))

