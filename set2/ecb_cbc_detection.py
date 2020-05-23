from random import randint
from aes_cbc import aes_cbc_encrypt, aes_ecb_encrypt

def generate_key(key_size=16):
	return bytes([randint(0,255) for _ in range(key_size)])

def enc_oracle(m):
	prefix = bytes([randint(0,255) for _ in range(randint(5,10))])
	suffix = bytes([randint(0,255) for _ in range(randint(5,10))])
	plaintext = prefix + m + suffix
	if (randint(0,1)):
		return aes_ecb_encrypt(m, generate_key())
	else:
		return aes_cbc_encrypt(m, generate_key(), generate_key())

if __name__ == '__main__':
	res = enc_oracle(b'A' * 64)
	if res[16:32] == res[32:48]:
		print('ECB')
	else:
		print('CBC')