import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from crypto.cipher import (
	pad, 
	unpad, 
	generate_key, 
	aes_cbc_encrypt, 
	aes_cbc_decrypt
)
from crypto.attack import cbc_padding_oracle
from random import randint
from base64 import b64decode
from statistics import mode

key = generate_key()

candidates = list(map(lambda x: b64decode(x), [
b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]))

def enc_oracle():
	m = candidates[randint(0,9)]
	iv = generate_key()
	c = aes_cbc_encrypt(m, key, iv)
	return (c, iv)

def is_padding_valid(c, iv, block_size=16, style='pkcs7'):
	data = aes_cbc_decrypt(c, key, iv)
	if block_size >= 256:
		return False
	if style != 'pkcs7':
		return False
	if len(data) % block_size:
		return False
	last_byte = data[-1]
	if last_byte > block_size:
		return False
	for byte in data[-last_byte:]:
		if last_byte != byte:
			return False
	return True

# Not 100% correct since \x02\x02 is also valid
'''def cbc_padding_oracle(c, iv, valid_checker):
	c_blocks = [iv] + [c[i:i+16] for i in range(0,len(c),16)]
	m = b''
	for i in range(1, len(c_blocks)):
		c_block = c_blocks[i]
		correct_test_block = [0 for _ in range(16)]

		# Give multiple tries to increase likelihood
		last_byte_candidates = []
		for j in range(5):
			test_block = generate_key()
			while not is_padding_valid(c_block, test_block):
				test_block = generate_key()
			last_byte_candidates.append(test_block[15] ^ 1)
		correct_test_block[15] = mode(last_byte_candidates)

		for j in range(1,16):
			xored_correct_test_block = list(map(lambda x: x ^ (j+1), correct_test_block))
			test_block = generate_key(16-j) + bytes(xored_correct_test_block[16-j:])
			while not is_padding_valid(c_block, test_block):
				test_block = generate_key(16-j) + bytes(xored_correct_test_block[16-j:])
			correct_test_block[15-j] = test_block[15-j] ^ (j+1)
		m_block = bytes([c_blocks[i-1][k] ^ correct_test_block[k] for k in range(16)])
		m += m_block
	return m'''

if __name__ == '__main__':
	(c,iv) = enc_oracle()
	print(cbc_padding_oracle(c, iv, is_padding_valid))









