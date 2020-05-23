from random import randint
from aes_cbc import aes_cbc_encrypt, aes_ecb_encrypt
from base64 import b64decode

def pad(data, block_size=16, style='pkcs7'):
	assert block_size < 256
	assert style == 'pkcs7'
	num_remaining = block_size - len(data) % block_size
	return data + (chr(num_remaining) * num_remaining).encode('utf-8')

def generate_key(key_size=16):
	return bytes([randint(0,255) for _ in range(key_size)])

key = generate_key()

def enc_oracle(m):
	suffix = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK'
	plaintext = m + b64decode(suffix)
	return aes_ecb_encrypt(plaintext, key)

'''
Rollin' in my 5.0
'''
if __name__ == '__main__':
	total_len = len(enc_oracle(b''))
	print(total_len)
	correct_bytes = b''
	for j in range(16):
		correct_c = enc_oracle(b'A' * (15-j))[:16]
		for i in range(256):
			test_m = b'A' * (15-j) + correct_bytes + bytes([i])
			test_c = enc_oracle(test_m)[:16]
			if test_c == correct_c:
				correct_bytes += bytes([i])
				break

	for i in range(16,total_len):
		pad_len = 15 - i%16
		expected_c = enc_oracle(b'A' * pad_len)[i+pad_len-15: i+pad_len+1]
		for j in range(256):
			test_m = correct_bytes[-15:] + bytes([j])
			test_c = enc_oracle(test_m)[:16]
			if test_c == expected_c:
				correct_bytes += bytes([j])
				break
	print(correct_bytes)
