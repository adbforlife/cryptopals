from aes_cbc import aes_ecb_encrypt, aes_ecb_decrypt
from ecb_cbc_detection import generate_key
from random import randint
from base64 import b64decode

key = generate_key()

def enc_oracle(m):
	prefix = bytes([randint(0,255) for _ in range(randint(0,255))])
	suffix = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK'
	plaintext = prefix + m + b64decode(suffix)
	return aes_ecb_encrypt(plaintext, key)

def try_till_aligned(test_m, segment):
	while True:
		c = enc_oracle(test_m)
		if segment in c:
			return c
	return b''

if __name__ == '__main__':
	c1 = enc_oracle(b'A' * 100)
	c2 = b''
	total_len = 0
	for i in range(0, len(c1)-16, 16):
		if c1[i:i+16] == c1[i+16:i+32]:
			c2 = c1[i:i+16]
			total_len = len(c1) - i
			break
	correct_bytes = b'B' * 15
	for i in range(total_len):
		pad_len = (14-len(correct_bytes)) % 16
		correct_c = try_till_aligned(b'A' * 16 + b'B' * pad_len, c2)
		match_index = correct_c.index(c2) + 16 + (len(correct_bytes)-15) // 16 * 16
		correct_seg = correct_c[match_index: match_index+16]
		for j in range(255):
			test_m = b'A' * 16 + correct_bytes[-15:] + bytes([j])
			test_c = try_till_aligned(test_m, c2)
			match_index2 = test_c.index(c2) + 16
			test_seg = test_c[match_index2: match_index2+16]
			if test_seg == correct_seg:
				correct_bytes += bytes([j])
				print(correct_bytes)
				break
	print(correct_bytes[15:])

