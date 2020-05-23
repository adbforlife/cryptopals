from Crypto.Cipher import AES
from functools import reduce
from base64 import b64decode

def pad(data, block_size=16, style='pkcs7'):
	assert block_size < 256
	assert style == 'pkcs7'
	num_remaining = block_size - len(data) % block_size
	return data + (chr(num_remaining) * num_remaining).encode('utf-8')

def unpad(data, block_size=16, style='pkcs7'):
	assert(block_size < 256)
	assert(style == 'pkcs7')
	assert(not (len(data) % block_size))
	last_byte = data[-1]
	assert(last_byte <= block_size)
	return data[:-last_byte]

def xor(b1, b2):
	return bytes([b1[i]^b2[i] for i in range(len(b1))])

def aes_ecb_encrypt(plaintext, key, padding=True):
	cipher = AES.new(key, AES.MODE_ECB)
	if padding:
		plaintext = pad(plaintext)
	return cipher.encrypt(plaintext)

def aes_ecb_decrypt(ciphertext, key, unpadding=True):
	cipher = AES.new(key, AES.MODE_ECB)
	res = cipher.decrypt(ciphertext)
	if unpadding:
		return unpad(res)
	else:
		return res

def aes_cbc_encrypt(plaintext, key, iv):
	cipher = AES.new(key, AES.MODE_ECB)
	m = pad(plaintext)
	blocks = [m[i:i+16] for i in range(0, len(m), 16)]
	c_blocks = []
	for block in blocks:	
		iv = cipher.encrypt(xor(block, iv))
		c_blocks.append(iv)
	return reduce(lambda x,y: x+y, c_blocks)

def aes_cbc_decrypt(ciphertext, key, iv):
	c = ciphertext
	cipher = AES.new(key, AES.MODE_ECB)
	c_blocks = [c[i:i+16] for i in range(0, len(c), 16)][::-1]
	c_blocks.append(iv)
	m_blocks = []
	for i in range(len(c_blocks) - 1):
		c_block = c_blocks[i]
		m_blocks.append(xor(cipher.decrypt(c_block), c_blocks[i+1]))
	return reduce(lambda x,y: x+y, m_blocks[::-1])

'''
Play That Funky Music
'''
if __name__ == '__main__':
	ciphertext = ''
	with open('set2/10.txt', 'r') as f:
		ciphertext = b64decode(f.read())
	m = aes_cbc_decrypt(ciphertext, b'YELLOW SUBMARINE', b'\x00'*16)
	m = unpad(m)
	print(m)
	c_new = aes_cbc_encrypt(m, b'YELLOW SUBMARINE', b'\x00'*16)
	print(c_new==ciphertext)


