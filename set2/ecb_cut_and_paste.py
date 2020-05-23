from aes_cbc import aes_ecb_encrypt, aes_ecb_decrypt
from ecb_byte_at_a_time import generate_key

key = generate_key()

def parseKV(string):
	pairs = string.split(b'&')
	result = {}
	for pair in pairs:
		parts = pair.split(b'=')
		assert len(parts) == 2
		result.update({parts[0].decode('utf-8'): parts[1].decode('utf-8')})
	return result

def profile_for(string):
	assert string.find(b'=') < 0
	assert string.find(b'&') < 0
	encoded = b'email=' + string + b'&uid=10&role=user'
	return aes_ecb_encrypt(encoded, key)

def decrypt(string):
	return aes_ecb_decrypt(string, key)

if __name__ == '__main__':
	print(parseKV(b'foo=bar&baz=qux&zap=zazzle'))
	c1 = profile_for(b'A' * 10 + b'admin' + b'\x0b' * 11)
	c2 = profile_for(b'A' * 13)
	c3 = c2[:32] + c1[16:32]
	print(decrypt(c3))