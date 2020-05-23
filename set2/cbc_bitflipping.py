from ecb_byte_at_a_time import generate_key
from aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, pad

key = generate_key()
iv = b''

def enc_oracle(m):
	m = b''.join(m.split(b';'))
	m = b''.join(m.split(b'='))
	prefix = b'comment1=cooking%20MCs;userdata='
	suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
	plaintext = prefix + m + suffix
	global iv
	iv = generate_key()
	return aes_cbc_encrypt(plaintext, key, iv)

def dec_oracle(c):
	admin_string =  b';admin=true;'
	m = aes_cbc_decrypt(c, key, iv)
	return m.find(admin_string) >= 0

if __name__ == '__main__':
	test_string = b'AadminAtrue'
	c = list(enc_oracle(test_string))
	c[16] = c[16] ^ ord('A') ^ ord(';')
	c[22] = c[22] ^ ord('A') ^ ord('=')
	c = bytes(c)
	print(dec_oracle(c))
