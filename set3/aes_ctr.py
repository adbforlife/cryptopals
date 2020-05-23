from Crypto.Cipher import AES
from base64 import b64decode
import sys

sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from crypto.cipher import (
	xor
)

def aes_ctr_encrypt(plaintext, key, nonce=b'\x00\x00\x00\x00\x00\x00\x00\x00', byteorder='little'):
	cipher = AES.new(key, AES.MODE_ECB)
	m_length = len(plaintext)
	counter = 0
	keystream = b''
	while len(keystream) < m_length:
		keystream += cipher.encrypt(nonce + counter.to_bytes(8, byteorder=byteorder))
		counter += 1
	return xor(plaintext, keystream[:m_length])

def aes_ctr_decrypt(ciphertext, key, nonce=b'\x00\x00\x00\x00\x00\x00\x00\x00', byteorder='little'):
	return aes_ctr_encrypt(ciphertext, key, nonce, byteorder)

if __name__ == '__main__':
	ciphertext = b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
	key = b'YELLOW SUBMARINE'
	print(aes_ctr_decrypt(ciphertext, key))