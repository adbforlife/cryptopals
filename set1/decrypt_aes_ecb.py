from Crypto.Cipher import AES
from base64 import b64decode

'''
Play That Funky Music
'''
if __name__ == '__main__':
	ciphertext = ''
	with open('set1/7.txt', 'r') as f:
		ciphertext = b64decode(f.read())
	key = b'YELLOW SUBMARINE'
	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = cipher.decrypt(ciphertext)
	print(plaintext)