import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from cryptotools import *
import time
from Crypto.Cipher import AES

key = generate_key()

start = time.time()
for _ in range(100000):
	aes_ecb_encrypt(b'AAAABBBBCCCCDDDD', key)
end = time.time()
print('Abstracted: {}'.format(end-start))

start = time.time()
cipher = AES.new(key, mode=AES.MODE_ECB)
for _ in range(100000):
	cipher.encrypt(b'AAAABBBBCCCCDDDD')
end = time.time()
print('Normal: {}'.format(end-start))

