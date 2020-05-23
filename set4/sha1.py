import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from cryptools import *

# only bytes no bits
'''
def sha1(m, digest='hex'):
	# 32 bit word, rotate by num bits
	def rotl(word, num):
		return ((word << num) | (word >> (32-num))) & 0xFFFFFFFF

	if isinstance(m, str):
		m = m.encode('utf-8')

	h0 = 0x67452301
	h1 = 0xEFCDAB89
	h2 = 0x98BADCFE
	h3 = 0x10325476
	h4 = 0xC3D2E1F0

	ml = len(m) * 8
	m += b'\x80'
	m += bytes((56 - len(m)) % 64)
	m += ml.to_bytes(8, byteorder='big')
	
	chunks = [m[i:i+64] for i in range(0,len(m),64)]
	for chunk in chunks:
		w = [int.from_bytes(chunk[i:i+4],byteorder='big')
			for i in range(0,len(chunk),4)]
		for i in range(16,80):
			new_word = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
			new_word = rotl(new_word, 1)
			w.append(new_word)

		a = h0
		b = h1
		c = h2
		d = h3
		e = h4

		for i in range(80):
			if i < 20:
				f = (b & c) | ((b ^ 0xFFFFFFFF) & d)
				k = 0x5A827999
			elif i < 40:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif i < 60:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			else:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			tmp = (rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
			e = d
			d = c
			c = rotl(b, 30)
			b = a
			a = tmp

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
		h0 &= 0xFFFFFFFF
		h1 &= 0xFFFFFFFF
		h2 &= 0xFFFFFFFF
		h3 &= 0xFFFFFFFF
		h4 &= 0xFFFFFFFF

	hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
	
	if digest == 'hex':
		hh = format(hh, 'x')
	elif digest == 'bytes':
		hh = hh.to_bytes(20, byteorder='big')
	
	return hh
'''

def sha1_keyed_mac(message, key):
	return sha1(key + message)

if __name__ == '__main__':
	sha1('', digest='bytes')
	sha1_keyed_mac('adb', 'adb')

