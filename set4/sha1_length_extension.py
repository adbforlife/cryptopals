import sys
sys.path.append('/Users/ADB/Desktop/ /cryptopals')
from cryptools import sha1_pad

def sha1(m, digest='hex',h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0,length=-1):
	# 32 bit word, rotate by num bits
	def rotl(word, num):
		return ((word << num) | (word >> (32-num))) & 0xFFFFFFFF

	if isinstance(m, str):
		m = m.encode('utf-8')

	ml = len(m) * 8
	m += b'\x80'
	m += bytes((56 - len(m)) % 64)
	if length < 0:
		length = ml
	m += length.to_bytes(8, byteorder='big')
	print(len(m))
	
	chunks = [m[i:i+64] for i in range(0,len(m),64)]
	print(chunks)
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

if __name__ == '__main__':
	key = b'secret'
	m = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	hashed = sha1(key + m, digest='bytes')
	segs = [hashed[i:i+4] for i in range(0, 20, 4)]
	segs = list(map(lambda x: int.from_bytes(x, byteorder='big'), segs))
	print(hashed)
	print(segs)
	print(sha1_pad(key+m) + b';admin=true')
	print(sha1(sha1_pad(key+m) + b';admin=true'))
	print(sha1(b';admin=true', digest='hex', h0=segs[0], h1=segs[1], h2=segs[2], h3=segs[3], h4=segs[4], length=139*8))





