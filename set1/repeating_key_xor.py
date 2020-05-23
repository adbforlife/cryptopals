from binascii import hexlify

def repeating_key_xor(byte_string, byte_key):
	key_length = len(byte_key)
	result = ''
	for i in range(len(byte_string)):
		result += chr(byte_string[i] ^ byte_key[i % key_length])
	return result.encode('utf-8')

'''
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
'''
if __name__ == '__main__':
	encrypted = repeating_key_xor(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b'ICE')
	print(hexlify(encrypted))