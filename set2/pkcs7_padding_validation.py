def unpad(data, block_size=16, style='pkcs7'):
	assert(block_size < 256)
	assert(style == 'pkcs7')
	assert(not (len(data) % block_size))
	last_byte = data[-1]
	assert(last_byte <= block_size)
	return data[:-last_byte]

def unsafe_unpad(data, block_size=16, style='pkcs7'):
	assert(block_size < 256)
	assert(style == 'pkcs7')
	assert(not (len(data) % block_size))
	last_byte = data[-1]
	assert(last_byte <= block_size)
	for byte in data[-last_byte:]:
		assert(last_byte == byte)
	return data[:-last_byte]

if __name__ == '__main__':
	print(unsafe_unpad(b'ICE ICE BABY\x04\x04\x04\x04'))
	print(unsafe_unpad(b'ICE ICE BABY\x05\x05\x05\x05'))