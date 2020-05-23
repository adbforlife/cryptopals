def pkcs_7_padding(block,N=16):
	if N >= 256:
		raise Exception('N is too large.')
	num_remaining = N - len(block) % N
	return block + (chr(num_remaining) * num_remaining).encode('utf-8')

if __name__ == '__main__':
	print(pkcs_7_padding(b'YELLOW SUBMARINE', 20))