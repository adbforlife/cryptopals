def count_reps(ciphertext):
	distinct_blocks = []
	count = 0
	for i in range(len(ciphertext) // 16):
		block = ciphertext[i*16:(i+1)*16+1]
		if block in distinct_blocks:
			count += 1
		else:
			distinct_blocks.append(block)
	return count
'''
d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a
'''
if __name__ == '__main__':
	ciphertexts = []
	with open('set1/8.txt', 'r') as f:
		ciphertexts = list(map(
			lambda x: x.rstrip().encode('utf-8'), f.readlines()))
	c_with_counts = list(map(lambda x: (x, count_reps(x)), ciphertexts))
	c_with_counts.sort(key=lambda x: x[1], reverse=True)
	print(c_with_counts[0])