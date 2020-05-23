def fixed_xor(hex_string1, hex_string2):
	return format(int(hex_string1, 16) ^ int(hex_string2, 16), 'x').encode('utf-8')

'''
the kid don't play
'''
if __name__ == '__main__':
	print(fixed_xor(b'1c0111001f010100061a024b53535009181c', b'686974207468652062756c6c277320657965'))