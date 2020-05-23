from single_byte_xor import single_byte_xor_exlude_nonprintables

def detect_single_byte_xors(hex_strings):
	possibles = []
	for hex_string in hex_strings:
		possibles += single_byte_xor_exlude_nonprintables(hex_string)
	possibles.sort(key=lambda candidate: candidate[1], reverse=True)
	return possibles

'''
Now that the party is jumping\n
'''
if __name__ == '__main__':
	hex_strings = []
	with open('set1/4.txt', 'r') as f:
		hex_strings = list(map(
			lambda string: string.rstrip().encode('utf-8'), f.readlines()))
	possibles = detect_single_byte_xors(hex_strings)
	for possible in possibles:
		print(possible)