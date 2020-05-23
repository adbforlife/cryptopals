from base64 import b64encode
from binascii import unhexlify
def hex_to_base64(hex_string):
    return b64encode(unhexlify(hex_string))

'''
I'm killing your brain like a poisonous mushroom
'''
if __name__ == '__main__':
	print(hex_to_base64(b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))