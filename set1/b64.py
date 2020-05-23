b64_symbols = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
b64_table = {b64_symbols[i] : i for i in range(len(b64_symbols))}

def b64_encode(b_arr):
    # Padding zero bytes first
    padlen = (3 - (len(b_arr) % 3)) % 3
    b_arr += bytes(padlen)
    assert(len(b_arr) % 3 == 0)

    # This is the result we append to
    res_arr = bytearray()

    # For each of 3 bytes, we encode to 4 bytes
    for i in range(len(b_arr) // 3):
        b1 = b_arr[i * 3]
        b2 = b_arr[i * 3 + 1]
        b3 = b_arr[i * 3 + 2]
        assert(b1 < 256 and b2 < 256 and b3 < 256)
        res_arr.append(b64_symbols[b1 >> 2])
        res_arr.append(b64_symbols[((b1 & 0x3) << 4) | (b2 >> 4)])
        res_arr.append(b64_symbols[((b2 & 0xf) << 2) | (b3 >> 6)])
        res_arr.append(b64_symbols[b3 & 0x3f])
    
    return res_arr

def b64_decode(b_arr):
    assert(len(b_arr) % 4 == 0)
    res_arr = bytearray()

    # For each of 4 bytes, we decode to 3 bytes
    for i in range(len(b_arr) // 4):
        idx1 = b64_table[b_arr[i * 4]]
        idx2 = b64_table[b_arr[i * 4 + 1]]
        idx3 = b64_table[b_arr[i * 4 + 2]]
        idx4 = b64_table[b_arr[i * 4 + 3]]
        assert(idx1 < 64 and idx2 < 64 and idx3 < 64 and idx4 < 64)
        res_arr.append((idx1 << 2) | ((idx2 & 0x30) >> 4))
        res_arr.append(((idx2 & 0xf) << 4) | ((idx3 & 0x3c) >> 2))
        res_arr.append(((idx3 & 0x3) << 6) | idx4)
    
    return res_arr

if __name__ == '__main__':
    print(b64_decode(b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'))
    print(b64_encode(b'I\'m killing your brain like a poisonous mushroom'))
    