from cryptools import *
import socketserver
from Crypto.Util.number import getPrime
from random import randint
import gmpy2

MODULUS_BITS = 1024
PORT = 15213

def pkcs1_pad(m):
    bytelen = MODULUS_BITS // 8
    assert(len(m) <= bytelen - 11)
    num_rands = bytelen - 3 - len(m)
    rand_bytes = bytes([randint(1, 255) for _ in range(num_rands)])
    res = b'\x00\x02' + rand_bytes + b'\x00' + m
    assert(len(res) == bytelen)
    return res

p = getPrime(MODULUS_BITS // 2)
q = getPrime(MODULUS_BITS // 2)
n = p * q
e = 65537
lam = (p - 1) * (q - 1)
d = pow(e, -1, lam)
m = b"why_be_a_king_when_you_can_be_a_god"
m = pkcs1_pad(m)
c = pow(unbytify(m), e, n)

def pkcs1_unpad(c):
    bytelen = MODULUS_BITS // 8
    m = int(gmpy2.powmod(c, d, n))
    m = bytify(m).rjust(bytelen, b'\x00')
    assert(m[0] == 0 and m[1] == 2)
    assert(0 in m[2:])
    return m[2:][m[2:].index(b'\x00'):]

class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class MyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(f'n = {n}\n'.encode())
        self.wfile.write(f'e = {e}\n'.encode())
        self.wfile.write(f'c = {c}\n'.encode())
        while True:
            try:
                test_c = self.rfile.readline().rstrip()
                test_c = int(test_c)
                m = pkcs1_unpad(test_c)
                self.wfile.write(b'OK\n')
            except:
                self.wfile.write(b'ERROR\n')

if __name__ == "__main__":
    with MyTCPServer(("localhost", PORT), MyTCPHandler) as server:
        server.serve_forever()

