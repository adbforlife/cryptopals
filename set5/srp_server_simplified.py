import socketserver
import os
from cryptools import *
import random
import hashlib


n = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
g = 2
k = 3
I = b'adbforlife2018@gmail.com'
p = b'bad_password'

def sha256(m):
    hash_obj = hashlib.sha256()
    hash_obj.update(m)
    return hash_obj.digest()

def hmac_sha256(k,m):
    opad = bytes([0x5c for _ in range(64)])
    ipad = bytes([0x36 for _ in range(64)])
    if len(k) > 64:
        k = sha256(k)
    else:
        k += bytes([0 for _ in range(64 - len(k))])
    return sha256(xor(k, opad) + sha256(xor(k, ipad) + m))

class MyTCPHandler(socketserver.StreamRequestHandler):

    def handle(self):
        # Prep
        salt = os.urandom(16)
        xH = sha256(salt + p)
        x = int.from_bytes(xH, 'big')
        v = pow(g,x,n)

        # Get client info for DH about A
        I = self.rfile.readline().strip()
        A = int(self.rfile.readline().strip())

        # send salt and B
        b = random.randint(1, n-1)
        B = pow(g,b,n)
        self.wfile.write(salt)
        self.wfile.write(str(B).encode() + b'\n')

        # compute uH
        uH = sha256(A.to_bytes(192, 'big') + B.to_bytes(192, 'big'))
        u = int.from_bytes(uH, 'big')

        # validation
        s = pow(A * pow(v,u,n), b, n)
        k = sha256(s.to_bytes(192, 'big'))
        res = hmac_sha256(k, salt)
        received = self.rfile.read(32)
        if res == received:
          self.wfile.write(b'OK\n')
        else:
          self.wfile.write(b'You are cheating\n')

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
