from cryptools import *
import socketserver
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from random import randint
import gmpy2
import re
from cryptools import *

PORT = 15213
KEY = b'TOPSECRETAESKEYS'

def verify_message(req):
    if re.match(b'from=.*&to=.*&amount.*', req):
        return True
    else:
        return False

def compute_mac(m, iv):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    c = cipher.encrypt(pad(m))
    return c[-16:]

def verify_mac(m, iv, mac):
    return compute_mac(m, iv) == mac



class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class MyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # Leaked mac
        acc1 = 213
        acc2 = 251
        message = f'from={acc1}&to={acc2}&amount=1000000'.encode()
        iv = b'HIGHLYGENERICIVS'
        mac = compute_mac(message, iv)
        self.wfile.write(message + b'\n')
        self.wfile.write(iv)
        self.wfile.write(mac)
        # Check
        m = self.rfile.readline().rstrip()
        iv = self.rfile.read(16)
        mac = self.rfile.read(16)
        if not verify_message(m):
            self.wfile.write(b'Message error\n')
            return
        if not verify_mac(m, iv, mac):
            self.wfile.write(b'Bad mac\n')
            return
        self.wfile.write(b'OK\n')

        # Leak 2
        acc1 = 213
        acc2 = 251
        acc3 = 410
        message = f'from={acc1}&tx_list={acc2}:30;{acc3}:50'.encode()
        iv = bytes(16)
        mac = compute_mac(message, iv)
        self.wfile.write(message + b'\n')
        self.wfile.write(mac)

        # Leak 3
        acc1 = 'adb'
        acc2 = 'adb'
        acc3 = 'adb'
        message = f'from={acc1}&tx_list={acc2}:0;{acc2}:1000000'.encode()
        iv = bytes(16)
        mac = compute_mac(message, iv)
        self.wfile.write(message + b'\n')
        self.wfile.write(mac)
        
        # Check 2
        m = b''
        while b'END' not in m:
            m += self.rfile.readline()
        m = m.split(b'END')[0]
        mac = m[-16:]
        m = m[:-16]
        if not verify_mac(m, iv, mac):
            self.wfile.write(b'Bad mac\n')
            return
        self.wfile.write(b'OK\n')


        

if __name__ == "__main__":
    with MyTCPServer(("localhost", PORT), MyTCPHandler) as server:
        server.serve_forever()

