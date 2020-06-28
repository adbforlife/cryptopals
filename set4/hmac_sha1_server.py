from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
from urllib.parse import urlparse, parse_qs
from cryptools import *
import os
from binascii import unhexlify
import time

PORT = 15213

fail = '''
<!doctype html>
<html>
  <head>
    <title>HMAC-SHA1</title>
  </head>
  <body>
    <p style="color:red; font-size:50px">Signature incorrect!</p>
  </body>
</html>
'''

success = '''
<!doctype html>
<html>
  <head>
    <title>HMAC-SHA1</title>
  </head>
  <body>
    <p style="color:green; font-size:50px">Hooray! Checks passed! flag{cooking_mcs_like_a_pound_of_bacon}</p>
  </body>
</html>
'''

server_key = os.urandom(32)
delay = 0.2

def hmac_sha1(k, m):
    opad = bytes([0x5c for _ in range(64)])
    ipad = bytes([0x36 for _ in range(64)])
    if len(k) > 64:
        k = sha1(k)
    else:
        k += bytes([0 for _ in range(64 - len(k))])
    return sha1(xor(k, opad) + sha1(xor(k, ipad) + m))

def bad_comp(expected, reality):
    if len(expected) != len(reality):
        return False
    for i in range(len(expected)):
        if expected[i] != reality[i]:
            return False
        time.sleep(delay)

class MyHandler(BaseHTTPRequestHandler):
    def _ret_500(self):
        self.send_response(500)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(fail.encode())

    def _ret_200(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(success.encode())

    def do_GET(self):
        self._ret_500()

    def do_POST(self):
        cont_len = int(self.headers['Content-Length'])
        dat = self.rfile.read(cont_len)
        dat = parse_qs(dat)
        if not b'file' in dat:
            self._ret_500()
        elif not b'sig' in dat:
            self._ret_500()
        else:
            f = dat[b'file']
            sig = dat[b'sig']
            if len(f) < 1 or len(sig) < 1:
                self._ret_500()
            else:
                f = f[0]
                sig = sig[0]
                expected = hmac_sha1(server_key, f)
                print(f'expecting {expected}')
                res = bad_comp(expected, unhexlify(sig))
                if res:
                    self._ret_200()
                else:
                    self._ret_500()

with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
    
