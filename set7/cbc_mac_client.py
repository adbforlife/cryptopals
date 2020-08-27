from pwn import *
from cryptools import *


r = remote('localhost', 15213)


def verify_mac(m, iv, mac):
    r.sendline(m)
    r.send(iv)
    r.send(mac)
    resp = r.recvline().rstrip()
    return resp == b'OK'

def verify_mac2(m, mac):
    r.send(m + mac + b'END\n')
    resp = r.recvline().rstrip()
    return resp == b'OK'

# IV control
m = r.recvline().rstrip()
iv = r.recv(16)
mac = r.recv(16)

new_m = m[:12] + b'adb' + m[15:]
new_iv = xor(xor(iv, bytes(12) + b'adb' + bytes(1)), bytes(12) + m[12:15] + bytes(1))
assert(verify_mac(new_m, new_iv, mac))

# No IV control
m = r.recvline().rstrip()
mac = r.recv(16)
m2 = r.recvline().rstrip()
mac2 = r.recv(16)

new_m = pad(m) + xor(mac, m2[:16]) + m2[16:]
assert(verify_mac2(new_m, mac2))

