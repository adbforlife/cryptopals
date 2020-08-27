from cryptools import *
from subprocess import call
from Crypto.Cipher import AES

MSG = b"console.log('MZA who was that?');\n"
KEY = b'YELLOW SUBMARINE'
IV = bytes(16)

def compute_mac(m):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    c = cipher.encrypt(pad(m))
    return c[-16:]

target = b"console.log('Ayo, the Wu is back!'); //"
mac = compute_mac(target)
new_m = pad(target) + xor(mac, MSG[:16]) + MSG[16:]
assert(compute_mac(new_m) == compute_mac(MSG))

open('cbc_mac_msg.js', 'wb').write(new_m)
call('/home/adb/js/v8/v8/out/x64.release/d8 cbc_mac_msg.js', shell=True)



browser_m = b"alert('MZA who was that?');\n"
target = b"alert('Ayo, the Wu is back!');//"
mac = compute_mac(target)
new_m = pad(target) + xor(mac, browser_m[:16]) + browser_m[16:]
assert(compute_mac(new_m) == compute_mac(browser_m))
print(browser_m)
print(new_m)
open('cbc_mac_msg.js', 'wb').write(new_m)


