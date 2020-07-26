from pwn import *
import random
n = 23225289190564444957355012420506799886824798892957158658855783766457687131287869240197141367980046722708397364275478014644363593750314580466189315905108264881208530507246375261112837910586728741265161245730593228359828614308545870700577302472778318080699960181105223831382668002169891662778965046467486056759677998021866176596270953027929910737848605503245965956856691646887257802285588994385981665064859583583914986618720429963262010478327071683000826019933437577719612151009126396883125583948856724410471761247467614943368606813821531412975646301357520160333318645764170411350956899809284475283941979189366877842949
e = 65537


encrypted = b'4\xa6=\x87\x12\x81\x03c\x86\x7f\xfe\xf9X\xb9zS\xe0\xc5\xa4\x92r\x91\x10l\x9d\x8d\xecE\xf1\xfa\x0b!\xab\xef\x8f\xf5\xb5\ni\x1c>;\x8a]\xd3\xd8+\x04\xe0\xe0/\xcf6\x86]\x80\xd5\xdd\xca9\xe3d\xbeG)Ay\xb4[\xe4\x13\xae7)\xfa6\xc6\xa4k\xb6 )\x0b\x0c\xc2\x93z` s\xb8\xff\x089\xa0w\x98\x9e\xb4\x18\xe3Y\x81\x90\xd4+-\xbar\x8b\xf6\x11\x88\x15+\x9b\x90M\x89\x83\xed\xcdT\x96\x06\xdb\xf5&(\x00\xdd\xd9\xeb\x91\tc>\x1f\xf3\xc9\x10Y\x9d\x8ej\x03Dq\xffTe\x84\xd2\xee\xdf\x16\x8a\x94A},\xe1/Y\xa8\x8d\x7fY\xd2v\xd5\xe47j\xe7\x93\xbe\xcbM\xb5\x1e\x17d\x95\xa7\x17/\x1aK\x1dr\x92J\xbc\x1e\x08\x9d\x1dP\xc6F\xbbc\x83>\xc9#\x88s\x1bE\xec\xcemI\xc9\x85\x0e\xc4\xfd\x93\xebb\xad\xb3\x1b^\x8em0\xabR-\xc8\x07T\xbek\x87s\xdf\x12\xda#\x87S8\x1d\xc5\xd4\x9a\x98\xa4=\xad\x06'

'''
Can't send encrypted
'''
r = remote('localhost', 9999)
r.send(encrypted)
print(r.recv())

'''
Homomorphic properties
'''
r = remote('localhost', 9999)
r.send((int.from_bytes(encrypted, 'big') * pow(2,e,n) % n).to_bytes(256, 'big'))
res = r.recv()
res = int.from_bytes(res, 'big')
res = res // 2
res = res.to_bytes(256, 'big')
print(res)


