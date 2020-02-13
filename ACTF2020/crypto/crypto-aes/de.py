#!/usr/bin/python3
#__author__:TaQini

from Crypto.Cipher import AES
import os
import gmpy2
from Crypto.Util.number import *

out = long_to_bytes(91144196586662942563895769614300232343026691029427747065707381728622849079757)

key = out[:16]*2

xor_res = out[16:]

iv = bytes_to_long(xor_res)^bytes_to_long(key[16:])
iv = long_to_bytes(iv)

aes=AES.new(key,AES.MODE_CBC,iv)

out = b'\x8c-\xcd\xde\xa7\xe9\x7f.b\x8aKs\xf1\xba\xc75\xc4d\x13\x07\xac\xa4&\xd6\x91\xfe\xf3\x14\x10|\xf8p'

flag = aes.decrypt(out)

print(flag)
