from Crypto.Util.number import *
import random

#FLAG=#hidden, please solve it
#flag=int.from_bytes(FLAG,byteorder = 'big')

# flag = int -> hex -> str = FLAG
flag = 23456

p=getPrime(512)
q=getPrime(512)

print(p)
print(q)
N=p*q
e=65537
enc = pow(flag,e,N)
print (enc)

# flag=pow(c,d,n)
