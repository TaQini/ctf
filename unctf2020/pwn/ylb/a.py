from pwn import *
p = remote('45.158.33.12',8000)
p.recvuntil('UNCTF')
print 'UNCTF'+p.recvuntil('}')

