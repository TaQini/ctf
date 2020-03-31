#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

p = remote('212.47.229.1', 33002)

context.log_level = 'debug'

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

def solve(ans='-1'):
    ru('Message:  ')
    data = ru('\n')
    ru('Answer: ')
    print data
    data = data.decode('rot13')
    print data
    if(ans!='-1'):
        sl(ans)
    else:
        sl(str(data))
i = 0
while True:
    solve()
    print i
    i+=1

# find flag after 100 times 
# FLAG{Y0U_V3RY_F45T3R_CRYPT0GR4PH}

p.interactive()

