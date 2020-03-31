#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

p = remote('212.47.229.1', 33001)

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

l = []
def solve(ans='-1'):
    data = ru('\r')
    print data
    l.append(data)

for i in range(1200):
    solve()

print l

# dump morse code:
# HERE UPON THE LAPEL OF MY COAT YOU MAY SEE THE RIBBON OF MY DECORATION BUT THE MEDAL ITSELF I KEEP IN A LEATHERN POUCH AT HOME FLAG SHERLOCK LIKES YOUR MORSE

# FLAG{SHERLOCK_LIKES_YOUR_MORSE}

p.interactive()
