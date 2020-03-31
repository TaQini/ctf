#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

p = remote('212.47.229.1', 33003)

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

op = {'XOR':'^', 'OR':'|', 'AND':'&'}
def solve(ans='-1'):
    ru('[>]')
    data = ru('\n')
    ru('[>]')
    print data
    data = data.split()
    res = eval(data[0]+op[data[1]]+data[2])
    if(ans!='-1'):
        sl(ans)
    else:
        sl(str(res))


while True:
    solve()

# find flag after 100 times 
# FLAG{0HH_Y0UR3_4_V3RY_5M3RT_M4TH3M4T1C}

p.interactive()

