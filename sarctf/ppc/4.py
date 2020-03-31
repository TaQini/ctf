#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

p = remote('212.47.229.1', 33004)

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
    ru('[>]')
    data = ru('\n')
    ru('[>]')
    data = data.split()
    res = eval(data[0])+eval(data[2])
    if(ans!='-1'):
        sl(ans)
    else:
        sl(str(res))

for i in range(9):
    solve()

solve('0.30000000000000004')

# FLAG{MaGiC_0f_NuMbErS}

p.interactive()

