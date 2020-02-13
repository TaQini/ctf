#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './girlfriend'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
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
    if is_local: gdb.attach(p,cmd)

def add(name):
    sla('Your choice :','1')
    sla('Her name size is :',name)

def dlt(index):
    sla("Your choice :",'2')
    sla("Index :",str(index))

def show(index):
    sla("Your choice :",'3')
    sla("Index :",str(index))
    return rc()

def bye():
    sla("Your choice :",'4')

# info

# gadget

# elf, libc
backdoor = 0x0400B9C

# rop1
offset = 0
payload = 'A'*offset
payload += ''

# ru('')
# sl(payload)

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

