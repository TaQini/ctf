#!/usr/bin/python
#-*-coding:utf-8-*-
#__author__:TaQini

'''
Premise: Enumerate the alphabet by 0、1、2、.....  、25
Using the RSA system
Encryption:0156 0821 1616 0041 0140 2130 1616 0793
Public Key:2537 and 13
Private Key:2537 and 937

flag: wctf2020{Decryption}
'''

N = 2537
e = 13
d = 937
c = [156, 821, 1616, 41, 140, 2130, 1616, 793]
m = [pow(i, d, N) for i in c]
flag=[chr(ord('a')+i) for i in m]

print 'wctf2020{%s}'%(''.join(flag))
