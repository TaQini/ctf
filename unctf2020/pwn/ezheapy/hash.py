#!/usr/bin/python3
#coding=utf-8
#__author__:TaQini

for i in range(0xffffffff): 
    tmp = (0x9e3779b1*i)&0xffffffff
    print(hex(i),hex(tmp)) 
    if tmp|0xfff == 0x8049ed8|0xfff: 
        input('next?')
