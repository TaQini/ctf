#!/usr/bin/python
#coding=utf-8
#__author__:TaQini
import string

def convert(encode):
    key = []
    for i in encode:
        if i in string.ascii_letters:
            key.append(i)
    tmp = encode
    for i in key:
        tmp=tmp.replace(i,'@')
    num = tmp.split('@')[1:]
    print key
    print num
    res = [key[i]*eval(num[i]) for i in range(len(key))]
    return ''.join(res)

a='j1X41H40f56b40f57Z40f53G40h4X1P40Z40Y1B2'
convert(a)