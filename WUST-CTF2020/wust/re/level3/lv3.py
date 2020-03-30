#!/usr/bin/python
#__author__:TaQini

table = 'TSRQPONMLKJIHGFEDCBAUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
c = 'd2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD'

def d(table):                 
    l = [table.index(i) for i in c]
    s = [bin(i)[2:].rjust(6,'0') for i in l]
    print (hex(int(''.join(s),2))[2:-1]+'0').decode('hex')

d(table)
