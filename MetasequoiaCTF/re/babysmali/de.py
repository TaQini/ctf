#!/usr/bin/python
#__author__:TaQini

table = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

res = "xsZDluYYreJDyrpDpucZCo!?"[:-2]

l = []
for i in res:
    l.append(table.index(i))

s = ''
for i in l:
    b = bin(i)[2:].rjust(6,'0')
    s += b

# print s

h = hex(int(s,2))[2:-2]
# print h

print "flag{%s}"%h.decode('hex')
