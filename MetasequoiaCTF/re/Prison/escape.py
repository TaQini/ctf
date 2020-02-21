#!/usr/bin/python
#__author__:TaQini

raw='r1,d2,r18,d10,r31,u6,l9,d2,r6,d2,l13,u2,r3,u5,r26,d15,r16,u13,l7,u4,r12,d19,l66,u4,r21,d1,r14,u3,l50,d5,r5,u3,r4,d5,l9,d4,r10,u3,r48,d6,r28'

flag = ''

for i in raw.split(','):
    op=i[0]
    tm=i[1:]
    flag+=op*eval(tm)

print "flag{%s}"%flag.upper()
