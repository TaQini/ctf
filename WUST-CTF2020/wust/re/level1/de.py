#!/usr/bin/python
#__author__:TaQini

c = [198, 232, 816, 200, 1536, 300, 6144, 984, 51200, 570, 92160, 1200, 565248, 756, 1474560, 800, 6291456, 1782, 65536000]

for i in range(1,20):
    #print i,
    if i&1:
        ch = c[i-1]>>i
    else:
        ch = c[i-1]/i
    print chr(ch),

# wctf2020{d9-dE6-20c}