#!/usr/bin/python
#__author__:TaQini

import itertools
a = 'JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs****kxyz012789+/'
b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
c = 'MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbvD'
l = [''.join(i) for i in itertools.permutations(set(b)-set(a),4)] 
ll = [a.replace('****',i) for i in l]

def d(table):                 
    l = [table.index(i) for i in c]
    s = [bin(i)[2:].rjust(6,'0') for i in l]
    print (hex(int(''.join(s),2))[2:-1]+'0').decode('hex')

for i in ll:
    d(i)
    print i
    print ''

# wctf2020{base64_1s_v3ry_e@sy_and_fuN}
