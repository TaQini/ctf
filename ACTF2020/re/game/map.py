#!/usr/bin/python
#__author__:TaQini
codemap_s = '2 5 0 1 4 0 6 8 9 0 0 8 9 0 6 2 0 5 6 7 9 2 5 8 1 4 3 3 1 2 5 8 4 7 0 0 0 8 0 7 9 0 5 3 2 5 9 7 0 6 2 8 1 0 7 2 4 0 1 3 0 5 8 8 6 5 4 7 9 3 0 1 9 3 1 8 2 5 4 0 0'
codemap = codemap_s.split()

def show():
    cnt = 0 
    cnt0 = 0
    for i in codemap:
        if i=='0':
            cnt0 += 1
        cnt += 1
        print i,
        if cnt %9==0:
            print ''
    print 'count of 0: %s'%cnt0
show()

user = [3,7,1,4,3,7,9,6,4,6,1,3,4,6,9,2,6,7]

print user

new_map = []

pos = 0
for i in codemap:
    if i == '0' and pos < len(user):
        new_map.append(str(user[pos]))
        pos += 1
    else:
        new_map.append(i)

flag = []
for i in user:
    flag.append(chr(i+96))

codemap = new_map
show()

print "flag{%s}"%''.join(flag)
