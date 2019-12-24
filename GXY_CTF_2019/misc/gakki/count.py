#!/usr/bin/python
#__author__:TaQini

f = open('./flag.txt','r')
a = f.read()
f.close()

s = set(a) 
f = {}
for i in s:
	f[i]=a.count(i)

f2 = sorted(f.items(),key=lambda x:x[1],reverse=True)

out = ''
for i in f2:
	out += i[0]
	
print out

