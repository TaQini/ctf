#!/usr/bin/python
#__author__:TaQini

import string as s

def enc(ss):
	ll = []
	for i in ss:         
		if i in s.ascii_lowercase:
			ll.append(chr((ord(i)-ord('O'))%26+ord('a')))
		elif i in s.ascii_uppercase:
			ll.append(chr((ord(i)-ord('3'))%26+ord('A')))
		else:
			ll.append(i)
	return ll
ans = 'Qsw3sj_lz4_Ujw@l'
d={}
for i in s.ascii_uppercase:
	d[enc(i)[0]]=i
for i in s.ascii_lowercase:
	d[enc(i)[0]]=i

print d

flag = ''
for i in ans:
	if i in d:
		flag += d[i]
	else:
		flag += i

print flag
# Cae3ar_th4_Gre@t
