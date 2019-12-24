#!/usr/bin/python
#__author__: TaQini
from pwn import *

context.log_level = 'debug'


#% nc 172.21.4.12 10022
#111111111111111111111111111
#too small
#try to give me a number!

#% nc 172.21.4.12 10022
#1111111111111111111111111111
# too big

max = 1111111111111111111111111111
min = 111111111111111111111111111
num = min

# bi-search
while(1):
	p = remote('172.21.4.12',10022)
	p.sendline(str(num))
	rec = p.recv()
	# print rec
	if rec == 'too small':
		min = num
		num = (max+min)/2
	elif rec == 'too big':
		max = num
		num = (max+min)/2
	else:
		print rec,num
		break
