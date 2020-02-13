#!/usr/bin/python
#__author__:TaQini

enced = [0x7A, 0x4D, 0x58, 0x48, 0x7A, 0x33, 0x54, 0x49, 0x67, 0x6E, 0x78, 0x4C, 0x78, 0x4A, 0x68, 0x46, 0x41, 0x64, 0x74, 0x5A, 0x6E, 0x32, 0x66, 0x46, 0x6B, 0x33, 0x6C, 0x59, 0x43, 0x72, 0x74, 0x50, 0x43, 0x32, 0x6C, 0x39]
chipertext = ''.join([chr(i) for i in enced])

print chipertext

# swap uppercase and lowercase
def swapUL(buf):
	tmp = ''
	for i in buf:
		c = ord(i)
		if c < 97 or c > 122:
			if c < 65 or c > 90:
				tmp += i
				continue
			tmp += chr(c+0x20)
		else:
			tmp += chr(c-0x20)
	return tmp

newc = swapUL(chipertext)
print newc

table = "ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/"
print table

l=[]
for i in newc:
	l.append(table.index(i))
# print l

s=''
for i in l:
    b = bin(i)[2:].rjust(6,'0')
    s += b
    # print(b)
# print s

h = hex(int(s,2))[2:-1]
# print h
print h.decode('hex')
