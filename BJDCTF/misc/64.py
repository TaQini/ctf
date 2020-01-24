# -- coding:UTF-8 --
#!/usr/bin/python
# from secret import flag

b = 7
def encrpyt5(flag,a):
    enc=''
    for i in flag:
        enc+=chr((a*(ord(i)-97)+b)%26+97)
    return(enc)

def encrypt4(enc):
    temp=''
    offset=5
    for i in range(len(enc)):
        temp+=chr(ord(enc[i])-offset-i)
    return(temp)
# zzzzzzzz
# utsrqpon
#-56789

def decrypt4(temp):
    enc=''
    offset=5
    for i in range(len(temp)):
        enc+=chr(ord(temp[i])+offset+i)
    return(enc)

# 这是什么，怎么看起来像是再算64卦！！！

m = '升随临损巽睽颐萃小过讼艮颐小过震蛊屯未济中孚艮困恒晋升损蛊萃蛊未济巽解艮贲未济观豫损蛊晋噬嗑晋旅解大畜困未济随蒙升解睽未济井困未济旅萃未济震蒙未济师涣归妹大有'
# 嗯？为什么还有个b呢?
# b=7
m = 'df zl dz sz ff hz sl zd ls tw ss sl ls ll sf wl hw fz ss zw lf hd df sz sf zd sf hw ff lw ss sh hw fd ld sz sf hd hl hd hs lw st zw hw zl sw df lw hz hw wf zw  hw hs zd  hw ll sw  hw dw fw lz ht'
b = m.split()
print len(m)
print b
print len(b)
a = ''
for i in b:
    a += i[::-1]
a = a.replace('t','111')
a = a.replace('d','000')
a = a.replace('l','100')
a = a.replace('s','001')
a = a.replace('h','101')
a = a.replace('w','010')
a = a.replace('z','110')
a = a.replace('f','011')
# flag：请按照格式BJD{}
print a
temp = hex(int(a,2))[2:-1].decode('hex').decode('base64')
print temp
print len(temp)
print encrypt4('zzzzzzzz')
print decrypt4('utsrqpon')
enc = decrypt4(temp)
print enc
# print encrpyt5('zzzz')

def getk(n,a):
	for i in range(100):
	    if (26*i+n)%a==0:
	        return i

def decrpyt5(flag,a):
	b=7
	enc=''
	for i in flag:
	    tmp1=(ord(i)-97)-7
	    k=getk(tmp1,a)
	    # print '[x]',k,(tmp1,a)
	    if tmp1<0 and k==0:
	        tmp1+=26
	    enc+=chr((tmp1+26*k)/a+97)
	return(enc)

# def d2(flag,a):
# 	for i in flag:
# 		print chr(ord(i)+a)
# decrypt5('zzzz')
def rot(s,a):
	t=''
	for i in s:
		t+= chr((ord(i)-97+a)%26+97)
	return t

for i in range(26):
	print rot(enc,i)
