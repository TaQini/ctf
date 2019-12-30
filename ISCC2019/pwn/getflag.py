#!/usr/bin/python3
import random
import hashlib

a = random.randint(1,100000)
m = hashlib.md5()
aa = str(a).encode('utf-8')
m.update(aa)
s =  '[Result]: Congratulations!Your flag is : '
r = m.hexdigest()
l = []
for i in range(len(r)):
    l.append(r[i])
    if i == 7:
        l.append('-')
    if i == 11:
        l.append('-')
    if i == 15:
        l.append('-')
    if i == 19:
        l.append('-')
ii = ''
for i in l:
    ii += i
print(s+ii)

# [Result]: Congratulations!Your flag is : d210fd3c-df60-4432-90e2-dfb488a3822c
# [Result]: Congratulations!Your flag is : 70cc721a-cc20-dc39-0b86-24404fcdc97b
# fake getflag
