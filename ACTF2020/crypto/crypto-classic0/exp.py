f=open('./cipher','r')
s=f.read()
f.close()
k=''
for i in s:
    k+=chr((ord(i)^0x7)+3)
print k
# 'actf{my_naive_encrytion}'

