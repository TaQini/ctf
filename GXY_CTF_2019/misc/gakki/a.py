f = open('./wolaopo.jpg','rb')
f.seek(137448)

a = f.read()

f2 = open('m2.rar','wb')
f2.write(a)
f2.close()
