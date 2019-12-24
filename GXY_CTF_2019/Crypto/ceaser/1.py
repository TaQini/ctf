s = "afZ_r9VYfScOeO_UL^RWUc"
res =""
j = 5
for i in s:
    res += chr(ord(i) + j)
    j += 1
print(res)