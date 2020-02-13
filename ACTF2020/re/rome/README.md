## Rome

凯撒加密+大小写互换，主要代码如下：

```c
for ( i = 0; i <= 15; ++i ){
    if ( *(&v1 + i) > '@' && *(&v1 + i) <= 'Z' )
        *(&v1 + i) = (*(&v1 + i) - '3') % 26 + 'A';
    if ( *(&v1 + i) > '`' && *(&v1 + i) <= 'z' )
        *(&v1 + i) = (*(&v1 + i) - 'O') % 26 + 'a';
}

for ( i = 0; i <= 15; ++i ){
	result = *(&v15 + i);
	if ( *(&v1 + i) != result )
		return result;
}
result = printf("You are correct!");
```

解密(懒得推算了，反正凯撒后的字母是一对一映射的，直接搞到映射表反解即可)：

```python
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
```



