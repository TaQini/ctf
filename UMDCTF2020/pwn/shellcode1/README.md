
## shellcodia1 (300pt)
### Description

> Welcome to shellcodia, here is an opportunity to write some custom shellcode to retrieve the flag! Simply connect, submit your shellcode in binary form, and if you've  completed the challenge then a flag will return. This first challenge is to return the value 7. Now, a few things to remember, these are x64  machines so don't think you can sneak by with 32bit shellcode.  Additionally, the environment assumes nothing about the shellcode you  give it. It's highly unlikely that if you break the environment, even if you accomplished the goal, you will get the flag. 
>
> Submit your shellcode to: `157.245.88.100:7778` Good luck! 
>
> Author: `quantumite (BlueStar)` 
> 
> (Note: flag is in `UMDCTF{}` format)

### Analysis

Generally, `rax` is used to storage return value. This challenge is to return the value 7. 

So, we can set `rax` to 7 by assembly language code as following: 

```nasm
xor  rax, rax
mov  al, 0x7
ret  
```

### Solution

```python
context.log_level = 'debug'
context.arch = 'amd64'

p=remote('157.245.88.100', 7778)
sc=asm('xor rax,rax\n mov al,7\nret\n')
p.sendline(sc)

p.interactive()
```

> flag: UMDCTF{R_U_@_Tim3_tR@v3ll3r_OR_Ju$t_R3a11y_Sm@rT}

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/shellcode1) 


